/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  getElasticAgentStatus,
  getElasticEndpointReadiness,
  inspectElasticTemplateResidue,
  installAndVerifyElasticAgent,
  isElasticAgentHealthy,
  MACOS_TEST_BINARY,
  sanitizeElasticAgentForTemplate,
  verifyElasticTemplateIdentityAbsent,
} from "../execution/elastic-agent.js";
import {
  createEphemeralEnrollmentToken,
  getElasticEnvironment,
  revokeEnrollmentToken,
  validateApprovedElasticConfiguration,
} from "../execution/elastic-fleet.js";
import {
  installApprovedPackages,
  verifyApprovedPackages,
} from "../execution/approved-packages.js";
import { runSetupSteps } from "../execution/setup-steps.js";
import {
  stageApprovedOperatorSourceAssets,
  verifyApprovedSourceAssets,
} from "../execution/source-assets.js";
import { runProcess } from "../execution/process.js";
import {
  cloneAndStartTartTarget,
  coldBootTartTarget,
  deleteLocalTartImageArchive,
  sealLocalTartTarget,
  startExistingTartTarget,
  stopAndDeleteTartTarget,
  tartTargetExists,
} from "../execution/tart.js";
import { runOnTarget } from "../execution/target.js";
import { verifyTargetCapabilities } from "../execution/target-capabilities.js";
import { assertSafeTargetId } from "../shared/validation.js";
import {
  createAtomicRunStore,
  type AtomicPlan,
  type AtomicRunStore,
} from "./atomic-run-state.js";
import { textResult } from "./atomic-run.js";

const targetSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("doctor") }),
  z.object({ action: z.literal("status"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("instrumentation_status"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("register"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("provision"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("prepare_template"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("promote_template"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("destroy"), run_id: z.string().min(1) }),
]);

const targetToolSchema = z.object({
  action: z.enum([
    "doctor",
    "status",
    "instrumentation_status",
    "register",
    "provision",
    "prepare_template",
    "promote_template",
    "destroy",
  ]),
  run_id: z.string().min(1).optional(),
});

export const BOOTSTRAP_SCRIPT = `set -eu
for command in git python3 curl sudo; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required base-image command: $command" >&2
    exit 1
  }
done
sudo -n true
install_pinned_repo() {
  destination="$1"
  repository="$2"
  revision="$3"
  rm -rf "$destination"
  mkdir -p "$destination"
  git -C "$destination" init
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch --depth 1 origin "$revision"
  git -C "$destination" checkout --detach FETCH_HEAD
}
install_pinned_repo /opt/atomic-red-team "$ART_REPOSITORY" "$ART_REVISION"
install_pinned_repo /opt/invoke-atomicredteam "$INVOKE_REPOSITORY" "$INVOKE_REVISION"
install -d -m 1777 /var/tmp/macos-atomic-runs
`;

export const RUNNER_BOOTSTRAP_SCRIPT = `set -eu
command -v pwsh >/dev/null 2>&1 || {
  echo "missing pwsh after approved setup steps" >&2
  exit 1
}
pwsh -NoProfile -NonInteractive -Command "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; if (-not (Get-Module -ListAvailable powershell-yaml)) { Install-Module powershell-yaml -Scope AllUsers -Force -AllowClobber }"
`;

export function pinnedRepositoryRevisionArgs(repositoryPath: string): string[] {
  return ["sudo", "git", "-C", repositoryPath, "rev-parse", "HEAD"];
}

type ElasticAgentPlan = NonNullable<AtomicPlan["instrumentation"]>["elastic_agent"];
type AwsRuntimeCredentialPlan = NonNullable<
  NonNullable<AtomicPlan["runtime_credentials"]>["aws"]
>;

type AwsCredentialProcessDocument = {
  readonly Version?: unknown;
  readonly AccessKeyId?: unknown;
  readonly SecretAccessKey?: unknown;
  readonly SessionToken?: unknown;
  readonly Expiration?: unknown;
};

export type StagedAwsRuntimeCredentials = {
  readonly ok: true;
  readonly provider: "aws";
  readonly source_profile: string;
  readonly target_profile: string;
  readonly temporary: boolean;
  readonly expiration?: string;
};

export async function stageApprovedAwsRuntimeCredentials(
  scope: AtomicPlan["scope"],
  credentialPlan: AwsRuntimeCredentialPlan,
  options: {
    readonly runHostProcess?: typeof runProcess;
    readonly runTarget?: typeof runOnTarget;
  } = {}
): Promise<StagedAwsRuntimeCredentials> {
  if (scope.target_kind !== "tart" || scope.lifecycle !== "ephemeral") {
    throw new Error("AWS runtime credentials require a fresh ephemeral Tart target");
  }
  const runHostProcess = options.runHostProcess ?? runProcess;
  const runTarget = options.runTarget ?? runOnTarget;
  const exported = await runHostProcess(
    "aws",
    [
      "configure",
      "export-credentials",
      "--profile",
      credentialPlan.source_profile,
      "--format",
      "process",
    ],
    { timeoutMs: 30_000, maxOutputBytes: 64_000 }
  );
  if (
    exported.exitCode !== 0 ||
    exported.timedOut ||
    exported.truncated
  ) {
    throw new Error(
      `AWS credential export failed for approved profile ${credentialPlan.source_profile}`
    );
  }
  let document: AwsCredentialProcessDocument;
  try {
    document = JSON.parse(exported.stdout) as AwsCredentialProcessDocument;
  } catch {
    throw new Error(
      `AWS credential export returned invalid JSON for approved profile ${credentialPlan.source_profile}`
    );
  }
  const accessKeyId = requiredAwsCredentialValue(document.AccessKeyId, "access key id");
  const secretAccessKey = requiredAwsCredentialValue(
    document.SecretAccessKey,
    "secret access key"
  );
  const sessionToken = optionalAwsCredentialValue(document.SessionToken, "session token");
  const expiration = optionalAwsCredentialValue(document.Expiration, "expiration");
  const credentials = [
    `[${credentialPlan.target_profile}]`,
    `aws_access_key_id = ${accessKeyId}`,
    `aws_secret_access_key = ${secretAccessKey}`,
    ...(sessionToken ? [`aws_session_token = ${sessionToken}`] : []),
    "",
  ].join("\n");
  const staged = await runTarget(
    scope,
    [
      "/bin/sh",
      "-c",
      'set -eu; umask 077; mkdir -p "$HOME/.aws"; cat > "$HOME/.aws/credentials"; chmod 600 "$HOME/.aws/credentials"',
    ],
    30_000,
    { input: credentials }
  );
  if (staged.exitCode !== 0 || staged.timedOut || staged.truncated) {
    throw new Error("AWS runtime credential staging failed on the disposable target");
  }
  return {
    ok: true,
    provider: "aws",
    source_profile: credentialPlan.source_profile,
    target_profile: credentialPlan.target_profile,
    temporary: sessionToken !== undefined,
    ...(expiration ? { expiration } : {}),
  };
}

function requiredAwsCredentialValue(value: unknown, label: string): string {
  const normalized = optionalAwsCredentialValue(value, label);
  if (!normalized) throw new Error(`AWS credential export omitted ${label}`);
  return normalized;
}

function optionalAwsCredentialValue(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || /[\r\n\0]/.test(value) || value.length > 16_384) {
    throw new Error(`AWS credential export returned an invalid ${label}`);
  }
  return value;
}

export type ElasticProcessTelemetryReadiness = {
  readonly ok: true;
  readonly host_name: string;
  readonly marker: string;
  readonly attempts: number;
  readonly waited_ms: number;
  readonly event_count: number;
};

export async function waitForElasticProcessTelemetry(
  scope: AtomicPlan["scope"],
  elastic: ElasticAgentPlan,
  runId: string,
  options: {
    readonly runTarget?: typeof runOnTarget;
    readonly fetchImpl?: typeof fetch;
    readonly sleep?: (milliseconds: number) => Promise<void>;
    readonly now?: () => number;
    readonly timeoutMs?: number;
    readonly pollMs?: number;
    readonly environment?: { readonly kibanaUrl: string; readonly apiKey: string };
  } = {}
): Promise<ElasticProcessTelemetryReadiness> {
  const runTarget = options.runTarget ?? runOnTarget;
  const fetchImpl = options.fetchImpl ?? fetch;
  const sleep = options.sleep ?? ((milliseconds: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? 180_000;
  const pollMs = options.pollMs ?? 5_000;
  const environment = options.environment ?? getElasticEnvironment();
  const normalizedKibana = environment.kibanaUrl.replace(/\/$/, "");
  if (normalizedKibana !== elastic.kibana_url.replace(/\/$/, "")) {
    throw new Error("Telemetry readiness refuses a configured Kibana URL outside the approved stack");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 600_000) {
    throw new Error("Telemetry readiness timeout must be an integer from 1000 to 600000 milliseconds");
  }
  if (!Number.isInteger(pollMs) || pollMs < 250 || pollMs > 30_000) {
    throw new Error("Telemetry readiness poll interval must be an integer from 250 to 30000 milliseconds");
  }

  const hostnameResult = await runTarget(
    scope,
    ["/usr/sbin/scutil", "--get", "HostName"],
    30_000
  );
  const hostName = hostnameResult.stdout.trim();
  if (
    hostnameResult.exitCode !== 0 ||
    hostnameResult.timedOut ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(hostName)
  ) {
    throw new Error("Telemetry readiness could not resolve the target HostName");
  }
  const marker =
    "macos-atomic-ready-" + runId.replace(/[^a-z0-9-]/gi, "-").slice(-48);
  const startedAt = now();
  let attempts = 0;
  let eventCount = 0;
  while (now() - startedAt <= timeoutMs) {
    attempts += 1;
    const emitted = await runTarget(scope, ["/bin/echo", marker], 30_000);
    if (emitted.exitCode !== 0 || emitted.timedOut) {
      throw new Error("Telemetry readiness marker process failed on the target");
    }
    await sleep(pollMs);
    const url = new URL(
      "logs-endpoint.events.process-*/_count",
      elastic.elasticsearch_url.replace(/\/$/, "") + "/"
    );
    const response = await fetchImpl(url, {
      method: "POST",
      headers: {
        authorization: "ApiKey " + environment.apiKey,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        query: {
          bool: {
            filter: [
              { term: { "host.os.type": "macos" } },
              { term: { "host.name": hostName } },
              { term: { "event.category": "process" } },
              { term: { "event.action": "exec" } },
              { wildcard: { "process.command_line": { value: "*" + marker + "*" } } },
              { range: { "@timestamp": { gte: "now-10m", lte: "now+1m" } } },
            ],
          },
        },
      }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      const body = (await response.text()).slice(0, 2_000);
      throw new Error(
        "Elastic process-telemetry readiness query failed (" +
          response.status + "): " + body
      );
    }
    const body = await response.json() as { count?: unknown };
    if (typeof body.count !== "number") {
      throw new Error("Elastic process-telemetry readiness response has no numeric count");
    }
    eventCount = body.count;
    if (eventCount > 0) {
      return {
        ok: true,
        host_name: hostName,
        marker,
        attempts,
        waited_ms: now() - startedAt,
        event_count: eventCount,
      };
    }
  }
  throw new Error(
    "Elastic Endpoint process telemetry was not observable for " + hostName +
      " after " + timeoutMs + " ms"
  );
}

export function registerMacosAtomicTargetTool(
  server: McpServer,
  store: AtomicRunStore = createAtomicRunStore()
): void {
  server.registerTool(
    "macos-atomic-target",
    {
      title: "macOS Atomic Target",
      description:
        "Provision, register, verify, instrument, prepare and promote a no-MDM local Tart template, or destroy only the digest-approved macOS Tart/SSH target. Tart images must be OCI digest pinned or local .tvm archives bound by SHA-256. Elastic enrollment reuses the app default cluster credentials and requires MDM approval or a manually approved seed whose sanitized fresh clone passes every Endpoint readiness check.",
      inputSchema: targetToolSchema,
      annotations: { destructiveHint: true },
    },
    async (input) => {
      try {
        const parsed = targetSchema.parse(input);
        if (parsed.action === "doctor") return textResult(await doctor());
        const loaded = store.getLoaded(parsed.run_id);
        if (!loaded.plan) return textResult({ error: "No plan is stored" }, true);
        const plan = loaded.plan;
        assertSafeTargetId(plan.scope.target_id);

        if (parsed.action === "status") {
          return textResult(await targetStatus(plan));
        }
        if (parsed.action === "instrumentation_status") {
          if (!plan.instrumentation?.elastic_agent) {
            return textResult({ error: "The approved plan has no Elastic Agent instrumentation" }, true);
          }
          const status = await getElasticAgentStatus(plan.scope);
          const endpointReadiness = await getElasticEndpointReadiness(plan.scope, status);
          const templateResidue = endpointReadiness.ok
            ? undefined
            : await inspectElasticTemplateResidue(plan.scope);
          return textResult(
            {
              ok: endpointReadiness.ok,
              status,
              endpoint_readiness: endpointReadiness,
              template_residue: templateResidue,
            },
            !endpointReadiness.ok
          );
        }
        if (parsed.action === "register") {
          store.assertPhase(parsed.run_id, ["provisioning"]);
          return textResult(await registerTarget(store, parsed.run_id, plan));
        }
        if (parsed.action === "prepare_template") {
          store.assertPhase(parsed.run_id, ["provisioning"]);
          assertNoMdmTemplateControls(plan);
          const targetResource = loaded.resources.find(
            (resource) =>
              resource.id === plan.scope.target_id &&
              resource.kind === "target" &&
              !resource.cleaned
          );
          if (!targetResource) {
            return textResult(
              { error: "Register the manually approved Tart seed before preparing a template" },
              true
            );
          }
          if (!plan.instrumentation?.elastic_agent) {
            return textResult({ error: "Template preparation requires Elastic instrumentation" }, true);
          }
          const initialStatus = await getElasticAgentStatus(plan.scope);
          const initialReadiness = await getElasticEndpointReadiness(
            plan.scope,
            initialStatus
          );
          if (!initialReadiness.ok) {
            return textResult(
              { error: "The manually approved seed is not Endpoint-ready", initial_readiness: initialReadiness },
              true
            );
          }
          const sanitization = await sanitizeElasticAgentForTemplate(plan.scope);
          if (!sanitization.ok) {
            return textResult(
              { error: "Elastic identity sanitization failed", sanitization },
              true
            );
          }
          const persistenceBoot = await coldBootTartTarget(plan.scope);
          let persistentAbsence = await verifyElasticTemplateIdentityAbsent(plan.scope);
          let retrySanitization: Awaited<ReturnType<typeof sanitizeElasticAgentForTemplate>> | undefined;
          let retryPersistenceBoot: Awaited<ReturnType<typeof coldBootTartTarget>> | undefined;
          if (!persistentAbsence.ok && !persistentAbsence.agent_path_absent) {
            retrySanitization = await sanitizeElasticAgentForTemplate(plan.scope);
            if (retrySanitization.ok) {
              retryPersistenceBoot = await coldBootTartTarget(plan.scope);
              persistentAbsence = await verifyElasticTemplateIdentityAbsent(plan.scope);
            }
          }
          if (!persistentAbsence.ok) {
            return textResult(
              {
                error: "Elastic identity returned after a cold boot; refusing final archive promotion",
                persistence_boot: persistenceBoot,
                persistent_absence: persistentAbsence,
                retry_sanitization: retrySanitization,
                retry_persistence_boot: retryPersistenceBoot,
              },
              true
            );
          }
          const sealed = await sealLocalTartTarget(
            plan.scope,
            `${parsed.run_id}-candidate`,
            plan.controls.ttl_minutes
          );
          store.recordResource(parsed.run_id, {
            id: sealed.archivePath,
            kind: "tart-template-candidate",
            origin: "provisioned",
            cleaned: false,
            notes: `Candidate pending behavior, telemetry, and final sanitization: ${sealed.reference}`,
          });
          const removedSeed = await stopAndDeleteTartTarget(plan.scope.target_id);
          const seedAbsent = !(await tartTargetExists(plan.scope.target_id));
          if (!seedAbsent || removedSeed.deleted.exitCode !== 0) {
            return textResult(
              { error: "Could not replace the sanitized seed with a fresh import", removed_seed: removedSeed },
              true
            );
          }
          store.recordResource(parsed.run_id, { ...targetResource, cleaned: true });
          const preparedPlan: AtomicPlan = {
            ...plan,
            scope: { ...plan.scope, target_image: sealed.reference },
          };
          let launched: Awaited<ReturnType<typeof cloneAndStartTartTarget>>;
          try {
            launched = await cloneAndStartTartTarget(
              preparedPlan.scope,
              preparedPlan.controls.ttl_minutes
            );
          } catch (error) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: error instanceof Error ? error.message : String(error),
            });
            throw error;
          }
          store.recordResource(parsed.run_id, {
            id: plan.scope.target_id,
            kind: "target",
            origin: "orphaned",
            cleaned: false,
            notes: "Fresh import awaiting Elastic readiness validation",
          });
          const registered = await registerTarget(store, parsed.run_id, preparedPlan);
          return textResult({
            ok: true,
            candidate_image: {
              reference: sealed.reference,
              archive_path: sealed.archivePath,
              sha256: sealed.sha256,
            },
            promotion_required: true,
            sanitization,
            persistence_boot: persistenceBoot,
            persistent_absence: persistentAbsence,
            retry_sanitization: retrySanitization,
            retry_persistence_boot: retryPersistenceBoot,
            initial_readiness: initialReadiness,
            removed_seed: removedSeed,
            fresh_import: launched,
            registered,
          });
        }
        if (parsed.action === "promote_template") {
          store.assertPhase(parsed.run_id, ["cleaning"]);
          assertNoMdmTemplateControls(plan);
          const current = store.getLoaded(parsed.run_id);
          assertNoMdmTemplatePromotionReady(current);
          const candidate = current.resources.find(
            (resource) => resource.kind === "tart-template-candidate" && !resource.cleaned
          );
          const targetResource = current.resources.find(
            (resource) =>
              resource.id === plan.scope.target_id &&
              resource.kind === "target" &&
              !resource.cleaned
          );
          if (!candidate || !targetResource) {
            return textResult(
              { error: "Template promotion requires the validated candidate and target" },
              true
            );
          }
          await startExistingTartTarget(plan.scope);
          const status = await getElasticAgentStatus(plan.scope);
          const readiness = await getElasticEndpointReadiness(plan.scope, status);
          const preSanitizationAbsence = await verifyElasticTemplateIdentityAbsent(plan.scope);
          const sanitization = preSanitizationAbsence.ok
            ? {
                ok: true,
                uninstall: {
                  exitCode: 0,
                  timedOut: false,
                  stdout: "Already sanitized after an earlier promotion attempt",
                  stderr: "",
                },
                cleanup: { exitCode: 0, timedOut: false, stdout: "", stderr: "" },
                agent_path_absent: true,
                endpoint_path_absent: true,
                agent_link_absent: true,
                elastic_processes_absent: true,
              }
            : await sanitizeElasticAgentForTemplate(plan.scope);
          if (!sanitization.ok) {
            return textResult(
              { error: "Final Elastic identity sanitization failed", sanitization },
              true
            );
          }
          const persistenceBoot = await coldBootTartTarget(plan.scope);
          let persistentAbsence = await verifyElasticTemplateIdentityAbsent(plan.scope);
          let retrySanitization: Awaited<ReturnType<typeof sanitizeElasticAgentForTemplate>> | undefined;
          let retryPersistenceBoot: Awaited<ReturnType<typeof coldBootTartTarget>> | undefined;
          if (!persistentAbsence.ok && !persistentAbsence.agent_path_absent) {
            retrySanitization = await sanitizeElasticAgentForTemplate(plan.scope);
            if (retrySanitization.ok) {
              retryPersistenceBoot = await coldBootTartTarget(plan.scope);
              persistentAbsence = await verifyElasticTemplateIdentityAbsent(plan.scope);
            }
          }
          if (!persistentAbsence.ok) {
            return textResult(
              {
                error: "Elastic identity returned after a cold boot; refusing final archive promotion",
                persistence_boot: persistenceBoot,
                persistent_absence: persistentAbsence,
                retry_sanitization: retrySanitization,
                retry_persistence_boot: retryPersistenceBoot,
              },
              true
            );
          }
          const sealed = await sealLocalTartTarget(
            plan.scope,
            parsed.run_id,
            plan.controls.ttl_minutes
          );
          store.recordResource(parsed.run_id, {
            id: sealed.archivePath,
            kind: "tart-template-archive",
            origin: "provisioned",
            cleaned: false,
            notes: `Final sanitized archive pending target and candidate cleanup: ${sealed.reference}`,
          });
          deleteLocalTartImageArchive(candidate.id);
          store.recordResource(parsed.run_id, { ...candidate, cleaned: true });
          const removedTarget = await stopAndDeleteTartTarget(plan.scope.target_id);
          const targetAbsent = !(await tartTargetExists(plan.scope.target_id));
          if (!targetAbsent || removedTarget.deleted.exitCode !== 0) {
            return textResult(
              { error: "Could not remove the validation target after final sealing", removed_target: removedTarget },
              true
            );
          }
          store.recordResource(parsed.run_id, { ...targetResource, cleaned: true });
          const finalArchive = store
            .getLoaded(parsed.run_id)
            .resources.find(
              (resource) =>
                resource.id === sealed.archivePath &&
                resource.kind === "tart-template-archive"
            );
          if (!finalArchive) throw new Error("Final template archive ledger entry is missing");
          store.recordResource(parsed.run_id, {
            ...finalArchive,
            cleaned: true,
            notes: `Promoted immutable campaign input after behavior, telemetry, and fresh-clone validation: ${sealed.reference}`,
          });
          return textResult({
            ok: true,
            prepared_image: {
              reference: sealed.reference,
              archive_path: sealed.archivePath,
              sha256: sealed.sha256,
            },
            readiness,
            pre_sanitization_absence: preSanitizationAbsence,
            sanitization,
            persistence_boot: persistenceBoot,
            persistent_absence: persistentAbsence,
            retry_sanitization: retrySanitization,
            retry_persistence_boot: retryPersistenceBoot,
            removed_candidate: candidate.id,
            removed_target: removedTarget,
            target_absent: targetAbsent,
          });
        }
        if (parsed.action === "provision") {
          store.assertPhase(parsed.run_id, ["provisioning"]);
          if (plan.scope.target_kind !== "tart" || plan.scope.lifecycle !== "ephemeral") {
            return textResult(
              { error: "provision is allowed only for an approved ephemeral Tart target" },
              true
            );
          }
          if (plan.instrumentation?.elastic_agent) {
            await validateApprovedElasticConfiguration(
              plan.instrumentation.elastic_agent
            );
          }
          let launched: Awaited<ReturnType<typeof cloneAndStartTartTarget>>;
          try {
            launched = await cloneAndStartTartTarget(
              plan.scope,
              plan.controls.ttl_minutes
            );
          } catch (error) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: error instanceof Error ? error.message : String(error),
            });
            throw error;
          }
          if (launched.clone.exitCode !== 0 || launched.clone.timedOut) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Tart clone failed or timed out",
            });
            return textResult({ ok: false, tart: launched }, true);
          }
          const bootstrap = await runOnTarget(
            plan.scope,
            [
              "sudo",
              "env",
              `ART_REPOSITORY=${plan.source.repository}`,
              `ART_REVISION=${plan.source.revision}`,
              `INVOKE_REPOSITORY=${plan.runner.repository}`,
              `INVOKE_REVISION=${plan.runner.revision}`,
              "/bin/sh",
              "-s",
            ],
            20 * 60_000,
            { input: BOOTSTRAP_SCRIPT }
          );
          if (bootstrap.exitCode !== 0 || bootstrap.timedOut) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "macOS bootstrap failed",
            });
            return textResult({ ok: false, tart: launched, bootstrap }, true);
          }
          const packages = await installApprovedPackages(
            plan.scope,
            plan.target_prerequisites?.packages ?? []
          );
          if (!packages.ok) {
            return textResult({ ok: false, tart: launched, packages }, true);
          }
          const setup = await runSetupSteps(plan.scope, plan.setup_steps ?? []);
          if (!setup.ok) return textResult({ ok: false, tart: launched, setup }, true);
          const runtimeCredentials = plan.runtime_credentials?.aws
            ? await stageApprovedAwsRuntimeCredentials(
                plan.scope,
                plan.runtime_credentials.aws
              )
            : undefined;
          if (runtimeCredentials) {
            store.recordResource(parsed.run_id, {
              id: `runtime-credential:aws:${runtimeCredentials.target_profile}`,
              kind: "runtime-credential",
              origin: "provisioned",
              cleaned: false,
              notes: `Ephemeral AWS credential material from approved host profile ${runtimeCredentials.source_profile}`,
            });
          }
          const runnerBootstrap = await runOnTarget(
            plan.scope,
            ["sudo", "/bin/sh", "-s"],
            10 * 60_000,
            { input: RUNNER_BOOTSTRAP_SCRIPT }
          );
          if (runnerBootstrap.exitCode !== 0 || runnerBootstrap.timedOut) {
            return textResult(
              { ok: false, tart: launched, setup, runner_bootstrap: runnerBootstrap },
              true
            );
          }
          const registered = await registerTarget(store, parsed.run_id, plan);
          return textResult({
            ...registered,
            tart: launched,
            bootstrap,
            packages,
            setup,
            runtime_credentials: runtimeCredentials,
            runner_bootstrap: runnerBootstrap,
          });
        }

        store.assertPhase(parsed.run_id, ["cleaning", "blocked"]);
        if (plan.scope.lifecycle === "existing" || plan.scope.target_kind !== "tart") {
          return textResult(
            { error: "Automatic destruction is refused for existing SSH targets" },
            true
          );
        }
        for (const resource of loaded.resources) {
          if (
            resource.kind === "elastic-fleet-enrollment-token" &&
            !resource.cleaned &&
            resource.id.startsWith("fleet-enrollment-token:")
          ) {
            await revokeEnrollmentToken(resource.id.slice("fleet-enrollment-token:".length));
            store.recordResource(parsed.run_id, { ...resource, cleaned: true });
          }
        }
        const targetExisted = await tartTargetExists(plan.scope.target_id);
        const destroyed = targetExisted
          ? await stopAndDeleteTartTarget(plan.scope.target_id)
          : undefined;
        const absent = !(await tartTargetExists(plan.scope.target_id));
        if (!absent || (destroyed && destroyed.deleted.exitCode !== 0)) {
          return textResult({ ok: false, destroyed, absent }, true);
        }
        const refreshed = store.getLoaded(parsed.run_id);
        for (const resource of refreshed.resources) {
          if (resource.id === plan.scope.target_id && resource.kind === "target") {
            store.recordResource(parsed.run_id, { ...resource, cleaned: true });
          }
          if (resource.kind === "runtime-credential" && !resource.cleaned) {
            store.recordResource(parsed.run_id, {
              ...resource,
              cleaned: true,
              notes: `${resource.notes ?? "Runtime credential material"}; removed with disposable target`,
            });
          }
          if (
            ["tart-template-archive", "tart-template-candidate"].includes(resource.kind) &&
            !resource.cleaned
          ) {
            deleteLocalTartImageArchive(resource.id);
            store.recordResource(parsed.run_id, {
              ...resource,
              cleaned: true,
              notes: "Removed template archive after failed or incomplete validation",
            });
          }
        }
        return textResult({ ok: true, destroyed, target_absent: absent });
      } catch (error) {
        return textResult(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );
}

export function assertNoMdmTemplateControls(plan: AtomicPlan): void {
  if (plan.scope.target_kind !== "tart" || plan.scope.lifecycle !== "ephemeral") {
    throw new Error("No-MDM template preparation requires an ephemeral Tart target");
  }
  if (plan.scope.target_profile !== "desktop") {
    throw new Error("No-MDM template preparation requires a manually approved desktop target");
  }
  if (
    !plan.controls.snapshot_before ||
    !plan.controls.allow_destructive ||
    !plan.controls.allow_reboot ||
    !plan.controls.allow_tcc_changes
  ) {
    throw new Error(
      "No-MDM template preparation requires snapshot_before, allow_destructive, allow_reboot, and allow_tcc_changes"
    );
  }
}

export function assertNoMdmTemplatePromotionReady(
  loaded: ReturnType<AtomicRunStore["getLoaded"]>
): void {
  if (!loaded.plan) throw new Error("Template promotion requires an exact plan");
  if (loaded.state.phase !== "cleaning") {
    throw new Error("Template promotion is allowed only during cleaning");
  }
  for (const test of loaded.plan.tests) {
    const behavior = loaded.executions.find(
      (execution) =>
        execution.test_guid === test.test_guid &&
        ["execute", "manual"].includes(execution.stage) &&
        execution.status === "passed" &&
        execution.behavior_success === true
    );
    if (!behavior) {
      throw new Error(`Template validation behavior is not proven for ${test.test_guid}`);
    }
    const coverage = loaded.coverage.find(
      (record) =>
        record.test_guid === test.test_guid &&
        ["detected", "missed"].includes(record.outcome) &&
        (record.raw_event_count ?? 0) > 0
    );
    if (!coverage) {
      throw new Error(`Template validation telemetry is not proven for ${test.test_guid}`);
    }
  }
}

async function registerTarget(
  store: AtomicRunStore,
  runId: string,
  plan: AtomicPlan
): Promise<Record<string, unknown>> {
  const startup =
    plan.scope.target_kind === "tart" && plan.scope.lifecycle === "ephemeral"
      ? await startExistingTartTarget(plan.scope)
      : undefined;
  const [user, version, architecture] = await Promise.all([
    runOnTarget(plan.scope, ["id", "-u", plan.scope.execution_user], 30_000),
    runOnTarget(plan.scope, ["sw_vers", "-productVersion"], 30_000),
    runOnTarget(plan.scope, ["uname", "-m"], 30_000),
  ]);
  if ([user, version, architecture].some((result) => result.exitCode !== 0 || result.timedOut)) {
    throw new Error("Target identity, macOS version, or architecture verification failed");
  }
  const actualMajor = version.stdout.trim().split(".", 1)[0];
  if (plan.scope.distro !== `macos-${actualMajor}`) {
    throw new Error(
      `Target macOS version ${version.stdout.trim()} does not match approved ${plan.scope.distro}`
    );
  }
  const actualArchitecture = normalizeArchitecture(architecture.stdout.trim());
  if (actualArchitecture !== plan.scope.architecture) {
    throw new Error(
      `Target architecture ${actualArchitecture} does not match approved ${plan.scope.architecture}`
    );
  }
  const [sourceRevision, runnerRevision, powershell, sourceAssets, packages, capabilities] =
    await Promise.all([
      runOnTarget(
        plan.scope,
        pinnedRepositoryRevisionArgs("/opt/atomic-red-team"),
        30_000
      ),
      runOnTarget(
        plan.scope,
        pinnedRepositoryRevisionArgs("/opt/invoke-atomicredteam"),
        30_000
      ),
      runOnTarget(plan.scope, ["pwsh", "--version"], 30_000),
      verifyApprovedSourceAssets(plan.scope, plan.tests),
      verifyApprovedPackages(plan.scope, plan.target_prerequisites?.packages ?? []),
      verifyTargetCapabilities(plan.scope),
    ]);
  if (
    sourceRevision.stdout.trim() !== plan.source.revision ||
    runnerRevision.stdout.trim() !== plan.runner.revision ||
    powershell.exitCode !== 0 ||
    !sourceAssets.ok ||
    !packages.ok ||
    !capabilities.ok
  ) {
    throw new Error("Target does not satisfy the digest-approved runtime and capability checks");
  }
  const stagedSourceAssets = await stageApprovedOperatorSourceAssets(
    plan.scope,
    runId,
    plan.tests
  );
  if (!stagedSourceAssets.ok) throw new Error("Approved operator assets could not be staged");

  let instrumentation: unknown;
  let instrumentationRecovery: unknown;
  if (plan.instrumentation?.elastic_agent) {
    await validateApprovedElasticConfiguration(plan.instrumentation.elastic_agent);
    let status = await getElasticAgentStatus(plan.scope);
    if (!isElasticAgentHealthy(status)) {
      const installedAgentChecks = await Promise.all([
        runOnTarget(
          plan.scope,
          [MACOS_TEST_BINARY, "-e", "/Library/Elastic/Agent"],
          30_000
        ),
        runOnTarget(
          plan.scope,
          [MACOS_TEST_BINARY, "-e", "/usr/local/bin/elastic-agent"],
          30_000
        ),
      ]);
      if (
        installedAgentChecks.some(
          (result) => result.exitCode === 0 && !result.timedOut
        )
      ) {
        assertNoMdmTemplateControls(plan);
        instrumentationRecovery = await sanitizeElasticAgentForTemplate(plan.scope);
        if (!(instrumentationRecovery as { ok?: boolean }).ok) {
          throw new Error("Could not sanitize the stale Elastic Agent before re-enrollment");
        }
      }
      const enrollment = await createEphemeralEnrollmentToken(
        plan.instrumentation.elastic_agent,
        runId
      );
      store.recordResource(runId, {
        id: `fleet-enrollment-token:${enrollment.id}`,
        kind: "elastic-fleet-enrollment-token",
        origin: "provisioned",
        cleaned: false,
        notes: `Temporary token for policy ${enrollment.policyId}`,
      });
      try {
        instrumentation = await installAndVerifyElasticAgent(
          plan.scope,
          plan.instrumentation.elastic_agent,
          enrollment.token
        );
      } finally {
        await revokeEnrollmentToken(enrollment.id);
        store.recordResource(runId, {
          id: `fleet-enrollment-token:${enrollment.id}`,
          kind: "elastic-fleet-enrollment-token",
          origin: "provisioned",
          cleaned: true,
          notes: `Revoked temporary token for policy ${enrollment.policyId}`,
        });
      }
      if (!(instrumentation as { ok?: boolean }).ok) {
        const failed = instrumentation as {
          installation?: Record<string, unknown>;
          endpoint_readiness?: unknown;
        };
        const installation = failed.installation ?? {};
        throw new Error(
          `Elastic Agent did not become healthy: ${JSON.stringify({
            error: installation.error,
            install_exit_code: installation.install_exit_code,
            process_exit_code: installation.process_exit_code,
            process_stderr: installation.process_stderr,
            endpoint_readiness: failed.endpoint_readiness,
          })}`
        );
      }
      status = await getElasticAgentStatus(plan.scope);
    }
    if (!isElasticAgentHealthy(status)) throw new Error("Elastic Agent is not healthy");
    const endpointReadiness = await getElasticEndpointReadiness(plan.scope, status);
    if (!endpointReadiness.ok) {
      throw new Error(
        "Elastic Endpoint is not telemetry-ready; require an active and enabled co.elastic.systemextension plus successful Full Disk Access and network-filter install checks"
      );
    }
    const processTelemetryReadiness = await waitForElasticProcessTelemetry(
      plan.scope,
      plan.instrumentation.elastic_agent,
      runId
    );
    instrumentation = {
      ...((instrumentation as Record<string, unknown> | undefined) ?? {
        status,
        endpoint_readiness: endpointReadiness,
      }),
      process_telemetry_readiness: processTelemetryReadiness,
    };
  }

  const snapshot = store.recordResource(runId, {
    id: plan.scope.target_id,
    kind: "target",
    origin: plan.scope.lifecycle === "existing" ? "existing" : "provisioned",
    cleaned: false,
    notes: `${plan.scope.target_kind}:${plan.scope.distro}:${plan.scope.architecture}`,
  });
  return {
    ok: true,
    macos_version: version.stdout.trim(),
    architecture: actualArchitecture,
    powershell: powershell.stdout.trim(),
    source_revision: sourceRevision.stdout.trim(),
    runner_revision: runnerRevision.stdout.trim(),
    source_assets: sourceAssets,
    staged_source_assets: stagedSourceAssets,
    packages,
    capabilities,
    instrumentation,
    instrumentation_recovery: instrumentationRecovery,
    startup,
    run: snapshot,
  };
}

async function doctor(): Promise<Record<string, unknown>> {
  const checks = await Promise.all(
    [
      ["tart", ["--version"]],
      ["ssh", ["-V"]],
      ["git", ["--version"]],
    ].map(async ([command, args]) => {
      const result = await runProcess(command as string, args as string[], {
        timeoutMs: 15_000,
      });
      return {
        command,
        ok: result.exitCode === 0 && !result.timedOut,
        stdout: result.stdout.trim(),
        stderr: result.stderr.trim(),
      };
    })
  );
  return {
    ok: checks.every((check) => check.ok),
    host_platform: process.platform,
    host_architecture: process.arch,
    checks,
  };
}

async function targetStatus(plan: AtomicPlan): Promise<Record<string, unknown>> {
  if (plan.scope.target_kind === "tart") {
    const exists = await tartTargetExists(plan.scope.target_id);
    return { ok: exists, kind: "tart", target_id: plan.scope.target_id, exists };
  }
  const result = await runOnTarget(plan.scope, ["sw_vers", "-productVersion"], 30_000);
  return {
    ok: result.exitCode === 0 && !result.timedOut,
    kind: "ssh",
    target_id: plan.scope.target_id,
    macos_version: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
}

function normalizeArchitecture(value: string): "arm64" | "x86_64" {
  if (value === "arm64" || value === "aarch64") return "arm64";
  if (value === "x86_64" || value === "amd64") return "x86_64";
  throw new Error(`Unsupported macOS target architecture ${value}`);
}
