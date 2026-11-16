/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  discoverElasticFleet,
  getElasticEnvironment,
} from "../execution/elastic-fleet.js";
import { publishAtomicRunResults } from "../execution/elastic-results.js";
import {
  createAtomicRunStore,
  type AtomicQueryPlan,
  type AtomicCoverageRecord,
} from "./atomic-run-state.js";
import { textResult } from "./atomic-run.js";

const DEFAULT_ALERT_GRACE_SECONDS = 120;
const MAX_ALERT_GRACE_SECONDS = 900;

const elasticSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("discover"),
    run_id: z.string().min(1),
  }),
  z.object({
    action: z.literal("probe"),
    run_id: z.string().min(1),
    test_guid: z.string().uuid(),
    layer: z.enum(["raw", "alerts"]),
    start: z.string().datetime(),
    end: z.string().datetime(),
    timestamp_field: z.string().regex(/^[A-Za-z0-9_.@-]+$/).default("@timestamp"),
  }),
  z.object({
    action: z.literal("verify"),
    run_id: z.string().min(1),
    test_guid: z.string().uuid(),
    start: z.string().datetime(),
    end: z.string().datetime(),
    timestamp_field: z.string().regex(/^[A-Za-z0-9_.@-]+$/).default("@timestamp"),
  }),
  z.object({
    action: z.literal("publish_results"),
    run_id: z.string().min(1),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/).optional(),
  }),
]);

const elasticToolSchema = z.object({
  action: z.enum(["discover", "probe", "verify", "publish_results"]),
  run_id: z.string().min(1),
  campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/).optional(),
  test_guid: z.string().uuid().optional(),
  layer: z.enum(["raw", "alerts"]).optional(),
  start: z.string().datetime().optional(),
  end: z.string().datetime().optional(),
  timestamp_field: z.string().regex(/^[A-Za-z0-9_.@-]+$/).default("@timestamp"),
});

export function registerAtomicElasticTool(
  server: McpServer,
  store = createAtomicRunStore()
): void {
  server.registerTool(
    "macos-atomic-elastic",
    {
      title: "Atomic Elastic Coverage",
      description:
        "Discover a minimal-input Elastic Fleet configuration during planning, execute only the raw-event and alert count queries embedded in the digest-approved plan, or publish terminal per-GUID outcome documents to the discovered Elasticsearch output. It reuses the app's default Elastic cluster credentials, with KIBANA_URL and ELASTIC_API_KEY available as explicit overrides. Publishing is retry-safe through deterministic document IDs and a local NDJSON outbox.",
      inputSchema: elasticToolSchema,
    },
    async (input) => {
      try {
        const parsed = elasticSchema.parse(input);
        if (parsed.action === "discover") {
          store.assertPhase(parsed.run_id, ["planning", "awaiting_approval"]);
          return textResult({ ok: true, ...(await discoverElasticFleet()) });
        }
        const loaded = store.getLoaded(parsed.run_id);
        if (!loaded.plan) return textResult({ error: "No approved plan is stored" }, true);
        if (parsed.action === "publish_results") {
          return textResult(
            await publishAtomicRunResults(loaded, { campaignId: parsed.campaign_id })
          );
        }
        const test = store.getApprovedTest(parsed.run_id, parsed.test_guid);
        if (parsed.action === "probe") {
          store.assertPhase(parsed.run_id, ["verifying", "covering"]);
          const query = test.telemetry?.[parsed.layer];
          if (!query) {
            return textResult(
              { error: `No ${parsed.layer} query is bound into the approved test plan` },
              true
            );
          }
          const count = await elasticCount(
            query,
            parsed.start,
            parsed.end,
            parsed.timestamp_field,
            loaded.plan.instrumentation?.elastic_agent.elasticsearch_url
          );
          return textResult({ ok: true, layer: parsed.layer, count });
        }

        store.assertPhase(parsed.run_id, ["covering"]);
        const rawQuery = test.telemetry?.raw;
        const alertQuery = test.telemetry?.alerts;
        if (!rawQuery || !alertQuery) {
          return textResult(
            {
              error:
                "verify needs both telemetry.raw and telemetry.alerts in the approved plan. Otherwise use the relevant hunt/rule tools and record_coverage manually.",
            },
            true
          );
        }
        const execution = loaded.executions.find(
          (record) =>
            record.test_guid === test.test_guid &&
            (record.stage === "execute" || record.stage === "manual")
        );
        const alertGrace = await waitForAlertGracePeriod(execution?.ended_at);
        const effectiveEnd = laterTimestamp(parsed.end, new Date().toISOString());
        const [rawCount, alertSummary] = await Promise.all([
          elasticCount(
            rawQuery,
            parsed.start,
            parsed.end,
            parsed.timestamp_field,
            loaded.plan.instrumentation?.elastic_agent.elasticsearch_url
          ),
          elasticAlertSummary(
            alertQuery,
            parsed.start,
            effectiveEnd,
            parsed.timestamp_field,
            loaded.plan.instrumentation?.elastic_agent.elasticsearch_url
          ),
        ]);
        const alertCount = alertSummary.count;
        const behaviorConfirmed =
          execution?.status === "passed" && execution.behavior_success === true;
        const outcome: AtomicCoverageRecord["outcome"] =
          !behaviorConfirmed
            ? "not_applicable"
            : rawCount === 0
              ? "no_telemetry"
              : alertCount === 0
                ? "missed"
                : "detected";
        const evidencePath = writeCoverageEvidence(loaded.dir, {
          test_guid: test.test_guid,
          start: parsed.start,
          end: effectiveEnd,
          raw_end: parsed.end,
          alert_end: effectiveEnd,
          requested_end: parsed.end,
          alert_grace_seconds: alertGrace.grace_seconds,
          alert_waited_ms: alertGrace.waited_ms,
          raw_event_count: rawCount,
          alert_count: alertCount,
          attributable_rule_names: alertSummary.rule_names,
          behavior_success: execution?.behavior_success ?? false,
          outcome,
          raw_indices: rawQuery.indices,
          alert_indices: alertQuery.indices,
        });
        const snapshot = store.recordCoverage(parsed.run_id, {
          test_guid: test.test_guid,
          outcome,
          raw_event_count: rawCount,
          alert_count: alertCount,
          attributable_rule_names: alertSummary.rule_names,
          detector: "elastic",
          evidence: evidencePath,
          reason: coverageReason(
            outcome,
            rawCount,
            alertCount,
            alertGrace.grace_seconds
          ),
        });
        return textResult({
          ok: true,
          test_guid: test.test_guid,
          outcome,
          raw_event_count: rawCount,
          alert_count: alertCount,
          attributable_rule_names: alertSummary.rule_names,
          effective_end: effectiveEnd,
          alert_grace_seconds: alertGrace.grace_seconds,
          alert_waited_ms: alertGrace.waited_ms,
          evidence_path: evidencePath,
          run: snapshot,
        });
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    }
  );
}

export async function waitForAlertGracePeriod(
  executionEndedAt: string | undefined,
  options: {
    readonly now?: () => number;
    readonly sleep?: (milliseconds: number) => Promise<void>;
    readonly env?: Readonly<Record<string, string | undefined>>;
  } = {}
): Promise<{ readonly grace_seconds: number; readonly waited_ms: number }> {
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? ((milliseconds: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const graceSeconds = alertGraceSeconds(options.env ?? process.env);
  if (!executionEndedAt) return { grace_seconds: graceSeconds, waited_ms: 0 };
  const endedAt = Date.parse(executionEndedAt);
  if (!Number.isFinite(endedAt)) {
    throw new Error("Execution end time is invalid; refusing delayed alert verification");
  }
  const remaining = Math.max(0, endedAt + graceSeconds * 1_000 - now());
  if (remaining > 0) await sleep(remaining);
  return { grace_seconds: graceSeconds, waited_ms: remaining };
}

function alertGraceSeconds(env: Readonly<Record<string, string | undefined>>): number {
  const configured = env.MACOS_ATOMIC_ALERT_GRACE_SECONDS?.trim();
  if (!configured) return DEFAULT_ALERT_GRACE_SECONDS;
  if (!/^\d+$/.test(configured)) {
    throw new Error("MACOS_ATOMIC_ALERT_GRACE_SECONDS must be an integer from 0 to 900");
  }
  const seconds = Number(configured);
  if (seconds > MAX_ALERT_GRACE_SECONDS) {
    throw new Error("MACOS_ATOMIC_ALERT_GRACE_SECONDS must be an integer from 0 to 900");
  }
  return seconds;
}

function laterTimestamp(first: string, second: string): string {
  return Date.parse(first) >= Date.parse(second) ? first : second;
}

function coverageReason(
  outcome: AtomicCoverageRecord["outcome"],
  rawCount: number,
  alertCount: number,
  graceSeconds: number
): string {
  if (outcome === "not_applicable") {
    return `Behavior success was not confirmed; ${rawCount} raw event(s) and ${alertCount} alert(s) are contextual only after a ${graceSeconds}-second grace period`;
  }
  if (outcome === "detected") {
    return `Behavior succeeded; ${rawCount} matching raw event(s) and ${alertCount} attributable alert(s) were observed after a ${graceSeconds}-second grace period`;
  }
  if (outcome === "missed") {
    return `Behavior succeeded; ${rawCount} matching raw event(s) were observed, but no attributable alert was found after a ${graceSeconds}-second grace period`;
  }
  return `Behavior succeeded; no matching raw telemetry or attributable alert was found after a ${graceSeconds}-second grace period`;
}

async function elasticCount(
  plan: AtomicQueryPlan,
  start: string,
  end: string,
  timestampField: string,
  approvedBase?: string
): Promise<number> {
  const base = approvedBase ?? process.env.ELASTICSEARCH_URL;
  const apiKey = getElasticEnvironment().apiKey;
  if (!base || !apiKey) {
    throw new Error(
      "The approved plan needs an Elasticsearch output URL and ELASTIC_API_KEY is required"
    );
  }
  assertAllowedIndices(plan.indices);
  const root = base.endsWith("/") ? base : `${base}/`;
  const indices = plan.indices.join(",");
  const url = new URL(`${indices}/_count`, root);
  const response = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `ApiKey ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      query: {
        bool: {
          filter: [
            plan.query,
            { range: { [timestampField]: { gte: start, lte: end } } },
          ],
        },
      },
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    const body = (await response.text()).slice(0, 2_000);
    throw new Error(`Elastic _count failed (${response.status}): ${body}`);
  }
  const body = (await response.json()) as { count?: unknown };
  if (typeof body.count !== "number") throw new Error("Elastic response has no numeric count");
  return body.count;
}

type AttributableAlertSummary = {
  readonly count: number;
  readonly rule_names: readonly string[];
};

export function parseAttributableAlertSummary(body: unknown): AttributableAlertSummary {
  if (!body || typeof body !== "object") {
    throw new Error("Elastic alert response is not an object");
  }
  const response = body as {
    hits?: { total?: number | { value?: unknown; relation?: unknown } };
    aggregations?: { attributable_rule_names?: { buckets?: unknown } };
  };
  const total = response.hits?.total;
  const count = typeof total === "number"
    ? total
    : typeof total?.value === "number" && total.relation === "eq"
      ? total.value
      : undefined;
  if (count === undefined) {
    throw new Error("Elastic alert response has no exact numeric hit count");
  }
  const buckets = response.aggregations?.attributable_rule_names?.buckets;
  if (!Array.isArray(buckets)) {
    throw new Error("Elastic alert response has no rule-name aggregation");
  }
  const ruleNames = [...new Set(
    buckets.flatMap((bucket) => {
      if (!bucket || typeof bucket !== "object") return [];
      const key = (bucket as { key?: unknown }).key;
      return typeof key === "string" && key.length > 0 ? [key] : [];
    })
  )].sort();
  return { count, rule_names: ruleNames };
}

async function elasticAlertSummary(
  plan: AtomicQueryPlan,
  start: string,
  end: string,
  timestampField: string,
  approvedBase?: string
): Promise<AttributableAlertSummary> {
  const base = approvedBase ?? process.env.ELASTICSEARCH_URL;
  const apiKey = getElasticEnvironment().apiKey;
  if (!base || !apiKey) {
    throw new Error(
      "The approved plan needs an Elasticsearch output URL and ELASTIC_API_KEY is required"
    );
  }
  assertAllowedIndices(plan.indices);
  const root = base.endsWith("/") ? base : `${base}/`;
  const indices = plan.indices.join(",");
  const url = new URL(`${indices}/_search`, root);
  const response = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `ApiKey ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      size: 0,
      track_total_hits: true,
      query: {
        bool: {
          filter: [
            plan.query,
            { range: { [timestampField]: { gte: start, lte: end } } },
          ],
        },
      },
      aggregations: {
        attributable_rule_names: {
          terms: {
            field: "kibana.alert.rule.name",
            size: 1_000,
            order: { _key: "asc" },
          },
        },
      },
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    const responseBody = (await response.text()).slice(0, 2_000);
    throw new Error(
      `Elastic attributable-alert search failed (${response.status}): ${responseBody}`
    );
  }
  return parseAttributableAlertSummary(await response.json());
}

function assertAllowedIndices(indices: readonly string[]): void {
  const configured =
    process.env.MACOS_ATOMIC_ELASTIC_INDEX_ALLOWLIST ??
    process.env.ELASTIC_INDEX_ALLOWLIST ??
    "logs-*,filebeat-*,.alerts-security.alerts-*";
  const patterns = configured.split(",").map((value) => value.trim()).filter(Boolean);
  for (const index of indices) {
    if (!/^[A-Za-z0-9._*:-]+$/.test(index)) throw new Error(`Invalid index expression ${index}`);
    if (!patterns.some((pattern) => globMatches(pattern, index))) {
      throw new Error(`Index ${index} is outside MACOS_ATOMIC_ELASTIC_INDEX_ALLOWLIST`);
    }
  }
}

function globMatches(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(value);
}

function writeCoverageEvidence(runDir: string, value: unknown): string {
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const file = path.join(evidenceDir, `${new Date().toISOString().replace(/[:.]/g, "-")}-coverage.json`);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return file;
}
