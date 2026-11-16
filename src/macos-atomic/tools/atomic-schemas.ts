/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from "zod";

export const jsonScalarSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.null(),
]);

export const queryPlanSchema = z.object({
  indices: z.array(z.string().min(1)).min(1),
  query: z.record(z.string(), z.unknown()),
});

export const fixtureSchema = z.object({
  input_name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
  content_base64: z
    .string()
    .min(4)
    .max(131_072)
    .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i),
  mode: z.enum(["0644", "0755"]).default("0644"),
  description: z.string().min(1).optional(),
});

export const sourceAssetSchema = z.object({
  path: z
    .string()
    .min(1)
    .max(4_096)
    .regex(/^(?!\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\/\/)(?!.*\/$)(?!.*[\0\r\n\\]).+$/),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i),
  size: z.number().int().min(0).max(1_073_741_824),
});

export const approvedPackageSchema = z.object({
  manager: z.literal("brew"),
  name: z.string().regex(/^[a-z0-9][a-z0-9+@.-]{0,79}$/),
  version: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$/).optional(),
  reason: z.string().min(1).max(500),
});

const outputNeedleSchema = z.string().min(1).max(4_096);
const targetPathSchema = z.string().regex(/^\/[^\0\r\n]{1,4095}$/);

export const successCriterionSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("stdout_contains"), value: outputNeedleSchema }),
  z.object({ kind: z.literal("stderr_contains"), value: outputNeedleSchema }),
  z.object({ kind: z.literal("target_path_exists"), path: targetPathSchema }),
  z.object({ kind: z.literal("target_path_absent"), path: targetPathSchema }),
  z.object({
    kind: z.literal("target_path_timestamp_equals"),
    path: targetPathSchema,
    field: z.enum(["atime", "mtime"]),
    epoch_seconds: z.number().int().min(-2_208_988_800).max(32_503_680_000),
  }),
  z.object({
    kind: z.literal("target_path_timestamp_matches"),
    path: targetPathSchema,
    field: z.enum(["atime", "mtime"]),
    reference_path: targetPathSchema,
  }),
  z.object({
    kind: z.literal("target_path_mode_equals"),
    path: targetPathSchema,
    mode: z.string().regex(/^[0-7]{3,4}$/),
  }),
  z.object({
    kind: z.literal("target_path_size_equals"),
    path: targetPathSchema,
    bytes: z.number().int().min(0).max(1_099_511_627_776),
  }),
  z.object({
    kind: z.literal("target_path_owner_equals"),
    path: targetPathSchema,
    owner: z.string().regex(/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/),
    group: z.string().regex(/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/).optional(),
  }),
  z.object({
    kind: z.literal("target_path_xattr_absent"),
    path: targetPathSchema,
    name: z.string().regex(/^[A-Za-z0-9_.-]{1,255}$/),
  }),
  z.object({
    kind: z.literal("target_path_flags_contains"),
    path: targetPathSchema,
    value: z.string().min(1).max(128),
  }),
  z.object({
    kind: z.literal("target_path_contains"),
    path: targetPathSchema,
    value: outputNeedleSchema,
  }),
  z.object({
    kind: z.literal("target_path_not_contains"),
    path: targetPathSchema,
    value: outputNeedleSchema,
  }),
  z.object({ kind: z.literal("target_rebooted") }),
  z.object({ kind: z.literal("target_stopped") }),
  z.object({
    kind: z.literal("manual_evidence"),
    description: z.string().min(1).max(1_000),
  }),
]);

export const setupStepSchema = z.object({
  description: z.string().min(1).max(500),
  command: z.array(z.string().min(1).max(4_096)).min(1).max(64),
  elevated: z.boolean().default(false),
});

export const targetCapabilitySchema = z.enum([
  "shell",
  "powershell",
  "launchd",
  "kernel",
  "network",
  "gui",
  "browser",
  "interactive",
  "reboot",
  "special_runtime",
  "endpoint_security",
  "full_disk_access",
  "tcc",
  "sip",
  "real_hardware",
]);

const manualExecutionSchema = z.object({
  reviewed_steps: z.array(z.string().min(1).max(4_000)).min(1).max(100),
  evidence_requirements: z.array(z.string().min(1).max(1_000)).min(1).max(20),
  cleanup_steps: z.array(z.string().min(1).max(4_000)).max(100).optional(),
});

export const elasticAgentPlanSchema = z.object({
  stack_version: z.string().regex(/^\d+\.\d+\.\d+$/),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  kibana_url: z
    .string()
    .url()
    .refine((value) => {
      const parsed = new URL(value);
      return parsed.protocol === "https:" && !parsed.username && !parsed.password;
    }, {
      message: "Kibana URL must use HTTPS and must not contain credentials",
    }),
  fleet_url: z
    .string()
    .url()
    .refine((value) => {
      const parsed = new URL(value);
      return parsed.protocol === "https:" && !parsed.username && !parsed.password;
    }, {
      message: "Fleet URL must use HTTPS and must not contain credentials",
    }),
  fleet_server_host_id: z.string().min(1),
  agent_policy_id: z.string().min(1),
  agent_policy_name: z.string().min(1),
  agent_policy_revision: z.number().int().min(1),
  elastic_defend_package_policy_id: z.string().min(1),
  elastic_defend_package_version: z.string().min(1),
  elasticsearch_output_id: z.string().min(1),
  elasticsearch_url: z
    .string()
    .url()
    .refine((value) => {
      const parsed = new URL(value);
      return parsed.protocol === "https:" && !parsed.username && !parsed.password;
    }, {
      message: "Elasticsearch URL must use HTTPS and must not contain credentials",
    }),
  ca_sha256: z.string().regex(/^[0-9a-f]{64}$/i).optional(),
  insecure: z.boolean().default(false),
  health_timeout_seconds: z.number().int().min(30).max(900).default(300),
});

export const testPlanSchema = z.object({
  technique_id: z.string().regex(/^T\d{4}(?:\.\d{3})?$/),
  test_guid: z.string().uuid(),
  name: z.string().min(1),
  executor: z.string().min(1),
  execution_mode: z.enum(["runner", "operator"]),
  execution_adapter: z
    .enum([
      "bash_interactive",
      "macos_usr_bin_echo_compat",
      "macos_t1036_006_compat",
      "macos_t1046_port_scan_compat",
      "macos_t1027_001_dd_multiline_compat",
      "macos_t1685_006_cat_dd_multiline_compat",
      "macos_t1685_006_srm_multiline_compat",
      "macos_t1685_006_realtime_log_clearance_compat",
      "macos_t1496_yes_bounded_compat",
      "macos_t1497_003_local_ping_compat",
      "macos_t1059_004_local_pipe_compat",
      "macos_t1059_004_awk_shell_compat",
      "macos_t1548_003_sudo_vim_compat",
      "macos_t1548_003_bsd_sed_compat",
      "macos_t1485_dd_count_bytes_compat",
      "macos_t1486_7z_password_compat",
      "macos_t1548_001_setuid_path_compat",
      "macos_t1027_013_powershell_compat",
      "macos_t1059_004_ping_compat",
      "macos_t1552_001_find_loop_compat",
      "macos_t1040_bpf_bounded_compat",
      "macos_t1090_001_proxy_verify_compat",
      "macos_t1135_network_share_compat",
      "macos_t1078_003_sysadminctl_compat",
      "macos_t1078_003_dsenableroot_compat",
      "macos_t1564_001_xattr_scan_compat",
      "macos_t1685_006_find_multiline_compat",
      "macos_t1048_ssh_push_local_compat",
      "macos_t1048_ssh_pull_local_compat",
      "macos_t1048_002_curl_local_compat",
      "macos_t1074_001_discovery_local_compat",
      "macos_t1659_proxy_injection_local_compat",
      "macos_t1070_008_mailbox_fixture_compat",
      "macos_t1222_002_chattr_compat",
      "macos_t1059_004_cpan_shell_compat",
      "macos_t1059_004_emacs_shell_compat",
      "macos_t1531_password_change_compat",
      "macos_t1546_018_python_hook_compat",
      "macos_t1564_001_finder_hidden_verify_compat",
      "macos_t1685_gatekeeper_verify_compat",
      "macos_t1497_001_virtualization_compat",
      "macos_t1070_006_birthtime_compat",
      "macos_t1529_reboot_path_compat",
      "macos_t1529_shutdown_path_compat",
      "macos_t1555_001_keychain_import_compat",
      "macos_t1553_004_root_ca_compat",
      "macos_t1059_002_applescript_loopback_compat",
      "macos_t1021_005_ard_compat",
      "macos_t1490_timemachine_compat",
      "macos_t1555_003_safari_cookie_compat",
      "macos_t1113_screencapture_compat",
      "macos_t1110_004_ssh_credential_stuffing_compat",
      "macos_t1098_004_authorized_keys_compat",
      "macos_t1056_002_prompt_compat",
      "macos_t1552_001_lazagne_compat",
      "macos_t1539_cookie_debug_compat",
      "macos_t1572_cloudflare_compat",
      "macos_t1685_vendor_fixture_compat",
      "macos_manual_t1036_006_compat",
      "macos_manual_t1037_002_compat",
      "macos_manual_t1048_003_loopback_compat",
      "macos_manual_t1176_chromium_compat",
      "macos_manual_t1176_firefox_compat",
      "macos_manual_t1647_compat",
      "macos_manual_t1690_compat",
    ])
    .optional(),
  elevation_required: z.boolean(),
  required_capabilities: z.array(targetCapabilitySchema).max(20),
  definition_digest: z.string().regex(/^[0-9a-f]{64}$/i),
  inputs: z.record(z.string(), jsonScalarSchema),
  expected_outcome: z.string().min(1),
  success_criteria: z.array(successCriterionSchema).min(1).max(10),
  cleanup_expected: z.boolean(),
  risk_flags: z.array(z.string()),
  manual: manualExecutionSchema.optional(),
  fixtures: z.array(fixtureSchema).max(20).optional(),
  source_assets: z.array(sourceAssetSchema).max(500).optional(),
  telemetry: z
    .object({
      raw: queryPlanSchema.optional(),
      alerts: queryPlanSchema.optional(),
      correlation_fields: z.array(z.string()).optional(),
    })
    .optional(),
}).superRefine((test, context) => {
  const manualExecutor = test.executor.toLowerCase().includes("manual");
  const automatedManualExecutor =
    manualExecutor &&
    test.execution_adapter !== undefined &&
    [
      "macos_manual_t1036_006_compat",
      "macos_manual_t1037_002_compat",
      "macos_manual_t1048_003_loopback_compat",
      "macos_manual_t1176_chromium_compat",
      "macos_manual_t1176_firefox_compat",
      "macos_manual_t1647_compat",
      "macos_manual_t1690_compat",
    ].includes(test.execution_adapter);
  if (
    test.execution_adapter !== undefined &&
    !["sh", "bash"].includes(test.executor.toLowerCase()) &&
    !automatedManualExecutor &&
    !(
      test.execution_adapter === "macos_t1027_013_powershell_compat" &&
      test.executor.toLowerCase() === "powershell"
    )
  ) {
    context.addIssue({
      code: "custom",
      path: ["execution_adapter"],
      message: "the selected execution adapter is not allowed for this executor",
    });
  }
  if (manualExecutor && !automatedManualExecutor && test.execution_mode !== "operator") {
    context.addIssue({
      code: "custom",
      path: ["execution_mode"],
      message: "manual executors require execution_mode=operator",
    });
  }
  if (manualExecutor && !automatedManualExecutor && !test.manual) {
    context.addIssue({
      code: "custom",
      path: ["manual"],
      message: "manual executors require reviewed operator steps",
    });
  }
  if (
    manualExecutor &&
    !automatedManualExecutor &&
    !test.success_criteria.some((criterion) => criterion.kind === "manual_evidence")
  ) {
    context.addIssue({
      code: "custom",
      path: ["success_criteria"],
      message: "manual executors require manual_evidence success criteria",
    });
  }
  if (
    manualExecutor &&
    !automatedManualExecutor &&
    test.cleanup_expected &&
    !test.manual?.cleanup_steps?.length
  ) {
    context.addIssue({
      code: "custom",
      path: ["manual", "cleanup_steps"],
      message: "manual executors with cleanup_expected require cleanup steps",
    });
  }
  if (
    automatedManualExecutor &&
    (test.execution_mode !== "runner" || test.manual !== undefined)
  ) {
    context.addIssue({
      code: "custom",
      path: ["execution_mode"],
      message: "automated manual compatibility adapters require runner mode without operator steps",
    });
  }
  if (!manualExecutor && test.execution_mode !== "runner") {
    context.addIssue({
      code: "custom",
      path: ["execution_mode"],
      message: "automated executors require execution_mode=runner",
    });
  }
  if (!manualExecutor && test.manual) {
    context.addIssue({
      code: "custom",
      path: ["manual"],
      message: "manual procedure is allowed only for manual executors",
    });
  }
});

export const atomicPlanSchema = z.object({
  schema_version: z.literal(3),
  run_id: z.string().min(3),
  mode: z.enum(["atomic", "rule", "coverage", "regression"]),
  type: z.enum(["atomic", "micro", "full"]),
  source: z.object({
    kind: z.enum(["atomic-red-team", "rule", "gap", "baseline"]),
    reference: z.string().min(1),
    repository: z.string().min(1),
    revision: z.string().regex(/^[0-9a-f]{40}$/i),
    catalog_digest: z.string().regex(/^[0-9a-f]{64}$/i),
  }),
  runner: z.object({
    repository: z.string().min(1),
    revision: z.string().regex(/^[0-9a-f]{40}$/i),
  }),
  objective: z.string().min(8),
  scope: z.object({
    target_kind: z.enum(["tart", "ssh"]),
    target_id: z.string().min(2),
    target_profile: z.enum(["server", "desktop", "custom"]),
    execution_user: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/),
    capabilities: z.array(targetCapabilitySchema).min(1).max(20),
    platform: z.literal("macos"),
    distro: z.string().regex(/^macos-(?:1[2345]|26)$/),
    architecture: z.enum(["arm64", "x86_64"]),
    target_image: z
      .string()
      .regex(
        /^(?:ghcr\.io\/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}|tvm\+file:\/\/\/[^#\r\n]+\.tvm#sha256=[0-9a-f]{64})$/i
      )
      .optional(),
    ssh_identity_file: z.string().min(1).max(4_096).optional(),
    classification: z.literal("owned-disposable-lab"),
    lifecycle: z.enum(["ephemeral", "existing"]),
    network: z.enum(["isolated", "egress-only", "custom"]),
  }),
  controls: z.object({
    ttl_minutes: z.number().int().min(1).max(10_080),
    allow_reboot: z.boolean(),
    allow_external_targets: z.boolean(),
    allow_destructive: z.boolean(),
    snapshot_before: z.boolean(),
    allow_setup_commands: z.boolean().default(false),
    allow_tcc_changes: z.boolean().default(false),
    allow_sip_changes: z.boolean().default(false),
  }),
  target_prerequisites: z
    .object({
      packages: z.array(approvedPackageSchema).min(1).max(100),
    })
    .optional(),
  setup_steps: z.array(setupStepSchema).min(1).max(20).optional(),
  runtime_credentials: z
    .object({
      aws: z
        .object({
          source_profile: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/),
          target_profile: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/),
        })
        .optional(),
    })
    .refine((value) => value.aws !== undefined, {
      message: "runtime_credentials must configure at least one provider",
    })
    .optional(),
  instrumentation: z
    .object({
      elastic_agent: elasticAgentPlanSchema,
    })
    .optional(),
  tests: z.array(testPlanSchema).min(1),
}).superRefine((plan, context) => {
  if (plan.setup_steps?.length && !plan.controls.allow_setup_commands) {
    context.addIssue({
      code: "custom",
      path: ["setup_steps"],
      message:
        "setup_steps require controls.allow_setup_commands=true; approve the digest only after reviewing the exact commands",
    });
  }
  if (plan.scope.target_kind === "tart" && !plan.scope.target_image) {
    context.addIssue({
      code: "custom",
      path: ["scope", "target_image"],
      message: "Tart targets require an immutable target_image reference",
    });
  }
  if (plan.scope.target_kind === "ssh" && !plan.scope.ssh_identity_file) {
    context.addIssue({
      code: "custom",
      path: ["scope", "ssh_identity_file"],
      message: "SSH targets require an identity file",
    });
  }
  if (
    plan.runtime_credentials !== undefined &&
    (plan.scope.target_kind !== "tart" || plan.scope.lifecycle !== "ephemeral")
  ) {
    context.addIssue({
      code: "custom",
      path: ["runtime_credentials"],
      message: "runtime credentials are allowed only on fresh ephemeral Tart targets",
    });
  }
});

export const resourceSchema = z.object({
  id: z.string().min(1),
  kind: z.string().min(1),
  origin: z.enum(["provisioned", "existing", "orphaned"]),
  cleaned: z.boolean(),
  notes: z.string().optional(),
});

export const executionRecordSchema = z.object({
  test_guid: z.string().uuid(),
  stage: z.enum(["prereq", "execute", "manual", "cleanup"]),
  status: z.enum(["passed", "failed", "skipped", "blocked"]),
  started_at: z.string().datetime(),
  ended_at: z.string().datetime(),
  exit_code: z.number().int().optional(),
  behavior_success: z.boolean().optional(),
  evidence_path: z.string().optional(),
  notes: z.string().optional(),
});

export const coverageRecordSchema = z.object({
  test_guid: z.string().uuid(),
  outcome: z.enum(["detected", "missed", "no_telemetry", "not_applicable"]),
  raw_event_count: z.number().int().min(0).optional(),
  alert_count: z.number().int().min(0).optional(),
  attributable_rule_names: z.array(z.string().min(1).max(1_024)).max(1_000).optional(),
  detector: z.string().optional(),
  evidence: z.string().optional(),
  reason: z.string().optional(),
}).superRefine((record, context) => {
  if (record.outcome === "not_applicable" && !record.reason?.trim()) {
    context.addIssue({
      code: "custom",
      path: ["reason"],
      message: "not_applicable coverage requires a reason",
    });
  }
  if (record.alert_count === 0 && record.attributable_rule_names?.length) {
    context.addIssue({
      code: "custom",
      path: ["attributable_rule_names"],
      message: "attributable rule names require at least one attributable alert",
    });
  }
});
