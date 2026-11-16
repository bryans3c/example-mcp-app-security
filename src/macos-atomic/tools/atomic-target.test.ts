/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it, vi } from "vitest";
import type { AtomicPlan, LoadedRun } from "./atomic-run-state.js";
import {
  assertNoMdmTemplateControls,
  assertNoMdmTemplatePromotionReady,
  pinnedRepositoryRevisionArgs,
  stageApprovedAwsRuntimeCredentials,
  waitForElasticProcessTelemetry,
} from "./atomic-target.js";

describe("macOS Atomic target verification", () => {
  it("verifies root-owned pinned repositories as root", () => {
    expect(pinnedRepositoryRevisionArgs("/opt/atomic-red-team")).toEqual([
      "sudo",
      "git",
      "-C",
      "/opt/atomic-red-team",
      "rev-parse",
      "HEAD",
    ]);
  });

  it("requires explicit destructive, snapshot, reboot, and TCC authority for a no-MDM template", () => {
    const plan = {
      scope: {
        target_kind: "tart",
        lifecycle: "ephemeral",
        target_profile: "desktop",
      },
      controls: {
        snapshot_before: true,
        allow_destructive: true,
        allow_reboot: false,
        allow_tcc_changes: true,
      },
    } as AtomicPlan;

    expect(() => assertNoMdmTemplateControls(plan)).toThrow(/allow_reboot/);
  });

  it("accepts an explicitly authorized no-MDM desktop template plan", () => {
    const plan = {
      scope: {
        target_kind: "tart",
        lifecycle: "ephemeral",
        target_profile: "desktop",
      },
      controls: {
        snapshot_before: true,
        allow_destructive: true,
        allow_reboot: true,
        allow_tcc_changes: true,
      },
    } as AtomicPlan;

    expect(() => assertNoMdmTemplateControls(plan)).not.toThrow();
  });

  it("refuses template promotion without proven behavior and raw telemetry", () => {
    const loaded = {
      state: { phase: "cleaning" },
      plan: { tests: [{ test_guid: "103d6533-fd2a-4d08-976a-4a598565280f" }] },
      executions: [],
      coverage: [],
    } as unknown as LoadedRun;

    expect(() => assertNoMdmTemplatePromotionReady(loaded)).toThrow(
      /behavior is not proven/
    );
  });

  it("accepts template promotion after behavior and raw telemetry are proven", () => {
    const testGuid = "103d6533-fd2a-4d08-976a-4a598565280f";
    const loaded = {
      state: { phase: "cleaning" },
      plan: { tests: [{ test_guid: testGuid }] },
      executions: [
        {
          test_guid: testGuid,
          stage: "execute",
          status: "passed",
          behavior_success: true,
        },
      ],
      coverage: [
        {
          test_guid: testGuid,
          outcome: "missed",
          raw_event_count: 2,
          alert_count: 0,
        },
      ],
    } as unknown as LoadedRun;

    expect(() => assertNoMdmTemplatePromotionReady(loaded)).not.toThrow();
  });

  it("stages approved AWS credentials through stdin without returning secret material", async () => {
    const runHostProcess = vi.fn().mockResolvedValue({
      exitCode: 0,
      timedOut: false,
      truncated: false,
      stdout: JSON.stringify({
        Version: 1,
        AccessKeyId: "AKIAEXAMPLE",
        SecretAccessKey: "secret-example",
        SessionToken: "token-example",
        Expiration: "2026-11-15T12:00:00Z",
      }),
      stderr: "",
    });
    const runTarget = vi.fn().mockResolvedValue({
      exitCode: 0,
      timedOut: false,
      truncated: false,
      stdout: "",
      stderr: "",
    });
    const result = await stageApprovedAwsRuntimeCredentials(
      { target_kind: "tart", lifecycle: "ephemeral" } as AtomicPlan["scope"],
      { source_profile: "trade-emulation", target_profile: "default" },
      { runHostProcess, runTarget }
    );

    expect(result).toEqual({
      ok: true,
      provider: "aws",
      source_profile: "trade-emulation",
      target_profile: "default",
      temporary: true,
      expiration: "2026-11-15T12:00:00Z",
    });
    expect(JSON.stringify(result)).not.toContain("secret-example");
    expect(JSON.stringify(runTarget.mock.calls[0]?.slice(0, 3))).not.toContain("secret-example");
    expect(runTarget.mock.calls[0]?.[3]?.input).toContain(
      "aws_secret_access_key = secret-example"
    );
  });

  it("refuses AWS runtime credentials on a persistent target before reading the host profile", async () => {
    const runHostProcess = vi.fn();
    await expect(stageApprovedAwsRuntimeCredentials(
      { target_kind: "ssh", lifecycle: "existing" } as AtomicPlan["scope"],
      { source_profile: "trade-emulation", target_profile: "default" },
      { runHostProcess }
    )).rejects.toThrow("fresh ephemeral Tart target");
    expect(runHostProcess).not.toHaveBeenCalled();
  });

  it("waits until a target marker process is observable in Endpoint telemetry", async () => {
    let clock = 0;
    const runTarget = vi.fn()
      .mockResolvedValueOnce({
        exitCode: 0,
        timedOut: false,
        stdout: "art-ready-a1\n",
        stderr: "",
      })
      .mockResolvedValue({
        exitCode: 0,
        timedOut: false,
        stdout: "marker\n",
        stderr: "",
      });
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ count: 0 }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ count: 1 }), { status: 200 }));
    const result = await waitForElasticProcessTelemetry(
      {} as AtomicPlan["scope"],
      {
        kibana_url: "https://kibana.example",
        elasticsearch_url: "https://elasticsearch.example",
      } as NonNullable<AtomicPlan["instrumentation"]>["elastic_agent"],
      "macos-art-ready-a1",
      {
        runTarget,
        fetchImpl,
        sleep: async (milliseconds) => { clock += milliseconds; },
        now: () => clock,
        timeoutMs: 30_000,
        pollMs: 1_000,
        environment: {
          kibanaUrl: "https://kibana.example",
          apiKey: "test-api-key",
        },
      }
    );

    expect(result).toEqual({
      ok: true,
      host_name: "art-ready-a1",
      marker: "macos-atomic-ready-macos-art-ready-a1",
      attempts: 2,
      waited_ms: 2_000,
      event_count: 1,
    });
    expect(runTarget).toHaveBeenCalledTimes(3);
    const secondRequest = fetchImpl.mock.calls[1]?.[1] as RequestInit;
    expect(String(secondRequest.body)).toContain("macos-atomic-ready-macos-art-ready-a1");
    expect(String(secondRequest.body)).toContain('\"event.action\":\"exec\"');
  });

  it("fails closed when Endpoint never reports the marker process", async () => {
    let clock = 0;
    await expect(waitForElasticProcessTelemetry(
      {} as AtomicPlan["scope"],
      {
        kibana_url: "https://kibana.example",
        elasticsearch_url: "https://elasticsearch.example",
      } as NonNullable<AtomicPlan["instrumentation"]>["elastic_agent"],
      "macos-art-not-ready",
      {
        runTarget: vi.fn()
          .mockResolvedValueOnce({
            exitCode: 0,
            timedOut: false,
            stdout: "art-not-ready\n",
            stderr: "",
          })
          .mockResolvedValue({
            exitCode: 0,
            timedOut: false,
            stdout: "marker\n",
            stderr: "",
          }),
        fetchImpl: vi.fn().mockImplementation(async () =>
          new Response(JSON.stringify({ count: 0 }), { status: 200 })
        ),
        sleep: async (milliseconds) => { clock += milliseconds; },
        now: () => clock,
        timeoutMs: 2_000,
        pollMs: 1_000,
        environment: {
          kibanaUrl: "https://kibana.example",
          apiKey: "test-api-key",
        },
      }
    )).rejects.toThrow("process telemetry was not observable");
  });
});
