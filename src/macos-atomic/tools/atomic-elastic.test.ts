/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  parseAttributableAlertSummary,
  waitForAlertGracePeriod,
} from "./atomic-elastic.js";

describe("waitForAlertGracePeriod", () => {
  it("waits for the remainder of the default two-minute grace period", async () => {
    const waits: number[] = [];
    const result = await waitForAlertGracePeriod("2026-11-11T22:00:00.000Z", {
      now: () => Date.parse("2026-11-11T22:01:30.000Z"),
      sleep: async (milliseconds) => { waits.push(milliseconds); },
      env: {},
    });

    expect(waits).toEqual([30_000]);
    expect(result).toEqual({ grace_seconds: 120, waited_ms: 30_000 });
  });

  it("does not wait once the grace period has elapsed", async () => {
    const waits: number[] = [];
    const result = await waitForAlertGracePeriod("2026-11-11T22:00:00.000Z", {
      now: () => Date.parse("2026-11-11T22:02:01.000Z"),
      sleep: async (milliseconds) => { waits.push(milliseconds); },
      env: {},
    });

    expect(waits).toEqual([]);
    expect(result).toEqual({ grace_seconds: 120, waited_ms: 0 });
  });

  it("supports a bounded environment override", async () => {
    const waits: number[] = [];
    const result = await waitForAlertGracePeriod("2026-11-11T22:00:00.000Z", {
      now: () => Date.parse("2026-11-11T22:00:05.000Z"),
      sleep: async (milliseconds) => { waits.push(milliseconds); },
      env: { MACOS_ATOMIC_ALERT_GRACE_SECONDS: "15" },
    });

    expect(waits).toEqual([10_000]);
    expect(result).toEqual({ grace_seconds: 15, waited_ms: 10_000 });
  });

  it("rejects an unbounded grace-period override", async () => {
    await expect(waitForAlertGracePeriod("2026-11-11T22:00:00.000Z", {
      env: { MACOS_ATOMIC_ALERT_GRACE_SECONDS: "901" },
    })).rejects.toThrow("integer from 0 to 900");
  });
});

describe("parseAttributableAlertSummary", () => {
  it("returns the exact alert count and sorted unique rule names", () => {
    expect(parseAttributableAlertSummary({
      hits: { total: { value: 3, relation: "eq" } },
      aggregations: {
        attributable_rule_names: {
          buckets: [
            { key: "Rule B", doc_count: 1 },
            { key: "Rule A", doc_count: 2 },
            { key: "Rule B", doc_count: 1 },
          ],
        },
      },
    })).toEqual({
      count: 3,
      rule_names: ["Rule A", "Rule B"],
    });
  });

  it("rejects an inexact alert count", () => {
    expect(() => parseAttributableAlertSummary({
      hits: { total: { value: 10_000, relation: "gte" } },
      aggregations: { attributable_rule_names: { buckets: [] } },
    })).toThrow("exact numeric hit count");
  });
});
