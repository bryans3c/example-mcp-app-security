/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertSafeTargetId } from "../shared/validation.js";
import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { runProcess, type ProcessResult } from "./process.js";
import { runOnTarget } from "./target.js";

export async function cloneAndStartTartTarget(
  scope: AtomicPlan["scope"],
  ttlMinutes: number
): Promise<{ readonly clone: ProcessResult; readonly transport: "tart-exec" }> {
  if (scope.target_kind !== "tart" || scope.lifecycle !== "ephemeral") {
    throw new Error("Tart provisioning requires an ephemeral tart target");
  }
  if (!scope.target_image) throw new Error("Tart target_image is required");
  assertSafeTargetId(scope.target_id);
  if (await tartTargetExists(scope.target_id)) {
    throw new Error(`Refusing to overwrite existing Tart VM ${scope.target_id}`);
  }
  const localImage = parseLocalTartImageReference(scope.target_image);
  if (localImage) await verifyLocalTartImage(scope.target_image);
  const clone = await runProcess(
    "tart",
    localImage
      ? ["import", localImage.archivePath, scope.target_id]
      : ["clone", scope.target_image, scope.target_id],
    { timeoutMs: tartCloneTimeoutMs(ttlMinutes) }
  );
  if (clone.exitCode !== 0 || clone.timedOut) return { clone, transport: "tart-exec" };

  await startExistingTartTarget(scope);
  return { clone, transport: "tart-exec" };
}

export async function startExistingTartTarget(
  scope: AtomicPlan["scope"]
): Promise<{ readonly started: boolean; readonly transport: "tart-exec" }> {
  if (scope.target_kind !== "tart" || scope.lifecycle !== "ephemeral") {
    throw new Error("Tart startup requires an ephemeral tart target");
  }
  assertSafeTargetId(scope.target_id);
  if (!(await tartTargetExists(scope.target_id))) {
    throw new Error(`Tart VM ${scope.target_id} does not exist`);
  }
  const initialProbe = await runOnTarget(scope, ["true"], 20_000);
  if (initialProbe.exitCode === 0 && !initialProbe.timedOut) {
    return { started: false, transport: "tart-exec" };
  }
  const child = spawn("tart", tartRunArgs(scope), {
    detached: true,
    stdio: "ignore",
    shell: false,
  });
  child.unref();
  const deadline = Date.now() + 5 * 60_000;
  let lastError = "Tart guest agent is not ready";
  while (Date.now() < deadline) {
    try {
      const probe = await runOnTarget(scope, ["true"], 20_000);
      if (probe.exitCode === 0 && !probe.timedOut) {
        return { started: true, transport: "tart-exec" };
      }
      lastError = probe.stderr || `tart exec exit ${probe.exitCode}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  throw new Error(`Timed out waiting for Tart VM ${scope.target_id}: ${lastError}`);
}

export type LocalTartImage = {
  readonly archivePath: string;
  readonly sha256: string;
};

export type SealedTartImage = LocalTartImage & {
  readonly reference: string;
  readonly export: ProcessResult;
  readonly stop: ProcessResult;
};

export function localTartTemplateDirectory(): string {
  const cacheRoot =
    process.env.MACOS_ATOMIC_CACHE_DIR ?? path.join(process.cwd(), ".macos-atomic-cache");
  return path.resolve(
    process.env.MACOS_ATOMIC_TEMPLATE_DIR ?? path.join(cacheRoot, "prepared-tart-images")
  );
}

export function localTartImageReference(archivePath: string, sha256: string): string {
  if (!/^[0-9a-f]{64}$/i.test(sha256)) throw new Error("Local Tart image needs a SHA-256");
  const absolute = path.resolve(archivePath);
  assertInsideTemplateDirectory(absolute);
  return `tvm+${pathToFileURL(absolute).href}#sha256=${sha256.toLowerCase()}`;
}

export function parseLocalTartImageReference(reference: string): LocalTartImage | undefined {
  if (!reference.startsWith("tvm+file://")) return undefined;
  let url: URL;
  try {
    url = new URL(reference.slice(4));
  } catch {
    throw new Error("Invalid local Tart image URL");
  }
  if (url.protocol !== "file:" || url.hostname) {
    throw new Error("Local Tart images must use an absolute file URL");
  }
  const match = /^#sha256=([0-9a-f]{64})$/i.exec(url.hash);
  if (!match) throw new Error("Local Tart images need a SHA-256 fragment");
  url.hash = "";
  const archivePath = path.resolve(fileURLToPath(url));
  if (path.extname(archivePath) !== ".tvm") {
    throw new Error("Local Tart images must be compressed .tvm archives");
  }
  assertInsideTemplateDirectory(archivePath);
  return { archivePath, sha256: match[1].toLowerCase() };
}

export async function verifyLocalTartImage(reference: string): Promise<LocalTartImage> {
  const parsed = parseLocalTartImageReference(reference);
  if (!parsed) throw new Error("Expected a local Tart image reference");
  const stat = fs.lstatSync(parsed.archivePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error("Local Tart image must be a regular non-symlink file");
  }
  const actual = await sha256File(parsed.archivePath);
  if (actual !== parsed.sha256) {
    throw new Error(
      `Local Tart image SHA-256 mismatch: expected ${parsed.sha256}, got ${actual}`
    );
  }
  return parsed;
}

export function deleteLocalTartImageArchive(archivePath: string): void {
  const absolute = path.resolve(archivePath);
  assertInsideTemplateDirectory(absolute);
  if (!fs.existsSync(absolute)) return;
  const stat = fs.lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || path.extname(absolute) !== ".tvm") {
    throw new Error("Refusing to delete an invalid local Tart archive");
  }
  fs.rmSync(absolute);
}

export async function sealLocalTartTarget(
  scope: AtomicPlan["scope"],
  runId: string,
  ttlMinutes: number
): Promise<SealedTartImage> {
  const targetId = scope.target_id;
  assertSafeTargetId(targetId);
  if (!/^[a-z0-9][a-z0-9-]{2,80}$/.test(runId)) throw new Error("Invalid template run ID");
  const directory = localTartTemplateDirectory();
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const archivePath = path.join(directory, `${runId}.tvm`);
  assertInsideTemplateDirectory(archivePath);
  if (fs.existsSync(archivePath)) {
    throw new Error(`Refusing to overwrite prepared Tart image ${archivePath}`);
  }
  const partial = `${archivePath}.partial`;
  if (fs.existsSync(partial)) fs.rmSync(partial, { force: true });
  const stop = await stopTartTargetGracefully(scope);
  const exported = await runProcess("tart", ["export", targetId, partial], {
    timeoutMs: tartCloneTimeoutMs(ttlMinutes),
  });
  if (exported.exitCode !== 0 || exported.timedOut) {
    if (fs.existsSync(partial)) fs.rmSync(partial, { force: true });
    throw new Error(`Could not export Tart seed ${targetId}: ${exported.stderr}`);
  }
  fs.renameSync(partial, archivePath);
  const digest = await sha256File(archivePath);
  return {
    archivePath,
    sha256: digest,
    reference: localTartImageReference(archivePath, digest),
    export: exported,
    stop,
  };
}

export async function sha256File(filePath: string): Promise<string> {
  return await new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function assertInsideTemplateDirectory(candidate: string): void {
  const directory = localTartTemplateDirectory();
  const relative = path.relative(directory, path.resolve(candidate));
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    if (!relative) return;
    throw new Error(`Local Tart image must be inside ${directory}`);
  }
}

export function tartCloneTimeoutMs(ttlMinutes: number): number {
  if (!Number.isInteger(ttlMinutes) || ttlMinutes < 1) {
    throw new Error("Tart clone timeout requires a positive integer TTL");
  }
  return Math.min(ttlMinutes, 240) * 60_000;
}

export function tartRunArgs(scope: AtomicPlan["scope"]): string[] {
  return scope.target_profile === "desktop"
    ? ["run", scope.target_id]
    : ["run", "--no-graphics", scope.target_id];
}

export async function stopAndDeleteTartTarget(
  targetId: string
): Promise<{ readonly stopped: ProcessResult; readonly deleted: ProcessResult }> {
  assertSafeTargetId(targetId);
  const stopped = await runProcess("tart", ["stop", targetId], { timeoutMs: 60_000 });
  const deleted = await runProcess("tart", ["delete", targetId], { timeoutMs: 60_000 });
  return { stopped, deleted };
}

export async function coldBootTartTarget(
  scope: AtomicPlan["scope"]
): Promise<{ readonly stopped: ProcessResult; readonly started: boolean; readonly transport: "tart-exec" }> {
  if (scope.target_kind !== "tart" || scope.lifecycle !== "ephemeral") {
    throw new Error("Tart cold boot requires an ephemeral tart target");
  }
  assertSafeTargetId(scope.target_id);
  const stopped = await stopTartTargetGracefully(scope);
  const startup = await startExistingTartTarget(scope);
  return { stopped, ...startup };
}

export async function stopTartTargetGracefully(
  scope: AtomicPlan["scope"]
): Promise<ProcessResult> {
  if (scope.target_kind !== "tart" || scope.lifecycle !== "ephemeral") {
    throw new Error("Graceful Tart shutdown requires an ephemeral tart target");
  }
  assertSafeTargetId(scope.target_id);
  const sync = await runOnTarget(scope, ["sudo", "/bin/sync"], 30_000);
  if (sync.exitCode !== 0 || sync.timedOut) {
    throw new Error(`Could not sync Tart target ${scope.target_id}: ${sync.stderr}`);
  }
  await runOnTarget(scope, ["sudo", "/sbin/shutdown", "-h", "now"], 30_000);
  const deadline = Date.now() + 2 * 60_000;
  let poweredOff = false;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    const probe = await runOnTarget(scope, ["true"], 5_000);
    if (probe.exitCode !== 0 || probe.timedOut) {
      poweredOff = true;
      break;
    }
  }
  if (!poweredOff) {
    throw new Error(`Timed out waiting for graceful shutdown of Tart target ${scope.target_id}`);
  }
  const stopped = await runProcess("tart", ["stop", scope.target_id], { timeoutMs: 60_000 });
  const alreadyStopped = stopped.stderr.includes("is not running");
  if ((stopped.exitCode !== 0 && !alreadyStopped) || stopped.timedOut) {
    throw new Error(`Could not stop Tart target ${scope.target_id}: ${stopped.stderr}`);
  }
  return stopped;
}

export async function tartTargetExists(targetId: string): Promise<boolean> {
  assertSafeTargetId(targetId);
  const result = await runProcess("tart", ["list", "--format", "json"], {
    timeoutMs: 15_000,
  });
  if (result.exitCode !== 0 || result.timedOut) {
    throw new Error(`Could not inspect Tart VMs: ${result.stderr}`);
  }
  return tartListContains(result.stdout, targetId);
}

export function tartListContains(output: string, targetId: string): boolean {
  try {
    const parsed: unknown = JSON.parse(output);
    const rows = Array.isArray(parsed)
      ? parsed
      : parsed && typeof parsed === "object"
        ? Object.values(parsed as Record<string, unknown>).flat()
        : [];
    return rows.some(
      (row) =>
        row !== null &&
        typeof row === "object" &&
        String((row as Record<string, unknown>).Name ?? (row as Record<string, unknown>).name) ===
          targetId
    );
  } catch {
    return false;
  }
}
