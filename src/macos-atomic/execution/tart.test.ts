/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  deleteLocalTartImageArchive,
  localTartImageReference,
  parseLocalTartImageReference,
  sha256File,
  verifyLocalTartImage,
} from "./tart.js";

const originalTemplateDirectory = process.env.MACOS_ATOMIC_TEMPLATE_DIR;
const temporaryDirectories: string[] = [];

afterEach(() => {
  if (originalTemplateDirectory === undefined) {
    delete process.env.MACOS_ATOMIC_TEMPLATE_DIR;
  } else {
    process.env.MACOS_ATOMIC_TEMPLATE_DIR = originalTemplateDirectory;
  }
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe("local Tart image references", () => {
  it("round-trips and verifies a SHA-256-bound archive", async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-tart-"));
    temporaryDirectories.push(directory);
    process.env.MACOS_ATOMIC_TEMPLATE_DIR = directory;
    const archivePath = path.join(directory, "prepared image.tvm");
    fs.writeFileSync(archivePath, "prepared-image");
    const digest = await sha256File(archivePath);
    const reference = localTartImageReference(archivePath, digest);

    expect(parseLocalTartImageReference(reference)).toEqual({
      archivePath,
      sha256: digest,
    });
    await expect(verifyLocalTartImage(reference)).resolves.toEqual({
      archivePath,
      sha256: digest,
    });
  });

  it("rejects an archive outside the configured template directory", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-tart-"));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-outside-"));
    temporaryDirectories.push(directory, outside);
    process.env.MACOS_ATOMIC_TEMPLATE_DIR = directory;

    expect(() =>
      localTartImageReference(
        path.join(outside, "prepared.tvm"),
        "a".repeat(64)
      )
    ).toThrow(/inside/);
  });

  it("rejects a modified archive", async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-tart-"));
    temporaryDirectories.push(directory);
    process.env.MACOS_ATOMIC_TEMPLATE_DIR = directory;
    const archivePath = path.join(directory, "prepared.tvm");
    fs.writeFileSync(archivePath, "original");
    const digest = await sha256File(archivePath);
    const reference = localTartImageReference(archivePath, digest);
    fs.writeFileSync(archivePath, "modified");

    await expect(verifyLocalTartImage(reference)).rejects.toThrow(/mismatch/);
  });

  it("deletes only a regular archive inside the configured template directory", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-tart-"));
    temporaryDirectories.push(directory);
    process.env.MACOS_ATOMIC_TEMPLATE_DIR = directory;
    const archivePath = path.join(directory, "failed-validation.tvm");
    fs.writeFileSync(archivePath, "invalid-template");

    deleteLocalTartImageArchive(archivePath);

    expect(fs.existsSync(archivePath)).toBe(false);
  });
});
