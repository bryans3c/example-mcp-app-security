/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it, vi } from "vitest";
import type { AtomicPlan } from "./atomic-run-state.js";
import { successCriterionSchema } from "./atomic-schemas.js";
import {
  BEHAVIOR_PATH_CONTENT_CHECKER,
  BASH_INTERACTIVE_RUNNER,
  MACOS_ATOMIC_RUNNER_ENVIRONMENT,
  POWERSHELL_DIRECT_RUNNER,
  lastNonEmptyLine,
  parseAtomicExecutionExitCode,
  parseMacosFileMode,
  parseMacosBootEpochSeconds,
  parseTartRunning,
  verifyMacosReboot,
  verifyTartStopped,
} from "./atomic-exec.js";

describe("macOS Atomic runner compatibility", () => {
  it("keeps the usr-bin echo rewrite exact and digest-selected", () => {
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_usr_bin_echo_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1036_006_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1046_port_scan_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1027_001_dd_multiline_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1685_006_cat_dd_multiline_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1685_006_srm_multiline_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("#system log file deletion");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1685_006_realtime_log_clearance_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_REALTIME_LOG_CLEARED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1496_yes_bounded_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1497_003_local_ping_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("$command = 'set -e'");
    expect(BASH_INTERACTIVE_RUNNER).toContain(".Replace('ping -c', '/sbin/ping -c')");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1090_001_proxy_verify_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("networksetup -getsecurewebproxy");
    expect(BASH_INTERACTIVE_RUNNER).toContain("sudo networksetup -set");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1135_network_share_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_SHARE_DISCOVERY_COMPLETED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1078_003_sysadminctl_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("sysadminctl -");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1078_003_dsenableroot_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_ROOT_ENABLED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1564_001_xattr_scan_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_XATTR_SCAN_COMPLETED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("xattr -lrx /tmp/atomic-hidden-fixture");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1040_bpf_bounded_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("UDP:[1-9][0-9]*");
    expect(BASH_INTERACTIVE_RUNNER).toContain("$env:ATOMIC_ACTION -eq 'cleanup'");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1685_006_find_multiline_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("#using \"shred\" execution");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1048_ssh_push_local_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/tmp/atomic-ssh-remote/Users.tar.gz.enc");
    expect(BASH_INTERACTIVE_RUNNER).toContain('"-pass pass:$password"');
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1048_ssh_pull_local_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/tmp/atomic-ssh-local/etc.tar.gz");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1048_002_curl_local_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("http://127.0.0.1:8091/upload");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1074_001_discovery_local_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("http://127.0.0.1:8092/Discovery.sh");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1659_proxy_injection_local_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("http://atomic-origin.invalid:8093/");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1070_008_mailbox_fixture_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/tmp/atomic-mailbox/copy");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1222_002_chattr_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_IMMUTABLE_REMOVED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1059_004_cpan_shell_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/tmp/atomic-cpan-shell.sh");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1059_004_emacs_shell_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/tmp/atomic-emacs-shell-marker");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1531_password_change_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1546_018_python_hook_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1564_001_finder_hidden_verify_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1685_gatekeeper_verify_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1497_001_virtualization_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1070_006_birthtime_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1529_reboot_path_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("sleep 5; /sbin/reboot");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1529_shutdown_path_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/sbin/shutdown ");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1555_001_keychain_import_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_KEYCHAIN_CERT_IMPORTED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1553_004_root_ca_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_ROOT_CA_INSTALLED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1059_002_applescript_loopback_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("127.0.0.1:8094/login/process.php");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1021_005_ard_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_ARD_AGENT_RUNNING");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1490_timemachine_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_TIME_MACHINE_DISABLED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1555_003_safari_cookie_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_SAFARI_COOKIE_MATCHED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1113_screencapture_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_SCREEN_CAPTURED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1110_004_ssh_credential_stuffing_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_SSH_CREDENTIAL_STUFFING_SUCCEEDED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1098_004_authorized_keys_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_AUTHORIZED_KEYS_REWRITTEN");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1056_002_prompt_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_T1056_002_PROMPT_DISPLAYED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("pgrep -f 'osascript.*hidden answer'");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_T1056_002_PROMPT_DISPLAYED\n# Keep the reviewed prompt process alive briefly");
    expect(BASH_INTERACTIVE_RUNNER).not.toContain('pgrep -P "$shell_pid" osascript');
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1552_001_lazagne_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1539_cookie_debug_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_T1539_CHROME_COOKIE_EXTRACTED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1572_cloudflare_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_T1572_CLOUDFLARE_TUNNEL_CONNECTED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1685_vendor_fixture_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_manual_t1176_chromium_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_manual_t1176_firefox_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_manual_t1690_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("$badAtomicRoot = '$/opt/atomic-red-team/atomics'");
    expect(BASH_INTERACTIVE_RUNNER).toContain('"@$expectedTarget /usr/bin/true;done"');
    expect(BASH_INTERACTIVE_RUNNER).toContain("$command.Replace($loopEnd, ' && break;done')");
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_PASSWORD_CHANGED");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1059_004_local_pipe_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1059_004_awk_shell_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1548_003_sudo_vim_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1548_003_bsd_sed_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1485_dd_count_bytes_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1548_001_setuid_path_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1486_7z_password_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1059_004_ping_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain("macos_t1552_001_find_loop_compat");
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      ".Replace('/usr/bin/echo', '/bin/echo')"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      ".Replace('/usr/bin/echo -e ', 'echo -e ')"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "printf '%s\\n' placeholder > 'testdirwithspaceend /init '"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "macos_t1046_port_scan_compat is restricted to the pinned T1046 port-scan Atomic"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "printf '%s\\\\n' ATOMIC_T1046_SCAN_COMPLETED"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "macos_t1027_001_dd_multiline_compat is restricted to the pinned T1027.001 DD padding Atomic"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "$command = $command.Replace($needle, ' ;')"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "macos_t1685_006_cat_dd_multiline_compat is restricted to the pinned T1685.006 cat/dd Atomic"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain("ATOMIC_CPU_LOAD_COMPLETED");
    expect(BASH_INTERACTIVE_RUNNER).toContain(" 127.0.0.1 > /dev/null");
    expect(BASH_INTERACTIVE_RUNNER).toContain("http://127.0.0.1:8089/echo-art-fish.sh");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/tmp/atomic-awk-shell-marker");
    expect(BASH_INTERACTIVE_RUNNER).toContain("sudo vim -es -c 'q' /etc/sudoers");
    expect(BASH_INTERACTIVE_RUNNER).toContain("sudo sed -i '' ");
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "macos_t1485_dd_count_bytes_compat is restricted to the pinned T1485 DD Atomic"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      ".Replace(' iflag=count_bytes', ' bs=1')"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "macos_t1486_7z_password_compat is restricted to the pinned T1486 7z Atomic"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "macos_t1548_001_setuid_path_compat is restricted to the pinned T1548.001 compiled-binary Atomic"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "sudo mv /tmp/hello /usr/local/bin/atomic-hello"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "7z a -p$1 -mhe=on"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "macos_t1059_004_ping_compat is restricted to the pinned T1059.004 shell-script Atomic"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain("/sbin/ping -c 4");
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "macos_t1552_001_find_loop_compat is restricted to the pinned T1552.001 database-credential Atomic"
    );
    expect(BASH_INTERACTIVE_RUNNER).toContain(
      "Invoke-AtomicRedTeam flattens the multiline loop to do-semicolon"
    );
    expect(BASH_INTERACTIVE_RUNNER.indexOf('$expanded.Replace("#{$name}"'))
      .toBeLessThan(BASH_INTERACTIVE_RUNNER.indexOf("$expanded.Replace('PathToAtomicsFolder'"));
  });

  it("binds writable temporary-directory variables for headless PowerShell", () => {
    expect(MACOS_ATOMIC_RUNNER_ENVIRONMENT).toEqual([
      "TMPDIR=/private/tmp",
      "TMP=/private/tmp",
      "TEMP=/private/tmp",
      "tmpdir=/private/tmp",
      "tmp=/private/tmp",
      "temp=/private/tmp",
    ]);
  });

  it("validates path content written as UTF-8 or PowerShell UTF-16 text", () => {
    expect(BEHAVIOR_PATH_CONTENT_CHECKER).toContain('value.encode("utf-8")');
    expect(BEHAVIOR_PATH_CONTENT_CHECKER).toContain('value.encode("utf-16-le")');
    expect(BEHAVIOR_PATH_CONTENT_CHECKER).toContain('value.encode("utf-16-be")');
  });

  it("restricts direct PowerShell compatibility execution to the pinned EICAR test", () => {
    expect(POWERSHELL_DIRECT_RUNNER).toContain("b404caaa-12ce-43c7-9214-62a531c044f7");
    expect(POWERSHELL_DIRECT_RUNNER).toContain("macos_t1027_013_powershell_compat");
    expect(POWERSHELL_DIRECT_RUNNER).toContain("[scriptblock]::Create($command)");
    expect(POWERSHELL_DIRECT_RUNNER).toContain("$powershellCoreCompat");
    expect(POWERSHELL_DIRECT_RUNNER).toContain("[IO.File]::WriteAllText($outputPath, $intended");
  });

  it("uses the Atomic CSV exit code instead of the wrapper process exit code", () => {
    expect(parseAtomicExecutionExitCode(`output\n---ATOMIC-EXECUTION-LOG---\n"ExitCode"\n"0"`))
      .toBeUndefined();
    expect(parseAtomicExecutionExitCode(`output\n---ATOMIC-EXECUTION-LOG---\n"A","ExitCode"\n"test","0"`))
      .toBe(0);
    expect(parseAtomicExecutionExitCode(`output\n---ATOMIC-EXECUTION-LOG---\n"test","137"\n`))
      .toBe(137);
    expect(parseAtomicExecutionExitCode("output only")).toBeUndefined();
  });

  it("retains BSD stat set-ID bits when normalizing a macOS mode", () => {
    expect(parseMacosFileMode("102654\n")).toBe("2654");
    expect(parseMacosFileMode("104744\n")).toBe("4744");
    expect(parseMacosFileMode("100755\n")).toBe("755");
    expect(parseMacosFileMode("not-octal\n")).toBeUndefined();
  });

  it("reads the final stat value without transport whitespace", () => {
    expect(lastNonEmptyLine("banner\n 755 \n\n")).toBe("755");
    expect(lastNonEmptyLine("\r\n0\r\n")).toBe("0");
    expect(lastNonEmptyLine("\n\n")).toBe("");
  });

  it("accepts an exact non-negative target file size criterion", () => {
    expect(successCriterionSchema.parse({
      kind: "target_path_size_equals",
      path: "/tmp/padded-binary",
      bytes: 19,
    })).toEqual({
      kind: "target_path_size_equals",
      path: "/tmp/padded-binary",
      bytes: 19,
    });
    expect(successCriterionSchema.safeParse({
      kind: "target_path_size_equals",
      path: "/tmp/padded-binary",
      bytes: -1,
    }).success).toBe(false);
  });

  it("accepts exact owner/group and absent-xattr criteria", () => {
    expect(successCriterionSchema.parse({
      kind: "target_path_owner_equals",
      path: "/tmp/owned-file",
      owner: "root",
      group: "wheel",
    })).toMatchObject({ owner: "root", group: "wheel" });
    expect(successCriterionSchema.parse({
      kind: "target_path_xattr_absent",
      path: "/tmp/Atomic.app",
      name: "com.apple.quarantine",
    })).toMatchObject({ name: "com.apple.quarantine" });
  });
});

const scope = {
  target_kind: "tart",
  target_id: "art-macos",
  target_profile: "server",
  execution_user: "admin",
  capabilities: ["shell", "powershell"],
  platform: "macos",
  distro: "macos-15",
  architecture: "arm64",
  target_image: `ghcr.io/example/macos@sha256:${"a".repeat(64)}`,
  ssh_identity_file: "/tmp/id_ed25519",
  classification: "owned-disposable-lab",
  lifecycle: "ephemeral",
  network: "egress-only",
} satisfies AtomicPlan["scope"];

describe("macOS lifecycle verification", () => {
  it("parses kernel boot time and Tart running state", () => {
    expect(parseMacosBootEpochSeconds("{ sec = 1790000000, usec = 0 }"))
      .toBe(1790000000);
    expect(parseTartRunning('[{"Name":"art-macos","Running":false}]', "art-macos"))
      .toBe(false);
    expect(parseTartRunning('[{"Name":"art-macos","State":"running"}]', "art-macos"))
      .toBe(true);
  });

  it("confirms a reboot from kern.boottime after transient transport failure", async () => {
    const started = Date.parse("2026-11-11T10:00:00.000Z");
    const runOnTarget = vi.fn()
      .mockRejectedValueOnce(new Error("connection reset"))
      .mockResolvedValueOnce({
        exitCode: 0,
        timedOut: false,
        stdout: `{ sec = ${started / 1000 + 1}, usec = 0 }`,
        stderr: "",
      });
    let now = started + 10_000;
    const result = await verifyMacosReboot(scope, new Date(started).toISOString(), {
      runOnTarget,
      runProcess: vi.fn(),
      now: () => now,
      sleep: async () => { now += 1_000; },
      timeoutMs: 30_000,
      intervalMs: 1_000,
    });
    expect(result.ok).toBe(true);
    expect(runOnTarget).toHaveBeenCalledTimes(2);
  });

  it("confirms Tart reached the stopped state", async () => {
    let now = 0;
    const runProcess = vi.fn().mockResolvedValue({
      exitCode: 0,
      timedOut: false,
      stdout: '[{"Name":"art-macos","Running":false}]',
      stderr: "",
    });
    const result = await verifyTartStopped(scope, {
      runOnTarget: vi.fn(),
      runProcess,
      now: () => now,
      sleep: async () => { now += 1; },
      timeoutMs: 10,
      intervalMs: 1,
    });
    expect(result).toMatchObject({ ok: true, running: false });
  });
});
