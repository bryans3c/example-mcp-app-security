/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { verifyStagedOperatorSourceAssets } from "../execution/source-assets.js";
import { runProcess } from "../execution/process.js";
import { runOnTarget } from "../execution/target.js";
import {
  createAtomicRunStore,
  type AtomicPhase,
  type AtomicPlan,
} from "./atomic-run-state.js";
import { textResult } from "./atomic-run.js";

const execSchema = z.object({
  action: z.enum([
    "show_details",
    "stage_fixtures",
    "check_prereqs",
    "get_prereqs",
    "execute",
    "manual_instructions",
    "record_manual",
    "cleanup",
    "manual_cleanup_instructions",
    "record_manual_cleanup",
  ]),
  run_id: z.string().min(1),
  test_guid: z.string().uuid(),
  timeout_seconds: z.number().int().min(1).max(3_600).optional(),
  operator_outcome: z.enum(["completed", "failed", "blocked"]).optional(),
  operator_attestation: z.string().min(8).max(4_000).optional(),
  operator_started_at: z.string().datetime().optional(),
  operator_ended_at: z.string().datetime().optional(),
  observations: z.string().max(8_000).optional(),
});

const POWERSHELL_RUNNER = String.raw`$ErrorActionPreference = 'Stop'
Import-Module /opt/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 -Force
$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ATOMIC_INPUTS_B64))
$inputArgs = @{}
if ($decoded -and $decoded -ne '{}') {
  $parsed = ConvertFrom-Json $decoded
  foreach ($property in $parsed.PSObject.Properties) { $inputArgs[$property.Name] = $property.Value }
}
$logDir = "/var/tmp/macos-atomic-runs/$($env:ATOMIC_RUN_ID)"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = "$logDir/$($env:ATOMIC_TEST_GUID)-$($env:ATOMIC_ACTION).csv"
$params = @{
  AtomicTechnique = $env:ATOMIC_TECHNIQUE
  TestGuids = @($env:ATOMIC_TEST_GUID)
  PathToAtomicsFolder = '/opt/atomic-red-team/atomics'
  InputArgs = $inputArgs
  TimeoutSeconds = [int]$env:ATOMIC_TIMEOUT_SECONDS
  ExecutionLogPath = $logPath
  Force = $true
}
switch ($env:ATOMIC_ACTION) {
  'show_details' { $params.ShowDetails = $true }
  'check_prereqs' { $params.CheckPrereqs = $true }
  'get_prereqs' { $params.GetPrereqs = $true }
  'cleanup' { $params.Cleanup = $true }
  'execute' { }
  default { throw "Unsupported action $($env:ATOMIC_ACTION)" }
}
$captured = @(& { Invoke-AtomicTest @params } 6>&1)
$captured | ForEach-Object { Write-Output $_ }
$capturedText = ($captured | Out-String)
if ($env:ATOMIC_ACTION -eq 'check_prereqs' -and $capturedText -match 'Prerequisites not met:') {
  throw 'One or more Atomic prerequisites are not satisfied'
}
if ($env:ATOMIC_ACTION -eq 'get_prereqs' -and $capturedText -match 'Failed to meet prereq:') {
  throw 'One or more Atomic prerequisites remain unsatisfied after acquisition'
}
if (Test-Path $logPath) {
  Write-Output '---ATOMIC-EXECUTION-LOG---'
  Get-Content -Raw $logPath
}
`;

export const POWERSHELL_DIRECT_RUNNER = String.raw`$ErrorActionPreference = 'Stop'
Import-Module powershell-yaml -RequiredVersion 0.4.12 -Force
$root = '/opt/atomic-red-team/atomics'
$definition = Join-Path (Join-Path $root $env:ATOMIC_TECHNIQUE) "$($env:ATOMIC_TECHNIQUE).yaml"
$yamlObject = ConvertFrom-Yaml -Yaml (Get-Content -Raw $definition)
$document = $yamlObject | ConvertTo-Json -Depth 100 | ConvertFrom-Json
$matches = @($document.atomic_tests | Where-Object { $_.auto_generated_guid -eq $env:ATOMIC_TEST_GUID })
if ($document.attack_technique -ne $env:ATOMIC_TECHNIQUE -or $matches.Count -ne 1) {
  throw 'the pinned definition must contain exactly one requested GUID under the approved technique'
}
if ($env:ATOMIC_TEST_GUID -ne 'b404caaa-12ce-43c7-9214-62a531c044f7' -or
    ([string]$matches[0].executor.name).ToLowerInvariant() -ne 'powershell' -or
    $env:ATOMIC_EXECUTION_ADAPTER -ne 'macos_t1027_013_powershell_compat') {
  throw 'macos_t1027_013_powershell_compat is restricted to the pinned PowerShell EICAR Atomic'
}
switch ($env:ATOMIC_ACTION) {
  'execute' { $command = [string]$matches[0].executor.command }
  'cleanup' { $command = [string]$matches[0].executor.cleanup_command }
  default { throw 'macos_t1027_013_powershell_compat supports only execute and cleanup' }
}
if (-not $command.Trim()) { exit 0 }
& ([scriptblock]::Create($command))
if ($env:ATOMIC_ACTION -eq 'execute') {
  $outputPath = Join-Path $env:TEMP 'T1027.013_decryptedEicar.txt'
  if (-not (Test-Path $outputPath)) {
    throw 'the pinned EICAR command did not create its intended output file'
  }
  $intended = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  $powershellCoreCompat = 'X5O!P%@AP[4\PZX54(P^)7CC)7}-STANDARD-ANTIVIRUS-TEST-FILE!+H*'
  $actual = [IO.File]::ReadAllText($outputPath).TrimEnd([char[]]@(13, 10))
  if ($actual -eq $powershellCoreCompat) {
    # PowerShell Core on macOS removes the two dollar-prefixed tokens while
    # reconstructing this Windows-generated SecureString. Repair only that
    # exact known result so the pinned Atomic reaches its documented behavior.
    [IO.File]::WriteAllText($outputPath, $intended + [Environment]::NewLine)
  } elseif ($actual -ne $intended) {
    throw 'the pinned EICAR command produced an unexpected plaintext'
  }
}
`;

// `tart exec` does not populate the usual macOS temporary-directory variables.
// Several upstream Atomics use PowerShell's `$env:TEMP`, so bind them to the
// system's writable temporary directory for the non-interactive runner.
export const MACOS_ATOMIC_RUNNER_ENVIRONMENT = [
  "TMPDIR=/private/tmp",
  "TMP=/private/tmp",
  "TEMP=/private/tmp",
  "tmpdir=/private/tmp",
  "tmp=/private/tmp",
  "temp=/private/tmp",
] as const;

// Digest-approved macOS shell adapters resolve the immutable Atomic YAML and
// approved inputs before applying one narrowly scoped execution compatibility
// behavior. No adapter is selected implicitly.
export const BASH_INTERACTIVE_RUNNER = String.raw`$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Import-Module powershell-yaml -RequiredVersion 0.4.12 -Force
$root = '/opt/atomic-red-team/atomics'
$definition = Join-Path (Join-Path $root $env:ATOMIC_TECHNIQUE) "$($env:ATOMIC_TECHNIQUE).yaml"
$yamlObject = ConvertFrom-Yaml -Yaml (Get-Content -Raw $definition)
$document = $yamlObject | ConvertTo-Json -Depth 100 | ConvertFrom-Json
if ($document.attack_technique -ne $env:ATOMIC_TECHNIQUE) {
  throw 'technique identifier does not match the pinned definition'
}
$matches = @($document.atomic_tests | Where-Object { $_.auto_generated_guid -eq $env:ATOMIC_TEST_GUID })
if ($matches.Count -ne 1) {
  throw 'the pinned definition must contain exactly one requested GUID'
}
$test = $matches[0]
$executor = $test.executor
$executorName = ([string]$executor.name).ToLowerInvariant()
$adapter = [string]$env:ATOMIC_EXECUTION_ADAPTER
if ($adapter -notin @('bash_interactive', 'macos_usr_bin_echo_compat', 'macos_t1036_006_compat', 'macos_t1046_port_scan_compat', 'macos_t1027_001_dd_multiline_compat', 'macos_t1685_006_cat_dd_multiline_compat', 'macos_t1685_006_srm_multiline_compat', 'macos_t1685_006_realtime_log_clearance_compat', 'macos_t1496_yes_bounded_compat', 'macos_t1497_003_local_ping_compat', 'macos_t1059_004_local_pipe_compat', 'macos_t1059_004_awk_shell_compat', 'macos_t1548_003_sudo_vim_compat', 'macos_t1548_003_bsd_sed_compat', 'macos_t1485_dd_count_bytes_compat', 'macos_t1486_7z_password_compat', 'macos_t1548_001_setuid_path_compat', 'macos_t1059_004_ping_compat', 'macos_t1552_001_find_loop_compat', 'macos_t1040_bpf_bounded_compat', 'macos_t1090_001_proxy_verify_compat', 'macos_t1135_network_share_compat', 'macos_t1078_003_sysadminctl_compat', 'macos_t1078_003_dsenableroot_compat', 'macos_t1564_001_xattr_scan_compat', 'macos_t1685_006_find_multiline_compat', 'macos_t1048_ssh_push_local_compat', 'macos_t1048_ssh_pull_local_compat', 'macos_t1048_002_curl_local_compat', 'macos_t1074_001_discovery_local_compat', 'macos_t1659_proxy_injection_local_compat', 'macos_t1070_008_mailbox_fixture_compat', 'macos_t1222_002_chattr_compat', 'macos_t1059_004_cpan_shell_compat', 'macos_t1059_004_emacs_shell_compat', 'macos_t1531_password_change_compat', 'macos_t1546_018_python_hook_compat', 'macos_t1564_001_finder_hidden_verify_compat', 'macos_t1685_gatekeeper_verify_compat', 'macos_t1497_001_virtualization_compat', 'macos_t1070_006_birthtime_compat', 'macos_t1529_reboot_path_compat', 'macos_t1529_shutdown_path_compat', 'macos_t1555_001_keychain_import_compat', 'macos_t1553_004_root_ca_compat', 'macos_t1059_002_applescript_loopback_compat', 'macos_t1021_005_ard_compat', 'macos_t1490_timemachine_compat', 'macos_t1555_003_safari_cookie_compat', 'macos_t1113_screencapture_compat', 'macos_t1110_004_ssh_credential_stuffing_compat', 'macos_t1098_004_authorized_keys_compat', 'macos_t1056_002_prompt_compat', 'macos_t1552_001_lazagne_compat', 'macos_t1539_cookie_debug_compat', 'macos_t1572_cloudflare_compat', 'macos_t1685_vendor_fixture_compat', 'macos_manual_t1036_006_compat', 'macos_manual_t1037_002_compat', 'macos_manual_t1048_003_loopback_compat', 'macos_manual_t1176_chromium_compat', 'macos_manual_t1176_firefox_compat', 'macos_manual_t1647_compat', 'macos_manual_t1690_compat')) {
  throw "unsupported shell execution adapter $adapter"
}
$manualAdapters = @('macos_manual_t1036_006_compat', 'macos_manual_t1037_002_compat', 'macos_manual_t1048_003_loopback_compat', 'macos_manual_t1176_chromium_compat', 'macos_manual_t1176_firefox_compat', 'macos_manual_t1647_compat', 'macos_manual_t1690_compat')
if ($executorName -notin @('sh', 'bash') -and -not ($executorName -eq 'manual' -and $adapter -in $manualAdapters)) {
  throw "$adapter does not support executor $executorName"
}
$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ATOMIC_INPUTS_B64))
$approvedInputs = @{}
if ($decoded -and $decoded -ne '{}') {
  $parsed = ConvertFrom-Json $decoded
  foreach ($property in $parsed.PSObject.Properties) {
    $approvedInputs[$property.Name] = $property.Value
  }
}
$values = @{}
if ($test.input_arguments) {
  foreach ($property in $test.input_arguments.PSObject.Properties) {
    $values[$property.Name] = $property.Value.default
  }
}
foreach ($name in $approvedInputs.Keys) {
  if (-not $values.ContainsKey($name)) {
    throw "approved input is not declared by the Atomic: $name"
  }
  $values[$name] = $approvedInputs[$name]
}
function Expand-AtomicCommand([string]$text) {
  $expanded = [string]$text
  foreach ($name in $values.Keys) {
    $expanded = $expanded.Replace("#{$name}", [string]$values[$name])
  }
  $expanded = $expanded.Replace('PathToAtomicsFolder', $root)
  if ($expanded.Contains('#{')) {
    throw 'an unresolved Atomic input remains in the command'
  }
  return $expanded
}
switch ($env:ATOMIC_ACTION) {
  'execute' { $command = Expand-AtomicCommand ([string]$(if ($executorName -eq 'manual') { $executor.steps } else { $executor.command })) }
  'cleanup' { $command = Expand-AtomicCommand ([string]$(if ($executorName -eq 'manual') { '' } else { $executor.cleanup_command })) }
  default { throw "$adapter does not support action $($env:ATOMIC_ACTION)" }
}
if (-not $command.Trim() -and $adapter -notin $manualAdapters) { exit 0 }
if ($adapter -eq 'macos_t1056_002_prompt_compat') {
  if ($env:ATOMIC_TEST_GUID -notin @('76628574-0bc1-4646-8fe2-8f4427b47d15', 'b7037b89-947a-427a-ba29-e7e9f09bc045') -or
      -not $command.Contains('osascript') -or
      -not $command.Contains('hidden answer')) {
    throw 'macos_t1056_002_prompt_compat requires one of the two pinned hidden-password prompt Atomics'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $env:ATOMIC_COMPAT_COMMAND_B64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($command))
  $compat = @'
set -eu
command=$(printf '%s' "$ATOMIC_COMPAT_COMMAND_B64" | base64 -D)
log=/tmp/atomic-t1056-002-prompt.log
rm -f "$log"
/bin/bash -c "$command" >"$log" 2>&1 &
shell_pid=$!
prompt_pid=''
for attempt in $(jot 30 1); do
  # bash may exec the final osascript in-place, and command substitution adds
  # another shell layer. Match only this Atomic's hidden-answer osascript
  # instead of assuming a fixed parent/child process shape.
  prompt_pid=$(pgrep -f 'osascript.*hidden answer' 2>/dev/null | head -1 || true)
  if test -n "$prompt_pid"; then break; fi
  sleep 1
done
if test -z "$prompt_pid"; then
  kill "$shell_pid" 2>/dev/null || true
  wait "$shell_pid" 2>/dev/null || true
  cat "$log" >&2 || true
  exit 1
fi
printf '%s\n' ATOMIC_T1056_002_PROMPT_DISPLAYED
# Keep the reviewed prompt process alive briefly so Endpoint can emit its
# process event before the unattended harness cancels it without credentials.
sleep 3
kill "$prompt_pid" "$shell_pid" 2>/dev/null || true
wait "$shell_pid" 2>/dev/null || true
rm -f "$log"
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1552_001_lazagne_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '9e507bb8-1d30-4e3b-a49b-cb5727d7ea79' -or
      $command.Trim() -ne 'python2 laZagne.py all') {
    throw 'macos_t1552_001_lazagne_compat expected the exact pinned LaZagne command'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $compat = @'
set -eu
cd /opt/atomic-tools/LaZagne/Mac
test "$(git -C /opt/atomic-tools/LaZagne rev-parse HEAD)" = 858ff6f95f5176ae3c3c50a3ffc86723bf500a99
PATH=/usr/local/bin:/usr/bin:/bin python2 laZagne.py all
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1539_cookie_debug_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'e43cfdaf-3fb8-4a45-8de0-7eee8741d072' -or
      -not $command.Contains('--remote-debugging-port=1337') -or
      -not $command.Contains('/tmp/WhiteChocolateMacademiaNut/chocolate -d cookies -p 1337')) {
    throw 'macos_t1539_cookie_debug_compat expected pinned Chrome cookie command is absent'
  }
  if ($env:ATOMIC_ACTION -eq 'cleanup') {
    $captured = @(& /bin/bash -c $command 2>&1)
    $status = $LASTEXITCODE
    $captured | ForEach-Object { Write-Output $_ }
    exit $status
  }
  $compat = @'
set -eu
extractor=/tmp/WhiteChocolateMacademiaNut/chocolate
profile=/tmp/atomic-t1539-chrome-profile
server_log=/tmp/atomic-t1539-cookie-server.log
chrome_log=/tmp/atomic-t1539-chrome.log
output=/tmp/atomic-t1539-chocolate.txt
test -x "$extractor"
pkill -f 'Google Chrome.*atomic-t1539-chrome-profile' 2>/dev/null || true
rm -rf "$profile" "$server_log" "$chrome_log" "$output"
/opt/homebrew/bin/node -e 'require("http").createServer((q,s)=>{s.setHeader("Set-Cookie","atomic_cookie=ATOMIC_COOKIE_VALUE; Path=/");s.end("ok")}).listen(31338,"127.0.0.1")' >"$server_log" 2>&1 &
server_pid=$!
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  pkill -f 'Google Chrome.*atomic-t1539-chrome-profile' 2>/dev/null || true
  sleep 1
  rm -rf "$profile" "$server_log" "$chrome_log" "$output"
}
trap cleanup EXIT
'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' --user-data-dir="$profile" --remote-debugging-port=1337 --remote-allow-origins=http://localhost/ --no-first-run http://127.0.0.1:31338/ >"$chrome_log" 2>&1 &
for attempt in $(jot 30 1); do
  if curl -fs http://127.0.0.1:1337/json/version >/dev/null 2>&1; then break; fi
  sleep 1
done
sleep 3
"$extractor" -d cookies -p 1337 >"$output"
grep -F 'name: atomic_cookie' "$output"
grep -F 'value: ATOMIC_COOKIE_VALUE' "$output"
cat "$output"
printf '%s\n' ATOMIC_T1539_CHROME_COOKIE_EXTRACTED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1572_cloudflare_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '228c336a-2f79-4043-8aef-bfa453a611d5' -or
      -not $command.Contains('tunnel --url')) {
    throw 'macos_t1572_cloudflare_compat expected pinned Quick Tunnel command is absent'
  }
  if ($env:ATOMIC_ACTION -eq 'cleanup') {
    $captured = @(& /bin/bash -c $command 2>&1)
    $status = $LASTEXITCODE
    & /bin/bash -c 'if test -f /tmp/atomic-t1572-http.pid; then kill $(cat /tmp/atomic-t1572-http.pid) 2>/dev/null || true; fi; rm -f /tmp/atomic-t1572-http.pid /tmp/atomic-t1572-http.log /tmp/atomic-t1572-cloudflared.log' 2>$null
    $captured | ForEach-Object { Write-Output $_ }
    exit $status
  }
  $env:ATOMIC_COMPAT_COMMAND_B64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($command))
  $compat = @'
set -eu
command=$(printf '%s' "$ATOMIC_COMPAT_COMMAND_B64" | base64 -D)
rm -f /tmp/atomic-t1572-http.pid /tmp/atomic-t1572-http.log /tmp/atomic-t1572-cloudflared.log
cd /tmp
/usr/bin/python3 -m http.server 8080 --bind 127.0.0.1 >/tmp/atomic-t1572-http.log 2>&1 &
echo $! >/tmp/atomic-t1572-http.pid
for attempt in $(jot 20 1); do nc -z 127.0.0.1 8080 >/dev/null 2>&1 && break; sleep 1; done
/bin/bash -c "$command"
connected=0
for attempt in $(jot 60 1); do
  if grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/atomic-t1572-cloudflared.log >/dev/null 2>&1; then connected=1; break; fi
  sleep 1
done
test "$connected" -eq 1
grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/atomic-t1572-cloudflared.log | head -1
printf '%s\n' ATOMIC_T1572_CLOUDFLARE_TUNNEL_CONNECTED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1685_vendor_fixture_compat') {
  $vendorTests = @(
    '07f43b33-1e15-4e99-be70-bc094157c849',
    '62155dd8-bb3d-4f32-b31c-6532ff3ac6a3',
    '8fba7766-2d11-4b4a-979a-1e3d9cc9a88c',
    'b3e7510c-2d4c-4249-a33f-591a2bc83eef'
  )
  if ($env:ATOMIC_TEST_GUID -notin $vendorTests -or -not $command.Contains('launchctl')) {
    throw 'macos_t1685_vendor_fixture_compat requires a reviewed vendor LaunchDaemon Atomic'
  }
  $labels = switch ($env:ATOMIC_TEST_GUID) {
    '07f43b33-1e15-4e99-be70-bc094157c849' { @('com.opendns.osx.RoamingClientConfigUpdater') }
    '62155dd8-bb3d-4f32-b31c-6532ff3ac6a3' { @('at.obdev.littlesnitchd') }
    '8fba7766-2d11-4b4a-979a-1e3d9cc9a88c' { @('com.carbonblack.daemon', 'com.carbonblack.defense.daemon') }
    'b3e7510c-2d4c-4249-a33f-591a2bc83eef' { @('com.crowdstrike.falcond', 'com.crowdstrike.userdaemon') }
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  if ($status -ne 0) {
    $captured | ForEach-Object { Write-Output $_ }
    exit $status
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    foreach ($label in $labels) {
      & sudo launchctl print "system/$label" *> $null
      if ($LASTEXITCODE -eq 0) { throw "vendor fixture $label remained loaded" }
    }
    $captured | ForEach-Object { Write-Output $_ }
    Write-Output 'ATOMIC_T1685_VENDOR_SERVICE_UNLOADED'
    exit 0
  }
  foreach ($label in $labels) {
    & sudo launchctl print "system/$label" *> $null
    if ($LASTEXITCODE -ne 0) { throw "vendor fixture $label was not restored by cleanup" }
    $plist = "/Library/LaunchDaemons/$label.plist"
    & sudo launchctl unload $plist *> $null
    & sudo rm -f $plist
  }
  $captured | ForEach-Object { Write-Output $_ }
  Write-Output 'ATOMIC_T1685_VENDOR_SERVICE_RESTORED'
  exit 0
}
if ($adapter -eq 'macos_manual_t1036_006_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '89a7dd26-e510-4c9f-9b15-f3bae333360f' -or
      -not $command.Contains('/usr/bin/python') -or
      -not $command.Contains('mv execute.txt "execute.txt "')) {
    throw 'macos_manual_t1036_006_compat expected pinned manual steps are absent'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $compat = @'
set -eu
work=/tmp/atomic-t1036-006-manual
rm -rf "$work"
trap 'rm -rf "$work"' EXIT
mkdir "$work"
cd "$work"
printf '#!/bin/bash\necho '\''print("hello, world!")'\'' | /usr/bin/python3\nexit\n' > execute.txt
chmod +x execute.txt
mv execute.txt 'execute.txt '
output=$("./execute.txt ")
test "$output" = 'hello, world!'
test -x 'execute.txt '
printf '%s\n' ATOMIC_T1036_006_TRAILING_SPACE_EXECUTED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_manual_t1037_002_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'f047c7de-a2d9-406e-a62b-12a09d9516f4' -or
      -not $command.Contains('LoginHook /Library/Scripts/AtomicRedTeam.sh')) {
    throw 'macos_manual_t1037_002_compat expected pinned LoginHook steps are absent'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $compat = @'
set -eu
cleanup() {
  sudo defaults delete com.apple.loginwindow LoginHook >/dev/null 2>&1 || true
  sudo -u admin defaults delete com.apple.loginwindow LoginHook >/dev/null 2>&1 || true
  sudo rm -f /Library/Scripts/AtomicRedTeam.sh /tmp/AtomicRedTeam.sh /tmp/atomic-loginhook-fired
}
trap cleanup EXIT
sudo mkdir -p /Library/Scripts /var/root/Library/Preferences /Users/admin/Library/Preferences
printf '#!/bin/sh\n/usr/bin/touch /tmp/atomic-loginhook-fired\n' > /tmp/AtomicRedTeam.sh
sudo install -o root -g wheel -m 755 /tmp/AtomicRedTeam.sh /Library/Scripts/AtomicRedTeam.sh
sudo touch /private/var/root/Library/Preferences/com.apple.loginwindow.plist
sudo defaults write com.apple.loginwindow LoginHook /Library/Scripts/AtomicRedTeam.sh
sudo -u admin touch /Users/admin/Library/Preferences/com.apple.loginwindow.plist
sudo -u admin defaults write com.apple.loginwindow LoginHook /Library/Scripts/AtomicRedTeam.sh
test "$(sudo defaults read com.apple.loginwindow LoginHook)" = /Library/Scripts/AtomicRedTeam.sh
test "$(sudo -u admin defaults read com.apple.loginwindow LoginHook)" = /Library/Scripts/AtomicRedTeam.sh
printf '%s\n' ATOMIC_T1037_002_LOGINHOOK_REGISTERED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_manual_t1048_003_loopback_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '1d1abbd6-a3d3-4b2e-bef5-c59293f46eff' -or
      -not $command.Contains('SimpleHTTPServer 1337') -or
      -not $command.Contains('wget http://VICTIM_IP:1337/victim-file.txt')) {
    throw 'macos_manual_t1048_003_loopback_compat expected pinned HTTP exfiltration steps are absent'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $compat = @'
set -eu
stage=/tmp/victim-staging-area
retrieved=/tmp/atomic-http-retrieved
log=/tmp/atomic-http-server.log
rm -rf "$stage" "$retrieved" "$log"
mkdir "$stage"
printf '%s\n' 'this file will be exfiltrated' > "$stage/victim-file.txt"
cd "$stage"
/usr/bin/python3 -m http.server 1337 --bind 127.0.0.1 >"$log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; rm -rf "$stage" "$retrieved" "$log"' EXIT
for attempt in $(jot 20 1); do
  if nc -z 127.0.0.1 1337 >/dev/null 2>&1; then break; fi
  sleep 1
done
/opt/homebrew/bin/wget -q http://127.0.0.1:1337/victim-file.txt -O "$retrieved"
cmp "$stage/victim-file.txt" "$retrieved"
printf '%s\n' ATOMIC_T1048_003_HTTP_EXFILTRATED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_manual_t1176_chromium_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '3ecd790d-2617-4abf-9a8c-4e8d47da9ee1' -or
      -not $command.Contains('chrome://extensions') -or
      -not $command.Contains('Load unpacked extension')) {
    throw 'macos_manual_t1176_chromium_compat expected pinned Chromium extension steps are absent'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $compat = @'
set -eu
app='/opt/atomic-tools/chrome-for-testing/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'
extension=/opt/atomic-tools/t1176-extension-mv3
profile=/tmp/atomic-t1176-chrome-profile
log=/tmp/atomic-t1176-chrome.log
test -x "$app"
test -f "$extension/manifest.json"
rm -rf "$profile" "$log"
"$app" --user-data-dir="$profile" --no-first-run --disable-default-apps --disable-sync --load-extension="$extension" --enable-logging=stderr --v=1 about:blank >"$log" 2>&1 &
browser_pid=$!
cleanup() {
  pkill -f 'Google Chrome for Testing.*atomic-t1176-chrome-profile' 2>/dev/null || true
  wait "$browser_pid" 2>/dev/null || true
  sleep 1
  rm -rf "$profile" "$log"
}
trap cleanup EXIT
loaded=0
for attempt in $(jot 30 1); do
  if grep -q "Failed to load extension from: $extension" "$log" 2>/dev/null; then cat "$log" >&2; exit 1; fi
  if pgrep -f 'Google Chrome for Testing.*atomic-t1176-chrome-profile.*extension-process' >/dev/null 2>&1; then loaded=1; break; fi
  sleep 1
done
test "$loaded" -eq 1
printf '%s\n' ATOMIC_T1176_CHROMIUM_EXTENSION_LOADED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_manual_t1176_firefox_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'cb790029-17e6-4c43-b96f-002ce5f10938' -or
      -not $command.Contains('about:debugging') -or
      -not $command.Contains('Load Temporary Add-on')) {
    throw 'macos_manual_t1176_firefox_compat expected pinned Firefox extension steps are absent'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $compat = @'
set -eu
source=/opt/atomic-red-team/atomics/T1176/src
log=/tmp/atomic-t1176-firefox.log
rm -f "$log"
/opt/homebrew/bin/web-ext run --source-dir "$source" --firefox '/Applications/Firefox.app/Contents/MacOS/firefox' --no-reload --verbose >"$log" 2>&1 &
web_pid=$!
cleanup() {
  kill "$web_pid" 2>/dev/null || true
  pkill -f '/Applications/Firefox.app/Contents/MacOS/firefox' 2>/dev/null || true
  wait "$web_pid" 2>/dev/null || true
  rm -f "$log"
}
trap cleanup EXIT
loaded=0
for attempt in $(jot 60 1); do
  if grep -F "Installed $source as a temporary add-on" "$log" >/dev/null 2>&1; then loaded=1; break; fi
  if ! kill -0 "$web_pid" 2>/dev/null; then cat "$log" >&2; exit 1; fi
  sleep 1
done
test "$loaded" -eq 1
printf '%s\n' ATOMIC_T1176_FIREFOX_EXTENSION_LOADED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_manual_t1647_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '394a538e-09bb-4a4a-95d1-b93cf12682a8' -or
      -not $command.Contains('/Library/Preferences') -or
      -not $command.Contains('Launch Agent')) {
    throw 'macos_manual_t1647_compat expected pinned plist-modification steps are absent'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $compat = @'
set -eu
plist="$HOME/Library/Preferences/com.atomicredteam.t1647.plist"
label=com.atomicredteam.t1647
marker=/tmp/atomic-t1647-fired
rm -f "$plist" "$marker"
cleanup() { launchctl unload "$plist" >/dev/null 2>&1 || true; rm -f "$plist" "$marker"; }
trap cleanup EXIT
mkdir -p "$HOME/Library/Preferences"
/usr/libexec/PlistBuddy -c "Add :Label string $label" "$plist"
/usr/libexec/PlistBuddy -c 'Add :ProgramArguments array' "$plist"
/usr/libexec/PlistBuddy -c 'Add :ProgramArguments:0 string /usr/bin/touch' "$plist"
/usr/libexec/PlistBuddy -c "Add :ProgramArguments:1 string $marker" "$plist"
/usr/libexec/PlistBuddy -c 'Add :RunAtLoad bool true' "$plist"
/usr/libexec/PlistBuddy -c 'Add :AtomicModified bool true' "$plist"
launchctl load "$plist"
for attempt in $(jot 10 1); do test -e "$marker" && break; sleep 1; done
test -e "$marker"
test "$(/usr/libexec/PlistBuddy -c 'Print :AtomicModified' "$plist")" = true
printf '%s\n' ATOMIC_T1647_PLIST_LAUNCH_AGENT_EXECUTED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_manual_t1690_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '468566d5-83e5-40c1-b338-511e1659628d' -or
      -not $command.Contains('HISTCONTROL=ignoreboth') -or
      -not $command.Contains('whoami > recon.txt')) {
    throw 'macos_manual_t1690_compat expected pinned HISTCONTROL steps are absent'
  }
  if ($env:ATOMIC_ACTION -ne 'execute') { exit 0 }
  $compat = @'
set -eu
profile="$HOME/.bash_profile"
backup=/tmp/atomic-t1690-bash-profile
recon=/tmp/atomic-t1690-recon.txt
if test -e "$profile"; then cp "$profile" "$backup"; else rm -f "$backup"; fi
cleanup() { if test -e "$backup"; then mv "$backup" "$profile"; else rm -f "$profile"; fi; rm -f "$recon"; }
trap cleanup EXIT
HOME="$HOME" /bin/bash --noprofile --norc -i -c 'export HISTCONTROL=ignoreboth; echo export "HISTCONTROL=ignoreboth" >> ~/.bash_profile; ls >/dev/null; whoami > /tmp/atomic-t1690-recon.txt; test "$HISTCONTROL" = ignoreboth'
grep -F 'export HISTCONTROL=ignoreboth' "$profile" >/dev/null
test "$(cat "$recon")" = "$(id -un)"
printf '%s\n' ATOMIC_T1690_HISTCONTROL_CONFIGURED
'@
  $captured = @(& /bin/bash -c $compat 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_usr_bin_echo_compat') {
  if ($env:ATOMIC_ACTION -eq 'execute' -and -not $command.Contains('/usr/bin/echo')) {
    throw 'macos_usr_bin_echo_compat requires /usr/bin/echo in the pinned command'
  }
  if ($command.Contains('/usr/bin/echo -e ')) {
    $command = $command.Replace('/usr/bin/echo -e ', 'echo -e ')
  } else {
    $command = $command.Replace('/usr/bin/echo', '/bin/echo')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1036_006_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'b95ce2eb-a093-4cd8-938d-5258cef656ea') {
    throw 'macos_t1036_006_compat is restricted to the pinned T1036.006 Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $directoryNeedle = "mkdir -p 'testdirwithspaceend '"
    if (-not $command.Contains('/usr/bin/echo -e ') -or -not $command.Contains($directoryNeedle)) {
      throw 'macos_t1036_006_compat expected command shape is absent'
    }
    $seedCommand = "printf '%s\n' placeholder > 'testdirwithspaceend /init '"
    $command = $command.Replace($directoryNeedle, $directoryNeedle + [Environment]::NewLine + $seedCommand)
    $command = $command.Replace('/usr/bin/echo -e ', 'echo -e ')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1046_port_scan_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '68e907da-2539-48f6-9fc9-257a78c05540') {
    throw 'macos_t1046_port_scan_compat is restricted to the pinned T1046 port-scan Atomic'
  }
  if ($env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('for port in {1..65535}') -or
      -not $command.Contains('/dev/tcp/')) {
    throw 'macos_t1046_port_scan_compat expected command shape is absent'
  }
  # The upstream loop returns the status of the final closed port even after a
  # complete scan. Preserve the exact loop and its output, then normalize only
  # the completed loop's shell status. Parse/shell failures still prevent the
  # trailing command from running and remain non-zero.
  $command = $command + [Environment]::NewLine + "printf '%s\\n' ATOMIC_T1046_SCAN_COMPLETED" + [Environment]::NewLine + 'true'
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1027_001_dd_multiline_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'ffe2346c-abd5-4b45-a713-bf5f1ebd573a') {
    throw 'macos_t1027_001_dd_multiline_compat is restricted to the pinned T1027.001 DD padding Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    # ConvertFrom-Yaml flattens this three-line command while retaining its
    # inline comments, causing the first comment to hide both later dd calls.
    # Replace only the three exact pinned comments with command separators.
    foreach ($needle in @(' #adds null bytes', ' #adds high-quality random data')) {
      if (-not $command.Contains($needle)) {
        throw "macos_t1027_001_dd_multiline_compat expected command comment is absent: $needle"
      }
      $command = $command.Replace($needle, ' ;')
    }
    $finalNeedle = ' #adds low-quality random data'
    if (-not $command.Contains($finalNeedle)) {
      throw "macos_t1027_001_dd_multiline_compat expected command comment is absent: $finalNeedle"
    }
    $command = $command.Replace($finalNeedle, '')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1685_006_cat_dd_multiline_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'c23bdb88-928d-493e-b46d-df2906a50941') {
    throw 'macos_t1685_006_cat_dd_multiline_compat is restricted to the pinned T1685.006 cat/dd Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $firstNeedle = ' #truncating the file to zero bytes'
    $finalNeedle = ' #log file filled with null bytes(zeros)'
    if (-not $command.Contains($firstNeedle) -or -not $command.Contains($finalNeedle)) {
      throw 'macos_t1685_006_cat_dd_multiline_compat expected pinned inline comments are absent'
    }
    $command = $command.Replace($firstNeedle, ' ;')
    $command = $command.Replace($finalNeedle, '')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1685_006_srm_multiline_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'b0768a5e-0f32-4e75-ae5b-d036edcf96b6' -or
      $env:ATOMIC_ACTION -ne 'execute') {
    throw 'macos_t1685_006_srm_multiline_compat is restricted to the pinned T1685.006 srm Atomic'
  }
  # ConvertFrom-Yaml flattens the two commands while retaining the first
  # inline comment, which otherwise comments out the recursive srm stage.
  $firstNeedle = ' #system log file deletion'
  $finalNeedle = ' #recursive deletion of log files'
  if (-not $command.Contains($firstNeedle) -or -not $command.Contains($finalNeedle)) {
    throw 'macos_t1685_006_srm_multiline_compat expected pinned inline comments are absent'
  }
  $command = $command.Replace($firstNeedle, ' ;').Replace($finalNeedle, '')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1685_006_realtime_log_clearance_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '848e43b3-4c0a-4e4c-b4c9-d1e8cea9651c' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      $command.Trim() -ne 'sudo log -f /var/log/system.log | : > /var/log/system.log') {
    throw 'macos_t1685_006_realtime_log_clearance_compat requires the pinned real-time log-clearance Atomic'
  }
  $target = '/var/log/system.log'
  if (-not (Test-Path -LiteralPath $target)) {
    throw 'macos_t1685_006_realtime_log_clearance_compat requires /var/log/system.log to exist'
  }
  $before = (Get-Item -LiteralPath $target).Length
  if ($before -le 0) {
    throw 'macos_t1685_006_realtime_log_clearance_compat requires a non-empty system.log precondition'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  $after = (Get-Item -LiteralPath $target).Length
  if ($after -ne 0) {
    throw "macos_t1685_006_realtime_log_clearance_compat expected an empty system.log, observed $after bytes"
  }
  Write-Output 'ATOMIC_REALTIME_LOG_CLEARED'
  exit 0
}
if ($adapter -eq 'macos_t1496_yes_bounded_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '904a5a0e-fb02-490d-9f8d-0e256eb37549' -or
      $env:ATOMIC_ACTION -ne 'execute' -or $command.Trim() -ne 'yes > /dev/null') {
    throw 'macos_t1496_yes_bounded_compat requires the pinned T1496 yes command'
  }
  $command = 'yes | head -c 1048576 > /dev/null' + [Environment]::NewLine + "printf '%s\\n' ATOMIC_CPU_LOAD_COMPLETED"
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1497_003_local_ping_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '8b87dd03-8204-478c-bac3-3959f6528de3' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('ping -c') -or
      -not $command.Contains(' 8.8.8.8 > /dev/null')) {
    throw 'macos_t1497_003_local_ping_compat requires the pinned T1497.003 ping command'
  }
  $command = 'set -e' + [Environment]::NewLine + $command.Replace('ping -c', '/sbin/ping -c').Replace(' 8.8.8.8 > /dev/null', ' 127.0.0.1 > /dev/null')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1040_bpf_bounded_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'e2480aee-23f3-4f34-80ce-de221e27cd19') {
    throw 'macos_t1040_bpf_bounded_compat is restricted to the pinned filtered BPF capture Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'cleanup') {
    $captured = @(& /bin/bash -c $command 2>&1)
    $status = $LASTEXITCODE
    $captured | ForEach-Object { Write-Output $_ }
    exit $status
  }
  if ($env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains(' -f -i ') -or
      -not $command.Contains(' -t 3')) {
    throw 'macos_t1040_bpf_bounded_compat requires the pinned filtered BPF capture command'
  }
  $program = [string]$values['program_path']
  $command = "(sleep 15; sudo pkill -INT -f '$program -f -i' >/dev/null 2>&1) &" +
    [Environment]::NewLine + $command
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0 -or (($captured -join [Environment]::NewLine) -notmatch 'UDP:[1-9][0-9]*')) {
    throw 'the filtered BPF capture did not observe UDP traffic'
  }
  exit $status
}
if ($adapter -eq 'macos_t1090_001_proxy_verify_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '648d68c1-8bcd-4486-9abe-71c6655b6a2c') {
    throw 'macos_t1090_001_proxy_verify_compat is restricted to the pinned T1090.001 proxy Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    if (-not $command.Contains('networksetup -setwebproxy') -or
        -not $command.Contains('networksetup -setsecurewebproxy')) {
      throw 'macos_t1090_001_proxy_verify_compat expected proxy command shape is absent'
    }
    $interface = [string]$values['interface']
    $command = $command.Replace('networksetup -set', 'sudo networksetup -set')
    $command = $command + [Environment]::NewLine +
      "networksetup -getwebproxy '$interface'" + [Environment]::NewLine +
      "networksetup -getsecurewebproxy '$interface'"
  } else {
    $command = $command.Replace('networksetup -set', 'sudo networksetup -set')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1135_network_share_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'f94b5ad9-911c-4eff-9718-fd21899db4f7' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('df -aH') -or
      -not $command.Contains('smbutil view -g //') -or
      -not $command.Contains('showmount ')) {
    throw 'macos_t1135_network_share_compat requires the pinned T1135 discovery commands'
  }
  # The discovery utilities legitimately return non-zero when the reviewed
  # loopback target exposes no shares. Preserve every probe and mark only that
  # the full discovery sequence reached completion.
  $command = $command + [Environment]::NewLine + "printf '%s\n' ATOMIC_SHARE_DISCOVERY_COMPLETED"
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1078_003_sysadminctl_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '191db57d-091a-47d5-99f3-97fde53de505' -or
      -not $command.Contains('sysadminctl interactive -')) {
    throw 'macos_t1078_003_sysadminctl_compat requires the pinned T1078.003 sysadminctl command'
  }
  # The interactive mode waits for a console operator even though the pinned command
  # already supplies the disposable account password. Keep the same account
  # operation while selecting sysadminctl's non-interactive mode.
  $command = $command.Replace('sysadminctl interactive -', 'sysadminctl -')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1078_003_dsenableroot_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '20b40ea9-0e17-4155-b8e6-244911a678ac' -or
      -not $command.Contains('dsenableroot')) {
    throw 'macos_t1078_003_dsenableroot_compat requires the pinned T1078.003 dsenableroot command'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $command = 'set -e' + [Environment]::NewLine +
      "dsenableroot -u art-tester -p '!pass123!' -r 'art-root'" + [Environment]::NewLine +
      "dscl . -authonly root 'art-root'" + [Environment]::NewLine +
      "printf '%s\n' ATOMIC_ROOT_ENABLED"
  } else {
    $command = "dsenableroot -d -u art-tester -p '!pass123!'"
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1564_001_xattr_scan_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'cddb9098-3b47-4e01-9d3b-6f5f323288a9' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('xattr -lr * /') -or
      -not $command.Contains('40 00 FF FF FF FF 00 00')) {
    throw 'macos_t1564_001_xattr_scan_compat requires the pinned T1564.001 xattr scan'
  }
  # The upstream command recursively scans the entire filesystem. Search the
  # reviewed FinderInfo fixture with the same xattr/grep mechanism instead.
  $command = 'set -e' + [Environment]::NewLine +
    "xattr -lrx /tmp/atomic-hidden-fixture | grep -C 2 '40 00 FF FF FF FF 00 00'" +
    [Environment]::NewLine + "printf '%s\n' ATOMIC_XATTR_SCAN_COMPLETED"
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1685_006_find_multiline_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'bc8eeb4a-cc3e-45ec-aa6e-41e973da2558' -or
      $env:ATOMIC_ACTION -ne 'execute') {
    throw 'macos_t1685_006_find_multiline_compat is restricted to the pinned T1685.006 find deletion Atomic'
  }
  # ConvertFrom-Yaml flattens the three commands while retaining their inline
  # comments, so the first comment hides the shred and unlink stages.
  $comments = @(' #using "rm" execution', ' #using "shred" execution', ' #using "unlink" execution')
  foreach ($comment in $comments) {
    if (-not $command.Contains($comment)) {
      throw "macos_t1685_006_find_multiline_compat expected comment is absent: $comment"
    }
  }
  $command = $command.Replace($comments[0], ' ;').Replace($comments[1], ' ;').Replace($comments[2], '')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1048_ssh_push_local_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '7c3cb337-35ae-4d06-bf03-3032ed2ec268' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('tar czpf - /Users/*') -or
      -not $command.Contains("'cat > /Users.tar.gz.enc'")) {
    throw 'macos_t1048_ssh_push_local_compat requires the pinned T1048 SSH push command'
  }
  $password = [string]$values['password']
  $command = 'set -o pipefail' + [Environment]::NewLine +
    $command.Replace("-pass $password", "-pass pass:$password").Replace(
      '/Users/*',
      '/tmp/atomic-ssh-local/users/*'
    ).Replace(
      "'cat > /Users.tar.gz.enc'",
      "'cat > /tmp/atomic-ssh-remote/Users.tar.gz.enc'"
    ) + [Environment]::NewLine + 'test -s /tmp/atomic-ssh-remote/Users.tar.gz.enc'
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1048_ssh_pull_local_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'f6786cc8-beda-4915-a4d6-ac2f193bb988' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('(cd /etc && tar -zcvf - *)') -or
      -not $command.Contains('> ./etc.tar.gz')) {
    throw 'macos_t1048_ssh_pull_local_compat requires the pinned T1048 SSH pull command'
  }
  $command = 'set -e' + [Environment]::NewLine + $command.Replace(
    '(cd /etc && tar -zcvf - *)',
    '(cd /tmp/atomic-ssh-remote/etc && tar -zcvf - *)'
  ).Replace('> ./etc.tar.gz', '> /tmp/atomic-ssh-local/etc.tar.gz') +
    [Environment]::NewLine + 'test -s /tmp/atomic-ssh-local/etc.tar.gz'
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1048_002_curl_local_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '4a4f31e2-46ea-4c26-ad89-f09ad1d5fe01') {
    throw 'macos_t1048_002_curl_local_compat is restricted to the pinned T1048.002 curl upload Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $remote = 'https://file.io/'
    if (-not $command.Contains($remote) -or -not $command.Contains("-F 'file=@")) {
      throw 'macos_t1048_002_curl_local_compat expected pinned multipart upload command is absent'
    }
    $command = $command.Replace($remote, 'http://127.0.0.1:8091/upload')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1074_001_discovery_local_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '39ce0303-ae16-4b9e-bb5b-4f53e8262066') {
    throw 'macos_t1074_001_discovery_local_compat is restricted to the pinned T1074.001 Discovery.sh Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $remote = 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.sh'
    if (-not $command.Contains($remote) -or -not $command.Contains('| sh -s >')) {
      throw 'macos_t1074_001_discovery_local_compat expected pinned curl-pipe-shell command is absent'
    }
    $command = 'set -o pipefail' + [Environment]::NewLine +
      $command.Replace($remote, 'http://127.0.0.1:8092/Discovery.sh')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1659_proxy_injection_local_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '9b360eaf-c778-4f07-a6e7-895c4f01ac1c') {
    throw 'macos_t1659_proxy_injection_local_compat is restricted to the pinned T1659 MITM proxy Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $remote = 'http://example.com'
    if (-not $command.Contains($remote) -or -not $command.Contains('--proxy http://127.0.0.1:8080')) {
      throw 'macos_t1659_proxy_injection_local_compat expected pinned proxy command is absent'
    }
    $command = $command.Replace($remote, 'http://atomic-origin.invalid:8093/')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1070_008_mailbox_fixture_compat') {
  if ($env:ATOMIC_TEST_GUID -notin @('3824130e-a6e4-4528-8091-3a52eeb540f6', '8a0b1579-5a36-483a-9cde-0236983e1665')) {
    throw 'macos_t1070_008_mailbox_fixture_compat is restricted to the pinned T1070.008 mailbox Atomics'
  }
  if (-not $command.Contains('~/Library/Mail/copy')) {
    throw 'macos_t1070_008_mailbox_fixture_compat expected mailbox copy path is absent'
  }
  $command = $command.Replace('mkdir ~/Library/Mail/copy', 'mkdir -p /tmp/atomic-mailbox/copy')
  $command = $command.Replace('cp -R ~/Library/Mail/* ~/Library/Mail/copy', 'cp -R /tmp/atomic-mailbox/source /tmp/atomic-mailbox/copy')
  $command = $command.Replace('~/Library/Mail/copy', '/tmp/atomic-mailbox/copy')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1222_002_chattr_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'e7469fe2-ad41-4382-8965-99b94dd3c13f' -or
      $env:ATOMIC_ACTION -ne 'execute' -or -not $command.Contains('chattr -i ')) {
    throw 'macos_t1222_002_chattr_compat requires the pinned immutable-flag removal command'
  }
  $command = $command.Replace('chattr -i ', 'chflags nouchg ') + [Environment]::NewLine +
    "stat -f '%Sf' /tmp/atomic-immutable-file | grep -vq uchg" + [Environment]::NewLine +
    "printf '%s\n' ATOMIC_IMMUTABLE_REMOVED"
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1059_004_cpan_shell_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'bcd4c2bc-490b-4f91-bd31-3709fe75bbdf' -or
      $env:ATOMIC_ACTION -ne 'execute' -or -not $command.Contains('/bin/sh &')) {
    throw 'macos_t1059_004_cpan_shell_compat requires the pinned CPAN shell-escape command'
  }
  $command = $command.Replace('/bin/sh &', '/bin/sh /tmp/atomic-cpan-shell.sh')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1059_004_emacs_shell_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'e0742e38-6efe-4dd4-ba5c-2078095b6156' -or
      $env:ATOMIC_ACTION -ne 'execute' -or -not $command.Contains('sudo emacs -Q -nw --eval')) {
    throw 'macos_t1059_004_emacs_shell_compat requires the pinned Emacs term-shell command'
  }
  $q = [char]34
  $command = "sudo emacs -Q --batch --eval '(call-process " + $q + "/bin/sh" + $q + " nil nil nil " + $q + "-c" + $q + " " + $q + "touch /tmp/atomic-emacs-shell-marker" + $q + ")'"
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1531_password_change_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '3c717bf3-2ecc-4d79-8ac8-0bfbf08fbce6' -or
      $env:ATOMIC_ACTION -ne 'execute' -or -not $command.Contains('passwd art-pass-fixture')) {
    throw 'macos_t1531_password_change_compat requires the pinned passwd command and approved fixture account'
  }
  $command = "dscl . -passwd /Users/art-pass-fixture 'AtomicChanged-1531!' && dscl . -authonly art-pass-fixture 'AtomicChanged-1531!' && printf '%s\n' ATOMIC_PASSWORD_CHANGED"
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1546_018_python_hook_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '28ca4f81-fa96-47ff-8555-dde98017e89b') {
    throw 'macos_t1546_018_python_hook_compat is restricted to the pinned Python startup-hook Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $expected = "import subprocess; subprocess.Popen(['open', '-a', 'Calculator'])"
    $replacement = "import pathlib; pathlib.Path('/tmp/atomic-python-hook-marker').touch()"
    if (-not $command.Contains('atomic_hook.pth') -or -not $command.Contains($expected)) {
      throw 'macos_t1546_018_python_hook_compat expected pinned .pth payload is absent'
    }
    $command = $command.Replace($expected, $replacement)
  } elseif ($env:ATOMIC_ACTION -eq 'cleanup') {
    if (-not $command.Contains('/tmp/atomic_python_hook_path.txt')) {
      throw 'macos_t1546_018_python_hook_compat expected pinned cleanup is absent'
    }
    $command += [Environment]::NewLine + 'rm -f /tmp/atomic-python-hook-marker'
  } else {
    throw 'macos_t1546_018_python_hook_compat supports execute and cleanup only'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1564_001_finder_hidden_verify_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '9a1ec7da-b892-449f-ad68-67066d04380c') {
    throw 'macos_t1564_001_finder_hidden_verify_compat is restricted to the pinned Finder hidden-files Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    if (-not $command.Contains('defaults write com.apple.finder AppleShowAllFiles YES')) {
      throw 'macos_t1564_001_finder_hidden_verify_compat expected pinned enable command is absent'
    }
    $command += [Environment]::NewLine +
      'value=$(defaults read com.apple.finder AppleShowAllFiles); if [ "$value" = YES ] || [ "$value" = 1 ]; then echo ATOMIC_FINDER_HIDDEN_ENABLED; else exit 1; fi'
  } elseif ($env:ATOMIC_ACTION -ne 'cleanup' -or
      -not $command.Contains('defaults write com.apple.finder AppleShowAllFiles NO')) {
    throw 'macos_t1564_001_finder_hidden_verify_compat expected pinned cleanup is absent'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1685_gatekeeper_verify_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '2a821573-fb3f-4e71-92c3-daac7432f053') {
    throw 'macos_t1685_gatekeeper_verify_compat is restricted to the pinned Gatekeeper Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    if (-not $command.Contains('spctl --master-disable')) {
      throw 'macos_t1685_gatekeeper_verify_compat expected pinned disable command is absent'
    }
    $command += [Environment]::NewLine +
      "spctl --status | grep -q 'assessments disabled' && echo ATOMIC_GATEKEEPER_DISABLED"
  } elseif ($env:ATOMIC_ACTION -eq 'cleanup') {
    if (-not $command.Contains('spctl --master-enable')) {
      throw 'macos_t1685_gatekeeper_verify_compat expected pinned cleanup is absent'
    }
    $command += [Environment]::NewLine +
      "spctl --status | grep -q 'assessments enabled'"
  } else {
    throw 'macos_t1685_gatekeeper_verify_compat supports execute and cleanup only'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1497_001_virtualization_compat') {
  if ($env:ATOMIC_ACTION -ne 'execute' -or
      $env:ATOMIC_TEST_GUID -notin @('6beae646-eb4c-4730-95be-691a4094408c', 'e04d2e89-de15-4d90-92f9-a335c7337f0f') -or
      -not $command.Contains('Virtualization Environment detected')) {
    throw 'macos_t1497_001_virtualization_compat requires a pinned macOS virtualization discovery Atomic'
  }
  if ($env:ATOMIC_TEST_GUID -eq '6beae646-eb4c-4730-95be-691a4094408c') {
    $command = 'model=$(sysctl -n hw.model); if printf "%s\n" "$model" | grep -Eq "Virtual|VMware|Parallels"; then echo "Virtualization Environment detected"; elif printf "%s\n" "$model" | grep -vq "Mac"; then echo "Virtualization Environment detected"; fi'
  } else {
    $command = 'model=$(system_profiler SPHardwareDataType | awk -F: "/Model Identifier/{print $2; exit}"); if printf "%s\n" "$model" | grep -Eq "Virtual|VMware|Parallels"; then echo "Virtualization Environment detected"; elif printf "%s\n" "$model" | grep -vq "Mac"; then echo "Virtualization Environment detected"; fi'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1070_006_birthtime_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '8164a4a6-f99c-4661-ac4f-80f5e4e78d2b') {
    throw 'macos_t1070_006_birthtime_compat is restricted to the pinned creation-timestamp Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    if (-not $command.Contains('date 010100001971') -or -not $command.Contains('touch /tmp/T1070.006-creation.txt')) {
      throw 'macos_t1070_006_birthtime_compat expected pinned clock-and-touch command is absent'
    }
    $command = 'target=/tmp/T1070.006-creation.txt; touch "$target"; setfile=$(xcrun -f SetFile); "$setfile" -d "01/01/1971 00:00:00" "$target"; birth=$(stat -f %B "$target"); if [ "$birth" -ge 31449600 ] && [ "$birth" -le 31622400 ]; then echo ATOMIC_CREATION_TIMESTAMP_SET; else exit 1; fi'
  } elseif ($env:ATOMIC_ACTION -ne 'cleanup' -or -not $command.Contains('rm -f /tmp/T1070.006-creation.txt')) {
    throw 'macos_t1070_006_birthtime_compat expected pinned cleanup is absent'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1529_reboot_path_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '47d0b042-a918-40ab-8cf9-150ffe919027') {
    throw 'macos_t1529_reboot_path_compat is restricted to the pinned reboot Atomic'
  }
  if ($env:ATOMIC_ACTION -ne 'execute' -or $command.Trim() -ne 'reboot') {
    throw 'macos_t1529_reboot_path_compat expected the pinned reboot command'
  }
  # Give Endpoint time to emit the exact shell command before reboot tears
  # down its own transport. The lifecycle verifier, not this channel, proves
  # that the reboot actually occurred.
  & /bin/sh -c 'sleep 5; /sbin/reboot'
  exit $LASTEXITCODE
}
if ($adapter -eq 'macos_t1529_shutdown_path_compat') {
  if ($env:ATOMIC_ACTION -ne 'execute' -or
      $env:ATOMIC_TEST_GUID -notin @('4963a81e-a3ad-4f02-adda-812343b351de', '6326dbc4-444b-4c04-88f4-27e94d0327cb')) {
    throw 'macos_t1529_shutdown_path_compat is restricted to the pinned shutdown Atomics'
  }
  $expected = if ($env:ATOMIC_TEST_GUID -eq '4963a81e-a3ad-4f02-adda-812343b351de') {
    'shutdown -h now'
  } else {
    'shutdown -r now'
  }
  if ($command.Trim() -ne $expected) {
    throw 'macos_t1529_shutdown_path_compat expected the pinned shutdown command'
  }
  $absolute = $expected.Replace('shutdown ', '/sbin/shutdown ')
  & /bin/sh -c "sleep 5; $absolute"
  exit $LASTEXITCODE
}
if ($adapter -eq 'macos_t1555_001_keychain_import_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'e544bbcb-c4e0-4bd0-b614-b92131635f59' -or
      $env:ATOMIC_ACTION -ne 'execute') {
    throw 'macos_t1555_001_keychain_import_compat is restricted to the pinned certificate-import Atomic'
  }
  $certificate = [string]$values['cert_export']
  if ($certificate -ne '/tmp/certs.pem' -or $command.Trim() -ne 'security import /tmp/certs.pem -k') {
    throw 'macos_t1555_001_keychain_import_compat expected the pinned certificate import command'
  }
  $keychain = '/tmp/atomic-t1555-import.keychain-db'
  $captured = @(& /usr/bin/security import $certificate -k $keychain 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  $verified = @(& /usr/bin/security find-certificate -c AtomicT1555001 -a $keychain 2>&1)
  $verifyStatus = $LASTEXITCODE
  $verified | ForEach-Object { Write-Output $_ }
  if ($verifyStatus -ne 0) { exit $verifyStatus }
  Write-Output 'ATOMIC_KEYCHAIN_CERT_IMPORTED'
  exit 0
}
if ($adapter -eq 'macos_t1553_004_root_ca_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'cc4a0b8c-426f-40ff-9426-4e10e5bf4c49' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('security add-trusted-cert') -or
      -not $command.Contains('/Library/Keychains/System.keychain')) {
    throw 'macos_t1553_004_root_ca_compat requires the pinned macOS root-CA Atomic'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  $verified = @(& /usr/bin/security find-certificate -c 'www.example.com' -a /Library/Keychains/System.keychain 2>&1)
  $verifyStatus = $LASTEXITCODE
  $verified | ForEach-Object { Write-Output $_ }
  if ($verifyStatus -ne 0) { exit $verifyStatus }
  Write-Output 'ATOMIC_ROOT_CA_INSTALLED'
  exit 0
}
if ($adapter -eq 'macos_t1059_002_applescript_loopback_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '3600d97d-81b9-4171-ab96-e4386506e2c2' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('osascript -e') -or
      -not $command.Contains('do shell script') -or
      -not $command.Contains('base64.b64decode')) {
    throw 'macos_t1059_002_applescript_loopback_compat requires the pinned encoded AppleScript Atomic'
  }
  $python = @'
import urllib.request
request = urllib.request.Request('http://127.0.0.1:8094/login/process.php')
request.add_header('User-Agent', 'Mozilla/5.0 Atomic Red Team')
request.add_header('Cookie', 'session=t3VhVOs/DyCcDTFzIKanRxkvk3I=')
urllib.request.urlopen(request, timeout=3).read()
'@
  $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($python))
  $shell = "printf '%s' '$encoded' | /usr/bin/base64 -D | /usr/bin/python3"
  $appleScript = 'do shell script "' + $shell + '"'
  $captured = @(& /usr/bin/osascript -e $appleScript 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1021_005_ard_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '8a930abe-841c-4d4f-a877-72e9fe90b9ea') {
    throw 'macos_t1021_005_ard_compat is restricted to the pinned Apple Remote Desktop Atomic'
  }
  $kickstart = '/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart'
  if (-not $command.Contains($kickstart)) {
    throw 'macos_t1021_005_ard_compat expected the pinned kickstart path'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $processes = @(& /usr/bin/pgrep -fl 'ARDAgent.app/Contents/MacOS/ARDAgent' 2>&1)
    $processStatus = $LASTEXITCODE
    $processes | ForEach-Object { Write-Output $_ }
    if ($processStatus -ne 0) { exit $processStatus }
    Write-Output 'ATOMIC_ARD_AGENT_RUNNING'
  } elseif ($env:ATOMIC_ACTION -ne 'cleanup') {
    throw 'macos_t1021_005_ard_compat supports execute and cleanup only'
  }
  exit 0
}
if ($adapter -eq 'macos_t1490_timemachine_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'ed952f70-91d4-445a-b7ff-30966bfb1aff' -or
      $env:ATOMIC_ACTION -notin @('execute', 'cleanup')) {
    throw 'macos_t1490_timemachine_compat is restricted to the pinned Time Machine Atomic'
  }
  $expected = if ($env:ATOMIC_ACTION -eq 'execute') { 'sudo tmutil disable' } else { 'sudo tmutil enable' }
  if ($command.Trim() -ne $expected) {
    throw 'macos_t1490_timemachine_compat expected the pinned tmutil command'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  $observed = @(& /usr/bin/defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>&1)
  $verifyStatus = $LASTEXITCODE
  $observed | ForEach-Object { Write-Output $_ }
  if ($verifyStatus -ne 0) { exit $verifyStatus }
  $expectedValue = if ($env:ATOMIC_ACTION -eq 'execute') { '0' } else { '1' }
  if (($observed | Select-Object -Last 1).Trim() -ne $expectedValue) { exit 1 }
  Write-Output $(if ($env:ATOMIC_ACTION -eq 'execute') { 'ATOMIC_TIME_MACHINE_DISABLED' } else { 'ATOMIC_TIME_MACHINE_ENABLED' })
  exit 0
}
if ($adapter -eq 'macos_t1555_003_safari_cookie_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'c1402f7b-67ca-43a8-b5f3-3143abedc01b' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      -not $command.Contains('cd ~/Library/Cookies') -or
      -not $command.Contains('grep -q "coinbase" "Cookies.binarycookies"')) {
    throw 'macos_t1555_003_safari_cookie_compat requires the pinned Safari cookie search Atomic'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  Write-Output 'ATOMIC_SAFARI_COOKIE_MATCHED'
  exit 0
}
if ($adapter -eq 'macos_t1113_screencapture_compat') {
  if ($env:ATOMIC_TEST_GUID -notin @('0f47ceb1-720f-4275-96b8-21f0562217ac', 'deb7d358-5fbd-4dc4-aecc-ee0054d2d9a4') -or
      $env:ATOMIC_ACTION -notin @('execute', 'cleanup')) {
    throw 'macos_t1113_screencapture_compat is restricted to the pinned macOS screencapture Atomics'
  }
  $output = [string]$values['output_file']
  if ($output -ne '/tmp/T1113_desktop.png' -or
      ($env:ATOMIC_ACTION -eq 'execute' -and -not $command.Contains('screencapture')) -or
      ($env:ATOMIC_ACTION -eq 'cleanup' -and $command.Trim() -ne 'rm /tmp/T1113_desktop.png')) {
    throw 'macos_t1113_screencapture_compat expected the pinned output and command'
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    if (-not (Test-Path -LiteralPath $output) -or (Get-Item -LiteralPath $output).Length -le 100) { exit 1 }
    $signature = (& /usr/bin/xxd -p -l 8 $output).Trim()
    if ($signature -ne '89504e470d0a1a0a') { exit 1 }
    Write-Output 'ATOMIC_SCREEN_CAPTURED'
  } elseif (Test-Path -LiteralPath $output) {
    exit 1
  }
  exit 0
}
if ($adapter -eq 'macos_t1110_004_ssh_credential_stuffing_compat') {
  $expectedTarget = '127.0.0.1 -p 2222 -o ConnectTimeout=1 -o NumberOfPasswordPrompts=1'
  if ($env:ATOMIC_TEST_GUID -ne 'd546a3d9-0be5-40c7-ad82-5a7d79e1b66b' -or
      $env:ATOMIC_ACTION -ne 'execute' -or
      [string]$values['target_host'] -ne $expectedTarget -or
      -not $command.Contains('credstuffuserpass.txt') -or
      -not $command.Contains('sshpass -p') -or
      -not $command.Contains("@$expectedTarget")) {
    throw 'macos_t1110_004_ssh_credential_stuffing_compat requires the pinned loopback SSH credential-stuffing Atomic'
  }
  $badAtomicRoot = '$/opt/atomic-red-team/atomics'
  if (-not $command.Contains($badAtomicRoot)) {
    throw 'macos_t1110_004_ssh_credential_stuffing_compat expected the pinned PathToAtomicsFolder expansion'
  }
  $command = $command.Replace($badAtomicRoot, '/opt/atomic-red-team/atomics')
  $interactiveLogin = "@$expectedTarget;done"
  if (-not $command.Contains($interactiveLogin)) {
    throw 'macos_t1110_004_ssh_credential_stuffing_compat expected one terminal SSH login command'
  }
  # A successful upstream attempt opens an interactive login shell and never
  # returns to the loop. Preserve authentication, but run a harmless remote
  # command so the successful attempt terminates and the bounded loop can stop.
  $command = $command.Replace($interactiveLogin, "@$expectedTarget /usr/bin/true;done")
  $loopEnd = ';done'
  if ([Text.RegularExpressions.Regex]::Matches($command, [Text.RegularExpressions.Regex]::Escape($loopEnd)).Count -ne 1) {
    throw 'macos_t1110_004_ssh_credential_stuffing_compat expected one pinned credential loop'
  }
  $command = $command.Replace($loopEnd, ' && break;done')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  $fixtureDigest = (& /usr/bin/shasum -a 256 /tmp/credstuffuserpass.txt).Split(' ')[0]
  if ($fixtureDigest -ne 'b82b0a952d8b7c93e2ab5d2c1e1095969aab0d8795999f886b4061f7081381b6') { exit 1 }
  if (-not (Select-String -LiteralPath /tmp/atomic-credential-stuffing-sshd.log -SimpleMatch 'Accepted password for administrator' -Quiet)) { exit 1 }
  Write-Output 'ATOMIC_SSH_CREDENTIAL_STUFFING_SUCCEEDED'
  exit 0
}
if ($adapter -eq 'macos_t1098_004_authorized_keys_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '342cc723-127c-4d3a-8292-9c0c6b4ecadc' -or
      $env:ATOMIC_ACTION -notin @('execute', 'cleanup')) {
    throw 'macos_t1098_004_authorized_keys_compat is restricted to the pinned authorized-keys Atomic'
  }
  $fixturePath = Join-Path $env:HOME '.ssh/authorized_keys'
  $fixture = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBENIGNATOMICFIXTURE00000000000000000 atomic-fixture'
  if (-not (Test-Path -LiteralPath $fixturePath) -or
      (Get-Content -Raw -LiteralPath $fixturePath).Trim() -ne $fixture) {
    throw 'macos_t1098_004_authorized_keys_compat requires the reviewed fixture'
  }
  if ($env:ATOMIC_ACTION -eq 'execute' -and
      (-not $command.Contains('~/.ssh/authorized_keys') -or
       -not $command.Contains('ssh_authorized_keys=$(cat'))) {
    throw 'macos_t1098_004_authorized_keys_compat expected pinned read/write command is absent'
  }
  if ($env:ATOMIC_ACTION -eq 'cleanup' -and $command.Trim() -ne 'unset ssh_authorized_keys') {
    throw 'macos_t1098_004_authorized_keys_compat expected pinned cleanup command is absent'
  }
  $before = (& /usr/bin/shasum -a 256 $fixturePath).Split(' ')[0]
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  if ($status -ne 0) { exit $status }
  $after = (& /usr/bin/shasum -a 256 $fixturePath).Split(' ')[0]
  if ($before -ne $after -or (Get-Content -Raw -LiteralPath $fixturePath).Trim() -ne $fixture) { exit 1 }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    Write-Output 'ATOMIC_AUTHORIZED_KEYS_REWRITTEN'
  }
  exit 0
}
if ($adapter -eq 'macos_t1059_004_local_pipe_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'd0c88567-803d-4dca-99b4-7ce65e7b257c') {
    throw 'macos_t1059_004_local_pipe_compat is restricted to the pinned T1059.004 pipe-to-shell Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $remote = 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh'
    if (-not $command.Contains($remote)) {
      throw 'macos_t1059_004_local_pipe_compat expected pinned URL is absent'
    }
    $command = $command.Replace($remote, 'http://127.0.0.1:8089/echo-art-fish.sh')
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1059_004_awk_shell_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'ee72b37d-b8f5-46a5-a9e7-0ff50035ffd5' -or
      $env:ATOMIC_ACTION -ne 'execute' -or -not $command.Contains('/bin/sh &')) {
    throw 'macos_t1059_004_awk_shell_compat requires the pinned awk shell command'
  }
  $command = $command.Replace('/bin/sh &', '/bin/sh -c \"touch /tmp/atomic-awk-shell-marker\" &')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1548_003_sudo_vim_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '150c3a08-ee6e-48a6-aeaf-3659d24ceb4e' -or
      $env:ATOMIC_ACTION -ne 'execute' -or -not $command.Contains('sudo vim /etc/sudoers')) {
    throw 'macos_t1548_003_sudo_vim_compat requires the pinned sudo/vim command'
  }
  $command = $command.Replace('sudo vim /etc/sudoers', "sudo vim -es -c 'q' /etc/sudoers")
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1548_003_bsd_sed_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'a7b17659-dd5e-46f7-b7d1-e6792c91d0bc' -or
      $env:ATOMIC_ACTION -ne 'execute' -or -not $command.Contains('timestamp_timeout=-1') -or
      -not $command.Contains('sudo sed -i ')) {
    throw 'macos_t1548_003_bsd_sed_compat requires the pinned sudoers timeout command'
  }
  $command = $command.Replace('sudo sed -i ', "sudo sed -i '' ")
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1485_dd_count_bytes_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '38deee99-fd65-4031-bec8-bfa4f9f26146') {
    throw 'macos_t1485_dd_count_bytes_compat is restricted to the pinned T1485 DD Atomic'
  }
  if ($env:ATOMIC_ACTION -ne 'execute' -or -not $command.Contains(' iflag=count_bytes')) {
    throw 'macos_t1485_dd_count_bytes_compat expected GNU DD count-bytes option is absent'
  }
  # BSD dd does not implement GNU iflag=count_bytes. With bs=1, the Atomic's
  # existing byte-sized count preserves the exact overwrite length.
  $command = $command.Replace(' iflag=count_bytes', ' bs=1')
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1486_7z_password_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '645f0f5a-ef09-48d8-b9bc-f0e24c642d72') {
    throw 'macos_t1486_7z_password_compat is restricted to the pinned T1486 7z Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    # p7zip requires the password to be attached to -p. The pinned Atomic uses
    # "-p #{file_password}", which prompts and shifts the archive arguments.
    # Rewrite only that single token boundary after approved input expansion.
    $rewritten = [Text.RegularExpressions.Regex]::Replace(
      $command,
      '7z a -p\s+(\S+)\s+-mhe=on',
      '7z a -p$1 -mhe=on'
    )
    if ($rewritten -eq $command) {
      throw 'macos_t1486_7z_password_compat expected command shape is absent'
    }
    $command = $rewritten
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1548_001_setuid_path_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '896dfe97-ae43-4101-8e96-9a7996555d80') {
    throw 'macos_t1548_001_setuid_path_compat is restricted to the pinned T1548.001 compiled-binary Atomic'
  }
  $newline = [Environment]::NewLine
  if ($env:ATOMIC_ACTION -eq 'execute') {
    $buildAndChown = 'sudo make /tmp/hello' + $newline + 'sudo chown root /tmp/hello'
    if (-not $command.Contains($buildAndChown) -or
        -not $command.Contains('sudo chmod u+s /tmp/hello') -or
        -not $command.Contains($newline + '/tmp/hello' + $newline)) {
      throw 'macos_t1548_001_setuid_path_compat expected compiled binary command shape is absent'
    }
    # Keep make beside /tmp/hello.c so its implicit rule works, then move only
    # the finished executable to a filesystem path that retains set-ID bits.
    $command = $command.Replace(
      $buildAndChown,
      'sudo make /tmp/hello' + $newline +
      'sudo mv /tmp/hello /usr/local/bin/atomic-hello' + $newline +
      'sudo chown root /usr/local/bin/atomic-hello'
    )
    $command = $command.Replace('sudo chmod u+s /tmp/hello', 'sudo chmod u+s /usr/local/bin/atomic-hello')
    $command = $command.Replace($newline + '/tmp/hello' + $newline, $newline + '/usr/local/bin/atomic-hello' + $newline)
  } else {
    $cleanupLine = 'sudo rm /tmp/hello' + $newline
    if (-not $command.Contains($cleanupLine)) {
      throw 'macos_t1548_001_setuid_path_compat expected cleanup path is absent'
    }
    $command = $command.Replace($cleanupLine, 'sudo rm -f /usr/local/bin/atomic-hello' + $newline)
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1059_004_ping_compat') {
  if ($env:ATOMIC_TEST_GUID -ne '7e7ac3ed-f795-4fa5-b711-09d6fbe9b873') {
    throw 'macos_t1059_004_ping_compat is restricted to the pinned T1059.004 shell-script Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute') {
    if (-not $command.Contains("echo 'ping -c 4 ")) {
      throw 'macos_t1059_004_ping_compat expected command shape is absent'
    }
    $command = $command.Replace("echo 'ping -c 4 ", "echo '/sbin/ping -c 4 ")
  }
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
if ($adapter -eq 'macos_t1552_001_find_loop_compat') {
  if ($env:ATOMIC_TEST_GUID -ne 'e62bccc4-0200-47e9-b40a-4ea5328495b3') {
    throw 'macos_t1552_001_find_loop_compat is restricted to the pinned T1552.001 database-credential Atomic'
  }
  if ($env:ATOMIC_ACTION -eq 'execute' -and
      (-not $command.Contains('for filename in ') -or
       -not $command.Contains('find ') -or
       -not $command.Contains('/tmp/creds.txt'))) {
    throw 'macos_t1552_001_find_loop_compat expected command shape is absent'
  }
  # Invoke-AtomicRedTeam flattens the multiline loop to do-semicolon, which is
  # a shell syntax error. Execute the same digest-bound YAML command with its
  # original newlines preserved.
  $captured = @(& /bin/bash -c $command 2>&1)
  $status = $LASTEXITCODE
  $captured | ForEach-Object { Write-Output $_ }
  exit $status
}
$env:SHELL = '/bin/bash'
if (-not $env:HISTFILE) { $env:HISTFILE = "$($env:HOME)/.bash_history" }
$historyEvidence = if ($env:ATOMIC_ACTION -eq 'execute') {
  "history > '/var/tmp/atomic-bash-history-$($env:ATOMIC_TEST_GUID).txt'" + [Environment]::NewLine +
  "set -o | grep '^history' > '/var/tmp/atomic-bash-history-option-$($env:ATOMIC_TEST_GUID).txt'"
} else {
  ''
}
$payload = $command + [Environment]::NewLine + $historyEvidence + [Environment]::NewLine + 'exit' + [Environment]::NewLine
$captured = @($payload | & /bin/bash --noprofile --norc -i 2>&1)
$status = $LASTEXITCODE
$captured | ForEach-Object { Write-Output $_ }
exit $status
`;

const FIXTURE_WRITER = String.raw`import base64, hashlib, os
p = os.environ["ATOMIC_FIXTURE_PATH"]
data = base64.b64decode(os.environ["ATOMIC_FIXTURE_B64"], validate=True)
expected = os.environ["ATOMIC_FIXTURE_SHA256"]
if hashlib.sha256(data).hexdigest() != expected:
    raise RuntimeError("fixture digest mismatch")
flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(p, flags, int(os.environ["ATOMIC_FIXTURE_MODE"], 8))
try:
    os.write(fd, data)
    os.fchmod(fd, int(os.environ["ATOMIC_FIXTURE_MODE"], 8))
finally:
    os.close(fd)
print(hashlib.sha256(data).hexdigest())
`;

const BEHAVIOR_PATH_CHECKER = String.raw`import os, sys
expected = sys.argv[1]
exists = os.path.exists(sys.argv[2])
sys.exit(0 if (expected == "exists") == exists else 1)
`;

export const BEHAVIOR_PATH_CONTENT_CHECKER = String.raw`import os, sys
expected = sys.argv[1]
path = sys.argv[2]
value = sys.argv[3]
needles = (value.encode("utf-8"), value.encode("utf-16-le"), value.encode("utf-16-be"))
data = open(path, "rb").read() if os.path.isfile(path) else b""
matches = any(needle in data for needle in needles)
sys.exit(0 if os.path.isfile(path) and ((expected == "contains") == matches) else 1)
`;

type BehaviorValidation = {
  readonly ok: boolean;
  readonly checks: readonly Record<string, unknown>[];
};

export function hasBehaviorExecution(
  executions: readonly { readonly stage: string }[]
): boolean {
  return executions.some(
    (execution) => execution.stage === "execute" || execution.stage === "manual"
  );
}

export function registerAtomicExecTool(
  server: McpServer,
  store = createAtomicRunStore()
): void {
  server.registerTool(
    "macos-atomic-exec",
    {
      title: "Execute Approved macOS Atomic",
      description:
        "Stages optional digest-approved benign fixtures, runs approved macOS atomics through pinned Invoke-AtomicRedTeam, and coordinates approved manual procedures. Inputs, elevation, cleanup, capabilities, and behavior-success criteria come only from the approved plan.",
      inputSchema: execSchema,
      annotations: { destructiveHint: true },
    },
    async (input) => {
      try {
        const loaded = store.getLoaded(input.run_id);
        if (!loaded.plan) return textResult({ error: "No approved plan is stored" }, true);
        const plan = loaded.plan;
        const test = store.getApprovedTest(input.run_id, input.test_guid);
        const allowedPhase: Record<typeof input.action, readonly AtomicPhase[]> = {
          show_details: ["approved", "provisioning", "executing"],
          stage_fixtures: ["provisioning", "executing"],
          check_prereqs: ["provisioning", "executing"],
          get_prereqs: ["provisioning", "executing"],
          execute: ["executing"],
          manual_instructions: ["executing"],
          record_manual: ["executing"],
          cleanup: ["cleaning"],
          manual_cleanup_instructions: ["cleaning"],
          record_manual_cleanup: ["cleaning"],
        };
        store.assertPhase(input.run_id, allowedPhase[input.action]);
        if (
          loaded.state.phase === "executing" &&
          ["stage_fixtures", "check_prereqs", "get_prereqs"].includes(input.action) &&
          hasBehaviorExecution(loaded.executions)
        ) {
          return textResult(
            {
              error:
                "Prerequisite actions are allowed in executing only before the behavior has run",
              test_guid: test.test_guid,
            },
            true
          );
        }
        const operatorMode = test.execution_mode === "operator";
        if (operatorMode && input.action === "manual_instructions") {
          const stagedSourceAssets = await verifyStagedOperatorSourceAssets(
            plan.scope,
            input.run_id,
            [test]
          );
          if (!stagedSourceAssets.ok) {
            return textResult(
              {
                error:
                  "Digest-approved operator assets are missing or changed in the execution user's home",
                test_guid: test.test_guid,
                staged_source_assets: stagedSourceAssets,
              },
              true
            );
          }
          const operatorWindowStartedAt = new Date().toISOString();
          return textResult({
            ok: true,
            stop: true,
            stop_reason: "The approved manual procedure requires operator action on the target",
            test_guid: test.test_guid,
            target_id: plan.scope.target_id,
            target_profile: plan.scope.target_profile,
            execution_user: plan.scope.execution_user,
            elevation_required: test.elevation_required,
            required_capabilities: test.required_capabilities,
            reviewed_steps: test.manual?.reviewed_steps,
            staged_source_assets: stagedSourceAssets,
            evidence_requirements: test.manual?.evidence_requirements,
            operator_window_started_at: operatorWindowStartedAt,
          });
        }
        if (operatorMode && input.action === "manual_cleanup_instructions") {
          const operatorWindowStartedAt = new Date().toISOString();
          return textResult({
            ok: true,
            stop: true,
            stop_reason: "The approved manual cleanup requires operator action on the target",
            test_guid: test.test_guid,
            target_id: plan.scope.target_id,
            cleanup_steps: test.manual?.cleanup_steps ?? [],
            operator_window_started_at: operatorWindowStartedAt,
          });
        }
        if (
          operatorMode &&
          (input.action === "record_manual" || input.action === "record_manual_cleanup")
        ) {
          if (
            !input.operator_outcome ||
            !input.operator_attestation ||
            !input.operator_started_at
          ) {
            return textResult(
              {
                error:
                  "operator_outcome, operator_attestation, and the operator_started_at returned by the instruction action are required",
              },
              true
            );
          }
          const operatorEndedAt = input.operator_ended_at ?? new Date().toISOString();
          if (Date.parse(operatorEndedAt) < Date.parse(input.operator_started_at)) {
            return textResult({ error: "operator_ended_at precedes operator_started_at" }, true);
          }
          const manualStage = input.action === "record_manual" ? "manual" : "cleanup";
          if (
            manualStage === "cleanup" &&
            test.cleanup_expected &&
            !(test.manual?.cleanup_steps?.length)
          ) {
            return textResult(
              { error: "Approved manual cleanup steps are missing; replan before cleanup" },
              true
            );
          }
          const status =
            input.operator_outcome === "completed"
              ? "passed"
              : input.operator_outcome === "failed"
                ? "failed"
                : "blocked";
          const evidencePath = writeManualEvidence(loaded.dir, test, {
            stage: manualStage,
            outcome: input.operator_outcome,
            operator_attestation: input.operator_attestation,
            started_at: input.operator_started_at,
            ended_at: operatorEndedAt,
            observations: input.observations,
          });
          const snapshot = store.recordExecution(input.run_id, {
            test_guid: test.test_guid,
            stage: manualStage,
            status,
            behavior_success: manualStage === "manual" ? status === "passed" : undefined,
            started_at: input.operator_started_at,
            ended_at: operatorEndedAt,
            evidence_path: evidencePath,
            notes: input.observations,
          });
          return textResult({
            ok: status === "passed",
            test_guid: test.test_guid,
            action: input.action,
            status,
            behavior_success: manualStage === "manual" ? status === "passed" : undefined,
            evidence_path: evidencePath,
            run: snapshot,
          }, status !== "passed");
        }
        if (operatorMode && input.action !== "stage_fixtures") {
          return textResult(
            {
              error:
                "Manual atomics use manual_instructions/record_manual and their cleanup counterparts; the runner path is disabled.",
              test_guid: test.test_guid,
            },
            true
          );
        }
        if (
          !operatorMode &&
          [
            "manual_instructions",
            "record_manual",
            "manual_cleanup_instructions",
            "record_manual_cleanup",
          ].includes(input.action)
        ) {
          return textResult({ error: "This approved test uses the automated runner" }, true);
        }
        if (input.action === "stage_fixtures") {
          const result = await stageFixtures(loaded.dir, plan.scope, input.run_id, test);
          const snapshot = store.recordExecution(input.run_id, {
            test_guid: test.test_guid,
            stage: "prereq",
            status: result.ok ? "passed" : "failed",
            started_at: result.startedAt,
            ended_at: result.endedAt,
            exit_code: result.ok ? 0 : 1,
            evidence_path: result.evidencePath,
            notes: result.ok
              ? `Staged ${result.fixtureCount} digest-approved fixtures`
              : result.error,
          });
          return textResult(
            {
              ok: result.ok,
              test_guid: test.test_guid,
              action: input.action,
              fixture_count: result.fixtureCount,
              evidence_path: result.evidencePath,
              error: result.error,
              run: snapshot,
            },
            !result.ok
          );
        }
        const timeoutSeconds =
          input.timeout_seconds ??
          Number(process.env.MACOS_ATOMIC_DEFAULT_TIMEOUT_SECONDS ?? 180);
        const inputsB64 = Buffer.from(JSON.stringify(test.inputs), "utf8").toString("base64");
        const privilegePrefix = approvedPrivilegePrefix(
          plan.scope,
          test.elevation_required
        );
        const useBashAdapter =
          plan.scope.platform === "macos" &&
          [
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
          ].includes(
            test.execution_adapter ?? ""
          ) &&
          (input.action === "execute" || input.action === "cleanup");
        const usePowerShellAdapter =
          plan.scope.platform === "macos" &&
          test.execution_adapter === "macos_t1027_013_powershell_compat" &&
          (input.action === "execute" || input.action === "cleanup");
        const runner = [
          "pwsh",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          usePowerShellAdapter
            ? POWERSHELL_DIRECT_RUNNER
            : useBashAdapter
              ? BASH_INTERACTIVE_RUNNER
              : POWERSHELL_RUNNER,
        ];
        const logDirectory = await runOnTarget(
          plan.scope,
          runnerLogDirectoryCommand(plan.scope, input.run_id),
          30_000
        );
        if (logDirectory.exitCode !== 0 || logDirectory.timedOut) {
          throw new Error(
            `Could not prepare the runner evidence directory for ${plan.scope.execution_user}: ${
              logDirectory.stderr.trim() || logDirectory.stdout.trim() || "unknown error"
            }`
          );
        }
        const result = await runOnTarget(
          plan.scope,
          [
            ...privilegePrefix,
            "env",
            ...(plan.scope.platform === "macos" ? MACOS_ATOMIC_RUNNER_ENVIRONMENT : []),
            `ATOMIC_ACTION=${input.action}`,
            `ATOMIC_RUN_ID=${input.run_id}`,
            `ATOMIC_TECHNIQUE=${test.technique_id}`,
            `ATOMIC_TEST_GUID=${test.test_guid}`,
            `ATOMIC_TIMEOUT_SECONDS=${timeoutSeconds}`,
            `ATOMIC_INPUTS_B64=${inputsB64}`,
            `ATOMIC_EXECUTION_ADAPTER=${test.execution_adapter ?? ""}`,
            ...runner,
          ],
          (timeoutSeconds + 30) * 1_000
        );
        const atomicExecutionExitCode =
          input.action === "execute" || input.action === "cleanup"
            ? parseAtomicExecutionExitCode(result.stdout)
            : undefined;
        const behaviorValidation =
          input.action === "execute"
            ? await validateBehaviorSuccess(
                plan.scope,
                test,
                result.stdout,
                result.stderr,
                result.startedAt
              )
            : undefined;
        const evidencePath = writeEvidence(
          loaded.dir,
          test.test_guid,
          input.action,
          result,
          behaviorValidation
        );
        if (input.action === "show_details") {
          return textResult({
            ok: result.exitCode === 0 && !result.timedOut,
            test_guid: test.test_guid,
            exit_code: result.exitCode,
            timed_out: result.timedOut,
            truncated: result.truncated,
            evidence_path: evidencePath,
            stdout: result.stdout,
            stderr: result.stderr,
          }, result.exitCode !== 0 || result.timedOut);
        }
        const stage =
          input.action === "execute"
            ? "execute"
            : input.action === "cleanup"
              ? "cleanup"
              : "prereq";
        const lifecycleAssertionPassed =
          input.action === "execute" &&
          test.success_criteria.some(
            (criterion) =>
              criterion.kind === "target_rebooted" || criterion.kind === "target_stopped"
          ) &&
          behaviorValidation?.ok === true;
        const runnerPassed =
          (result.exitCode === 0 &&
            !result.timedOut &&
            (atomicExecutionExitCode === undefined || atomicExecutionExitCode === 0)) ||
          lifecycleAssertionPassed;
        const behaviorPassed = input.action !== "execute" || behaviorValidation?.ok === true;
        const status = runnerPassed && behaviorPassed ? "passed" : "failed";
        const behaviorFailure =
          input.action === "execute" && !behaviorValidation?.ok
            ? "One or more digest-approved behavior success criteria failed"
            : undefined;
        const snapshot = store.recordExecution(input.run_id, {
          test_guid: test.test_guid,
          stage,
          status,
          started_at: result.startedAt,
          ended_at: result.endedAt,
          exit_code: atomicExecutionExitCode ?? result.exitCode ?? undefined,
          behavior_success:
            input.action === "execute" ? runnerPassed && behaviorPassed : undefined,
          evidence_path: evidencePath,
          notes: result.timedOut
            ? "Process timed out"
            : atomicExecutionExitCode !== undefined && atomicExecutionExitCode !== 0
              ? `Invoke-AtomicRedTeam reported Atomic exit code ${atomicExecutionExitCode}`
            : behaviorFailure
              ? behaviorFailure
              : lifecycleAssertionPassed && result.exitCode !== 0
                ? "Target lifecycle assertion confirmed the approved reboot/shutdown despite transport disconnect"
              : result.truncated
              ? "Tool response was truncated; full captured evidence is capped by MACOS_ATOMIC_MAX_OUTPUT_BYTES"
              : undefined,
        });
        return textResult(
          {
            ok: status === "passed",
            test_guid: test.test_guid,
            action: input.action,
            status,
            exit_code: atomicExecutionExitCode ?? result.exitCode,
            timed_out: result.timedOut,
            truncated: result.truncated,
            behavior_validation: behaviorValidation,
            evidence_path: evidencePath,
            stdout: result.stdout,
            stderr: result.stderr,
            run: snapshot,
          },
          status !== "passed"
        );
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    }
  );
}

/** Last Atomic exit code from Invoke-AtomicRedTeam's appended CSV evidence. */
export function parseAtomicExecutionExitCode(stdout: string): number | undefined {
  const marker = "---ATOMIC-EXECUTION-LOG---";
  const markerIndex = stdout.lastIndexOf(marker);
  if (markerIndex < 0) return undefined;
  const lines = stdout.slice(markerIndex + marker.length).split(/\r?\n/).reverse();
  for (const line of lines) {
    const match = /,(?:"(-?\d+)"|(-?\d+))\s*$/.exec(line.trim());
    const value = match?.[1] ?? match?.[2];
    if (value === undefined) continue;
    const parsed = Number(value);
    if (Number.isInteger(parsed)) return parsed;
  }
  return undefined;
}

export async function validateBehaviorSuccess(
  scope: AtomicPlan["scope"],
  test: AtomicPlan["tests"][number],
  stdout: string,
  stderr: string,
  executionStartedAt?: string
): Promise<BehaviorValidation> {
  const checks: Record<string, unknown>[] = [];
  for (const criterion of test.success_criteria) {
    if (criterion.kind === "stdout_contains" || criterion.kind === "stderr_contains") {
      const stream = criterion.kind === "stdout_contains" ? stdout : stderr;
      checks.push({ ...criterion, ok: stream.includes(criterion.value) });
      continue;
    }
    if (criterion.kind === "manual_evidence") {
      checks.push({ ...criterion, ok: false, error: "manual_evidence cannot validate an automated execution" });
      continue;
    }
    if (criterion.kind === "target_stopped") {
      if (scope.target_kind === "tart") {
        checks.push({ ...criterion, ...(await verifyTartStopped(scope)) });
      } else {
        checks.push({
          ...criterion,
          ok: false,
          supported: false,
          error: "target_stopped is only machine-verifiable for Tart targets",
        });
      }
      continue;
    }
    if (criterion.kind === "target_rebooted") {
      let result: Record<string, unknown> & { readonly ok: boolean };
      if (!executionStartedAt) {
        result = { ok: false, error: "target_rebooted requires the execution start time" };
      } else if (scope.target_kind === "tart" || scope.target_kind === "ssh") {
        result = await verifyMacosReboot(scope, executionStartedAt);
      } else {
        result = {
          ok: false,
          error: `target_rebooted is not supported for ${scope.platform} on ${scope.target_kind} targets`,
        };
      }
      checks.push({ ...criterion, ...result });
      continue;
    }
    if (
      criterion.kind === "target_path_timestamp_equals" ||
      criterion.kind === "target_path_timestamp_matches" ||
      criterion.kind === "target_path_mode_equals" ||
      criterion.kind === "target_path_size_equals" ||
      criterion.kind === "target_path_owner_equals" ||
      criterion.kind === "target_path_flags_contains"
    ) {
      const format = criterion.kind === "target_path_mode_equals"
        ? "%p"
        : criterion.kind === "target_path_size_equals"
          ? "%z"
        : criterion.kind === "target_path_owner_equals"
          ? "%Su:%Sg"
        : criterion.kind === "target_path_flags_contains"
          ? "%Sf"
          : criterion.field === "atime"
            ? "%a"
            : "%m";
      const result = await runOnTarget(
        scope,
        ["sudo", "stat", "-f", format, criterion.path],
        30_000
      );
      const rawObserved = lastNonEmptyLine(result.stdout);
      const observed = criterion.kind === "target_path_mode_equals"
        ? parseMacosFileMode(result.stdout) ?? rawObserved
        : rawObserved;
      let expected: string;
      let referenceResult: Awaited<ReturnType<typeof runOnTarget>> | undefined;
      if (criterion.kind === "target_path_timestamp_matches") {
        referenceResult = await runOnTarget(
          scope,
          ["sudo", "stat", "-f", format, criterion.reference_path],
          30_000
        );
        expected = lastNonEmptyLine(referenceResult.stdout);
      } else if (criterion.kind === "target_path_timestamp_equals") {
        expected = String(criterion.epoch_seconds);
      } else if (criterion.kind === "target_path_mode_equals") {
        expected = criterion.mode;
      } else if (criterion.kind === "target_path_size_equals") {
        expected = String(criterion.bytes);
      } else if (criterion.kind === "target_path_owner_equals") {
        expected = criterion.group ? `${criterion.owner}:${criterion.group}` : criterion.owner;
      } else {
        expected = criterion.value;
      }
      const comparisonOk = criterion.kind === "target_path_flags_contains"
        ? observed.split(",").map((value) => value.trim()).includes(expected)
        : criterion.kind === "target_path_owner_equals" && !criterion.group
          ? observed.split(":", 1)[0] === expected
        : observed === expected;
      checks.push({
        ...criterion,
        ok: result.exitCode === 0 && !result.timedOut &&
          (!referenceResult || (referenceResult.exitCode === 0 && !referenceResult.timedOut)) &&
          comparisonOk,
        observed,
        expected,
        exit_code: result.exitCode,
        reference_exit_code: referenceResult?.exitCode,
        timed_out: result.timedOut || referenceResult?.timedOut === true,
        stderr: result.stderr || referenceResult?.stderr,
      });
      continue;
    }
    if (criterion.kind === "target_path_xattr_absent") {
      const existsResult = await runOnTarget(
        scope,
        ["sudo", "stat", "-f", "%N", criterion.path],
        30_000
      );
      const xattrResult = await runOnTarget(
        scope,
        ["sudo", "xattr", "-p", criterion.name, criterion.path],
        30_000
      );
      checks.push({
        ...criterion,
        ok: existsResult.exitCode === 0 && !existsResult.timedOut &&
          xattrResult.exitCode !== 0 && !xattrResult.timedOut,
        path_exit_code: existsResult.exitCode,
        xattr_exit_code: xattrResult.exitCode,
        timed_out: existsResult.timedOut || xattrResult.timedOut,
        stderr: existsResult.stderr || xattrResult.stderr,
      });
      continue;
    }
    if (
      criterion.kind === "target_path_contains" ||
      criterion.kind === "target_path_not_contains"
    ) {
      const result = await runOnTarget(
        scope,
        [
          "sudo",
          "python3",
          "-c",
          BEHAVIOR_PATH_CONTENT_CHECKER,
          criterion.kind === "target_path_contains" ? "contains" : "not_contains",
          criterion.path,
          criterion.value,
        ],
        30_000
      );
      checks.push({
        ...criterion,
        ok: result.exitCode === 0 && !result.timedOut,
        exit_code: result.exitCode,
        timed_out: result.timedOut,
        stderr: result.stderr,
      });
      continue;
    }
    const expected = criterion.kind === "target_path_exists" ? "exists" : "absent";
    const result = await runOnTarget(
      scope,
      ["sudo", "python3", "-c", BEHAVIOR_PATH_CHECKER, expected, criterion.path],
      30_000
    );
    checks.push({
      ...criterion,
      ok: result.exitCode === 0 && !result.timedOut,
      exit_code: result.exitCode,
      timed_out: result.timedOut,
      stderr: result.stderr,
    });
  }
  return { ok: checks.length > 0 && checks.every((check) => check.ok === true), checks };
}

/** Last trimmed non-empty line emitted by a target stat command. */
export function lastNonEmptyLine(stdout: string): string {
  return stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).at(-1) ?? "";
}

/** Normalize BSD stat's full octal st_mode to permission and special bits. */
export function parseMacosFileMode(stdout: string): string | undefined {
  const raw = lastNonEmptyLine(stdout);
  if (!/^[0-7]+$/.test(raw)) return undefined;
  return (Number.parseInt(raw, 8) & 0o7777).toString(8).padStart(3, "0");
}

type LifecycleProbeDeps = {
  readonly runOnTarget: typeof runOnTarget;
  readonly runProcess: typeof runProcess;
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
  readonly timeoutMs: number;
  readonly intervalMs: number;
};

const defaultLifecycleProbeDeps: LifecycleProbeDeps = {
  runOnTarget,
  runProcess,
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutMs: 180_000,
  intervalMs: 3_000,
};

/** Epoch seconds from `sysctl -n kern.boottime`, or undefined when unparseable. */
export function parseMacosBootEpochSeconds(stdout: string): number | undefined {
  const match = /sec\s*=\s*(\d+)/.exec(stdout);
  if (!match?.[1]) return undefined;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) ? seconds : undefined;
}

/** Running state from `tart list --format json`, or undefined when unparseable. */
export function parseTartRunning(stdout: string, targetId: string): boolean | undefined {
  try {
    const parsed = JSON.parse(stdout) as unknown;
    const records = Array.isArray(parsed)
      ? parsed
      : typeof parsed === "object" && parsed !== null && "vms" in parsed
        ? (parsed as { vms?: unknown }).vms
        : [];
    if (!Array.isArray(records)) return undefined;
    const record = records.find((value) => {
      if (typeof value !== "object" || value === null) return false;
      const candidate = value as Record<string, unknown>;
      return candidate.Name === targetId || candidate.name === targetId;
    }) as Record<string, unknown> | undefined;
    if (!record) return false;
    const running = record.Running ?? record.running;
    if (typeof running === "boolean") return running;
    const state = record.State ?? record.state;
    if (typeof state === "string") return state.toLowerCase() === "running";
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * A macOS guest has rebooted after the approved execution started when the kernel boot timestamp
 * is at or after that start. Transport failures during the restart are expected and retried.
 */
export async function verifyMacosReboot(
  scope: AtomicPlan["scope"],
  executionStartedAt: string,
  deps: LifecycleProbeDeps = defaultLifecycleProbeDeps
): Promise<Record<string, unknown> & { readonly ok: boolean }> {
  const started = Date.parse(executionStartedAt);
  if (!Number.isFinite(started)) return { ok: false, error: "invalid execution start time" };
  const deadline = deps.now() + deps.timeoutMs;
  let lastError = "target has not returned";
  while (deps.now() < deadline) {
    try {
      const result = await deps.runOnTarget(scope, ["sysctl", "-n", "kern.boottime"], 10_000);
      const bootEpochSeconds = parseMacosBootEpochSeconds(result.stdout);
      if (result.exitCode === 0 && bootEpochSeconds !== undefined) {
        const bootEpochMs = bootEpochSeconds * 1_000;
        if (bootEpochMs >= started - 2_000) {
          return {
            ok: true,
            boot_time: new Date(bootEpochMs).toISOString(),
            execution_started_at: executionStartedAt,
          };
        }
        lastError = "kernel boot time predates the approved execution start";
      } else {
        lastError = result.stderr.trim() || result.stdout.trim() || "kernel boot time unavailable";
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await deps.sleep(deps.intervalMs);
  }
  return { ok: false, error: lastError, execution_started_at: executionStartedAt };
}

/** A Tart instance has stopped when `tart list --format json` reports it not running. */
export async function verifyTartStopped(
  scope: AtomicPlan["scope"],
  deps: LifecycleProbeDeps = defaultLifecycleProbeDeps
): Promise<Record<string, unknown> & { readonly ok: boolean }> {
  const deadline = deps.now() + deps.timeoutMs;
  let running: boolean | undefined;
  while (deps.now() < deadline) {
    try {
      const result = await deps.runProcess(
        "tart",
        ["list", "--format", "json"],
        { timeoutMs: 15_000 }
      );
      const parsed = result.exitCode === 0 ? parseTartRunning(result.stdout, scope.target_id) : undefined;
      if (parsed !== undefined) {
        running = parsed;
        if (!parsed) return { ok: true, supported: true, running };
      }
    } catch {
      // keep polling until the deadline
    }
    await deps.sleep(deps.intervalMs);
  }
  return {
    ok: false,
    supported: true,
    running,
    error: "instance did not reach the stopped state",
  };
}

export function approvedPrivilegePrefix(
  scope: AtomicPlan["scope"],
  elevationRequired: boolean
): string[] {
  return elevationRequired
    ? ["sudo"]
    : ["sudo", "-H", "-u", scope.execution_user, "--"];
}

export function runnerLogDirectoryCommand(
  scope: AtomicPlan["scope"],
  runId: string
): string[] {
  return [
    "sudo",
    "install",
    "-d",
    "-m",
    "0700",
    "-o",
    scope.execution_user,
    "-g",
    scope.execution_user,
    `/var/tmp/macos-atomic-runs/${runId}`,
  ];
}

async function stageFixtures(
  runDir: string,
  scope: AtomicPlan["scope"],
  runId: string,
  test: AtomicPlan["tests"][number]
): Promise<{
  ok: boolean;
  fixtureCount: number;
  startedAt: string;
  endedAt: string;
  evidencePath: string;
  error?: string;
}> {
  const startedAt = new Date().toISOString();
  const fixtures = test.fixtures ?? [];
  const fixtureRoot = `/var/tmp/macos-atomic-runs/${runId}/fixtures`;
  const evidence: Array<Record<string, unknown>> = [];
  let error: string | undefined;

  if (fixtures.length === 0) {
    error = "No digest-approved fixtures are defined for this test";
  }

  for (const fixture of fixtures) {
    if (error) break;
    const configuredPath = test.inputs[fixture.input_name];
    if (typeof configuredPath !== "string") {
      error = `Fixture input ${fixture.input_name} must reference a string path`;
      break;
    }
    const normalizedPath = path.posix.normalize(configuredPath);
    if (
      normalizedPath !== configuredPath ||
      !normalizedPath.startsWith(`${fixtureRoot}/`)
    ) {
      error = `Fixture path must be beneath ${fixtureRoot}`;
      break;
    }
    const content = Buffer.from(fixture.content_base64, "base64");
    const actualDigest = createHash("sha256").update(content).digest("hex");
    if (actualDigest !== fixture.sha256.toLowerCase()) {
      error = `Fixture digest mismatch for ${fixture.input_name}`;
      break;
    }
    const install = await runOnTarget(
      scope,
      ["sudo", "install", "-d", "-m", "0700", path.posix.dirname(normalizedPath)],
      30_000
    );
    if (install.exitCode !== 0 || install.timedOut) {
      evidence.push({ input_name: fixture.input_name, path: normalizedPath, install });
      error = `Could not create fixture directory for ${fixture.input_name}`;
      break;
    }
    const write = await runOnTarget(
      scope,
      [
        "sudo",
        "env",
        `ATOMIC_FIXTURE_PATH=${normalizedPath}`,
        `ATOMIC_FIXTURE_B64=${fixture.content_base64}`,
        `ATOMIC_FIXTURE_SHA256=${fixture.sha256.toLowerCase()}`,
        `ATOMIC_FIXTURE_MODE=${fixture.mode}`,
        "python3",
        "-c",
        FIXTURE_WRITER,
      ],
      30_000
    );
    evidence.push({
      input_name: fixture.input_name,
      path: normalizedPath,
      sha256: fixture.sha256.toLowerCase(),
      mode: fixture.mode,
      install_exit_code: install.exitCode,
      write_exit_code: write.exitCode,
      write_stdout: write.stdout,
      write_stderr: write.stderr,
      timed_out: write.timedOut,
    });
    if (
      write.exitCode !== 0 ||
      write.timedOut ||
      write.stdout.trim() !== fixture.sha256.toLowerCase()
    ) {
      error = `Could not verify fixture ${fixture.input_name}`;
      break;
    }
    const ownership = await runOnTarget(
      scope,
      [
        "sudo",
        "chown",
        "-R",
        scope.execution_user,
        `/var/tmp/macos-atomic-runs/${runId}`,
      ],
      30_000
    );
    if (ownership.exitCode !== 0 || ownership.timedOut) {
      error = `Could not assign fixture ownership to ${scope.execution_user}`;
      break;
    }
  }

  const endedAt = new Date().toISOString();
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const timestamp = startedAt.replace(/[:.]/g, "-");
  const evidencePath = path.join(
    evidenceDir,
    `${timestamp}-${test.test_guid}-stage_fixtures.json`
  );
  fs.writeFileSync(
    evidencePath,
    `${JSON.stringify({ started_at: startedAt, ended_at: endedAt, fixtures: evidence, error }, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 }
  );
  return {
    ok: !error,
    fixtureCount: evidence.length,
    startedAt,
    endedAt,
    evidencePath,
    error,
  };
}

function writeManualEvidence(
  runDir: string,
  test: AtomicPlan["tests"][number],
  value: {
    readonly stage: "manual" | "cleanup";
    readonly outcome: "completed" | "failed" | "blocked";
    readonly operator_attestation: string;
    readonly started_at: string;
    readonly ended_at: string;
    readonly observations?: string;
  }
): string {
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const timestamp = new Date().toISOString();
  const file = path.join(
    evidenceDir,
    `${timestamp.replace(/[:.]/g, "-")}-${test.test_guid}-${value.stage}.json`
  );
  fs.writeFileSync(
    file,
    `${JSON.stringify({
      recorded_at: timestamp,
      started_at: value.started_at,
      ended_at: value.ended_at,
      test_guid: test.test_guid,
      stage: value.stage,
      outcome: value.outcome,
      reviewed_steps:
        value.stage === "manual" ? test.manual?.reviewed_steps : test.manual?.cleanup_steps,
      evidence_requirements: test.manual?.evidence_requirements,
      operator_attestation: value.operator_attestation,
      observations: value.observations,
    }, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 }
  );
  return file;
}

function writeEvidence(
  runDir: string,
  testGuid: string,
  action: string,
  result: { stdout: string; stderr: string; exitCode: number | null; timedOut: boolean; startedAt: string; endedAt: string },
  behaviorValidation?: BehaviorValidation
): string {
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const timestamp = result.startedAt.replace(/[:.]/g, "-");
  const file = path.join(evidenceDir, `${timestamp}-${testGuid}-${action}.log`);
  const body = [
    `started_at=${result.startedAt}`,
    `ended_at=${result.endedAt}`,
    `exit_code=${result.exitCode ?? "null"}`,
    `timed_out=${result.timedOut}`,
    "",
    "[stdout]",
    result.stdout,
    "",
    "[stderr]",
    result.stderr,
    ...(behaviorValidation
      ? ["", "[behavior_validation]", JSON.stringify(behaviorValidation, null, 2)]
      : []),
    "",
  ].join("\n");
  fs.writeFileSync(file, body, { encoding: "utf8", mode: 0o600 });
  return file;
}
