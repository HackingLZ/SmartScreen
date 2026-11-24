#!/usr/bin/env python3
"""Read-only Windows SmartScreen lab collection through verified OpenSSH."""
import argparse
import base64
import hashlib
import getpass
import json
import os
import subprocess
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def ps_literal(value):
    return "'" + value.replace("'", "''") + "'"


def remote_ps(host, script, known_hosts=None, password=None):
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    if not host or host.startswith("-") or any(c.isspace() for c in host):
        raise ValueError("Host must be an SSH host or user@host, not options")
    cmd = ["ssh", "-o", "BatchMode=" + ("no" if password is not None else "yes"),
           "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes"]
    env = os.environ.copy()
    if password is not None:
        cmd = ["sshpass", "-e"] + cmd + ["-o", "PreferredAuthentications=password,keyboard-interactive",
                                        "-o", "NumberOfPasswordPrompts=1"]
        env["SSHPASS"] = password
    if known_hosts:
        cmd += ["-o", "UserKnownHostsFile=" + str(known_hosts)]
    cmd += [host, "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env)
    if run.returncode:
        raise RuntimeError(run.stderr.strip() or "Remote command failed")
    return run.stdout.lstrip("\ufeff").strip()


INVENTORY = r'''
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$paths = @(
  "$env:WINDIR\System32\smartscreen.exe",
  "$env:WINDIR\System32\smartscreen.dll",
  "$env:WINDIR\System32\apprepapi.dll",
  "$env:WINDIR\System32\Windows.SmartScreen.dll",
  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
)
$files = @(foreach ($p in $paths) {
  if (Test-Path -LiteralPath $p -PathType Leaf) {
    $f = Get-Item -LiteralPath $p
    [ordered]@{path=$p; size=$f.Length; version=$f.VersionInfo.FileVersion;
      sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()}
  }
})
$policies = @()
foreach ($key in @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer',
  'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy')) {
  if (Test-Path $key) {
    $values = Get-ItemProperty $key
    foreach ($name in @('SmartScreenEnabled','SmartScreenPuaEnabled', 'SmartScreenForTrustedDownloadsEnabled',
      'PreventSmartScreenPromptOverride','PreventSmartScreenPromptOverrideForFiles',
      'EnableSmartScreen','ShellSmartScreenLevel','SmartScreenEnable','VerifiedAndReputablePolicyState')) {
      if ($null -ne $values.PSObject.Properties[$name]) {
        $policies += [ordered]@{key=$key; name=$name; value=$values.$name}
      }
    }
  }
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
[ordered]@{
  collected_utc=[DateTime]::UtcNow.ToString('o'); windows_version=$os.Version;
  windows_build=$os.BuildNumber; os_architecture=$os.OSArchitecture;
  processor_architecture=$cpu.Architecture; elevated=$admin; files=$files; registry_observations=$policies;
  policy_note='Registry observations do not establish effective per-profile Edge policy. Record edge://policy separately.'
} | ConvertTo-Json -Depth 8
'''


def fetch_script(path):
    return r'''
$ErrorActionPreference = 'Stop'
$p = ''' + ps_literal(path) + r'''
$f = Get-Item -LiteralPath $p
if ($f.Length -gt 67108864) { throw 'File exceeds 64 MiB collection limit' }
$b = [IO.File]::ReadAllBytes($f.FullName)
$sha = [Security.Cryptography.SHA256]::Create()
$hash = ([BitConverter]::ToString($sha.ComputeHash($b))).Replace('-','').ToLower()
[ordered]@{sha256=$hash; size=$b.Length; base64=[Convert]::ToBase64String($b)} | ConvertTo-Json -Compress
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Explicit SSH user@host; no machine-specific default")
    parser.add_argument("--known-hosts", type=Path)
    parser.add_argument("--password", action="store_true", help="Prompt privately; use sshpass while retaining strict host verification")
    sub = parser.add_subparsers(dest="command", required=True)
    inv = sub.add_parser("inventory")
    inv.add_argument("-o", "--output", type=Path)
    fetch = sub.add_parser("fetch", help="Copy one explicit analysis file; never execute it")
    fetch.add_argument("remote_path")
    fetch.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        password = getpass.getpass("SSH password: ") if args.password else None
        if args.command == "inventory":
            data = json.loads(remote_ps(args.host, INVENTORY, args.known_hosts, password))
            output = json.dumps(data, indent=2) + "\n"
            if args.output:
                args.output.write_text(output, encoding="utf-8")
            else:
                print(output, end="")
        else:
            data = json.loads(remote_ps(args.host, fetch_script(args.remote_path), args.known_hosts, password))
            raw = base64.b64decode(data["base64"], validate=True)
            if len(raw) != data["size"] or hashlib.sha256(raw).hexdigest() != data["sha256"]:
                raise ValueError("Collected file failed length/hash verification")
            # Exclusive creation protects earlier evidence from accidental replacement.
            with args.output.open("xb") as out:
                out.write(raw)
            print(json.dumps({"path": str(args.output), "sha256": data["sha256"], "size": len(raw)}))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
