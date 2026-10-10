import { Knex } from 'knex';

// Device identity v2: the built-in "Regen
// device ID" scripts now rewrite the SHARED Obli* device ID
// (Oblitools\device-id.json) instead of the v1 override file. The previous ID
// goes to previousIds: every upgraded Obli* agent on the machine (Obliance,
// ObliReach, Obliview, Obliguard, Oblimap) notices the change within a minute
// and hands its history over to the new ID on its own platform ("old -> new").
// A machine sharing the old ID with another (clone, junk BIOS UUID) is told
// apart by the servers' hostname rule.
//
// The Windows script keeps the name seeded by migration 103 (updated in
// place); Linux and macOS get their own copy. Migration 095 (regenerate
// /etc/machine-id) stays for agents that still use the v1 identity.

const WINDOWS_NAME = 'Regen Windows device ID (fix duplicate agent ID)';
const UNIX_NAMES = {
  linux: 'Regen Linux device ID (shared Obli* ID)',
  macos: 'Regen macOS device ID (shared Obli* ID)',
} as const;

const WINDOWS_SCRIPT = `# Gives this machine a new shared Obli* device ID (all Obli* agents).
# The old ID is kept in previousIds: each upgraded agent tells its platform
# "old -> new" within a minute, so history and cross-app links follow.
$ErrorActionPreference = 'Stop'

$dir  = Join-Path $env:ProgramData 'Oblitools'
$file = Join-Path $dir 'device-id.json'
$lock = Join-Path $dir 'device-id.lock'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# Same lock as the agents (device_identity.go): exclusive create, stale after 30 s.
$lk = $null
$deadline = (Get-Date).AddSeconds(10)
while (-not $lk) {
  try { $lk = [IO.File]::Open($lock, 'CreateNew', 'Write', 'None') }
  catch {
    if ((Test-Path $lock) -and (((Get-Date) - (Get-Item $lock).LastWriteTime).TotalSeconds -gt 30)) {
      Remove-Item $lock -Force -ErrorAction SilentlyContinue
    } elseif ((Get-Date) -gt $deadline) {
      throw "device-id.lock is held by another process"
    } else { Start-Sleep -Milliseconds 200 }
  }
}
try {
  $old = $null
  if (Test-Path $file) {
    try { $old = (Get-Content -Raw -Path $file) | ConvertFrom-Json } catch { Write-Output "Existing device-id.json unreadable, replaced." }
  }
  $prev = @()
  if ($old -and $old.deviceId) { $prev += [string]$old.deviceId }
  if ($old -and $old.previousIds) { $prev += @($old.previousIds | ForEach-Object { [string]$_ }) }
  $prev = @($prev | Where-Object { $_ } | ForEach-Object { $_.ToLower() } | Select-Object -Unique | Select-Object -First 8)
  $fp = if ($old -and $old.fingerprint) { $old.fingerprint } else { [ordered]@{ os = ''; hw = ''; disk = '' } }

  $new = [guid]::NewGuid().ToString()
  $obj = [ordered]@{
    format      = 1
    deviceId    = $new
    previousIds = $prev
    reason      = 'regenerated'
    fingerprint = $fp
    createdAt   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    createdBy   = 'regen-script'
  }
  $json = $obj | ConvertTo-Json -Depth 4
  $tmp = Join-Path $dir ('.device-id.json.tmp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
  [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
  Move-Item -Force -Path $tmp -Destination $file

  $oldId = if ($old -and $old.deviceId) { [string]$old.deviceId } else { '(none)' }
  Write-Output "Old device ID: $oldId"
  Write-Output "New device ID: $new"
  Write-Output "Upgraded Obli* agents switch within a minute (old -> new announced to each platform)."
  Write-Output "Agents that do not use the shared ID yet keep their current ID until they are updated."
} finally {
  if ($lk) { $lk.Close() }
  Remove-Item $lock -Force -ErrorAction SilentlyContinue
}
exit 0
`;

const UNIX_SCRIPT = `#!/bin/bash
# Gives this machine a new shared Obli* device ID (all Obli* agents).
# The old ID is kept in previousIds: each upgraded agent tells its platform
# "old -> new" within a minute, so history and cross-app links follow.
set -eu

dir=/etc/oblitools
file="$dir/device-id.json"
lock="$dir/device-id.lock"
mkdir -p "$dir"
chmod 755 "$dir"

# Same lock as the agents (device_identity.go): exclusive create, stale after ~1 min.
i=0
while ! ( set -C; echo $$ > "$lock" ) 2>/dev/null; do
  if [ -n "$(find "$lock" -mmin +1 2>/dev/null)" ]; then rm -f "$lock"; continue; fi
  i=$((i + 1))
  if [ "$i" -gt 50 ]; then echo "device-id.lock is held by another process" >&2; exit 1; fi
  sleep 0.2
done
trap 'rm -f "$lock"' EXIT

flat=""
[ -f "$file" ] && flat=$(tr -d '\\n\\r' < "$file")
old=$(printf '%s' "$flat" | sed -n 's/.*"deviceId": *"\\([0-9a-fA-F-]\\{36\\}\\)".*/\\1/p' | tr 'A-F' 'a-f')
oldprev=$(printf '%s' "$flat" | sed -n 's/.*"previousIds": *\\[\\([^]]*\\)\\].*/\\1/p' | tr -d ' "' | tr ',' '\\n' | tr 'A-F' 'a-f')
fp=$(printf '%s' "$flat" | sed -n 's/.*"fingerprint": *\\({[^}]*}\\).*/\\1/p')
[ -n "$fp" ] || fp='{"os":"","hw":"","disk":""}'

if [ -r /proc/sys/kernel/random/uuid ]; then new=$(cat /proc/sys/kernel/random/uuid)
elif command -v uuidgen >/dev/null 2>&1; then new=$(uuidgen | tr 'A-F' 'a-f')
else
  h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n')
  new="\${h:0:8}-\${h:8:4}-4\${h:13:3}-$(printf '%x' $(( (0x\${h:16:1} & 3) | 8 )))\${h:17:3}-\${h:20:12}"
fi
if ! printf '%s' "$new" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
  echo "Could not generate a UUID" >&2; exit 1
fi

prev=$(printf '%s\\n%s\\n' "$old" "$oldprev" | grep -E '^[0-9a-f-]{36}$' | awk '!seen[$0]++' | head -n 8 \\
  | awk 'BEGIN{ORS=""} {printf "%s\\"%s\\"", (NR>1?", ":""), $0}')

tmp="$dir/.device-id.json.tmp-$$"
cat > "$tmp" <<JSON
{
  "format": 1,
  "deviceId": "$new",
  "previousIds": [$prev],
  "reason": "regenerated",
  "fingerprint": $fp,
  "createdAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "createdBy": "regen-script"
}
JSON
chmod 644 "$tmp"
mv -f "$tmp" "$file"

echo "Old device ID: \${old:-(none)}"
echo "New device ID: $new"
echo "Upgraded Obli* agents switch within a minute (old -> new announced to each platform)."
echo "Agents that do not use the shared ID yet keep their current ID until they are updated."
`;

const WINDOWS_DESCRIPTION =
  'Gives the machine a new shared Obli* device ID (Oblitools\\device-id.json) and keeps the old one as previous ID: every upgraded Obli* agent (Obliance, ObliReach, Obliview, Obliguard, Oblimap) moves its history to the new ID within a minute. Use on machines with a duplicate agent ID (clones, OEM placeholder BIOS UUID).';
const UNIX_DESCRIPTION =
  'Gives the machine a new shared Obli* device ID (/etc/oblitools/device-id.json) and keeps the old one as previous ID: every upgraded Obli* agent moves its history to the new ID within a minute. Use on machines with a duplicate agent ID.';

export async function up(knex: Knex): Promise<void> {
  const win = await knex('scripts').whereNull('tenant_id').where({ name: WINDOWS_NAME, is_builtin: true }).first('id');
  if (win) {
    await knex('scripts').where({ id: win.id }).update({ content: WINDOWS_SCRIPT, description: WINDOWS_DESCRIPTION, updated_at: knex.fn.now() });
  } else {
    await knex('scripts').insert({
      tenant_id: null, name: WINDOWS_NAME, description: WINDOWS_DESCRIPTION,
      tags: JSON.stringify(['identity', 'cloning', 'device-id', 'troubleshoot']),
      platform: 'windows', runtime: 'powershell', content: WINDOWS_SCRIPT,
      timeout_seconds: 60, expected_exit_code: 0, run_as: 'system', script_type: 'system', is_builtin: true,
    });
  }

  for (const [platform, name] of Object.entries(UNIX_NAMES)) {
    const exists = await knex('scripts').whereNull('tenant_id').where({ name, is_builtin: true }).first('id');
    if (exists) continue;
    await knex('scripts').insert({
      tenant_id: null, name, description: UNIX_DESCRIPTION,
      tags: JSON.stringify(['identity', 'cloning', 'device-id', 'troubleshoot']),
      platform, runtime: 'bash', content: UNIX_SCRIPT,
      timeout_seconds: 60, expected_exit_code: 0, run_as: 'system', script_type: 'system', is_builtin: true,
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  // The v1 Windows content lives in migration 103; re-running it after a
  // rollback is a no-op (row exists), so the v2 content simply stays.
  for (const name of Object.values(UNIX_NAMES)) {
    await knex('scripts').whereNull('tenant_id').where({ name, is_builtin: true }).delete();
  }
}
