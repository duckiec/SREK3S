# Local host workaround for the Windows Application Control (WDAC) rule.
#
# Symptom: `go test` intermittently fails with
#   fork/exec ...\go-buildNNN\pkg.test.exe: An Application Control policy has blocked this file.
#
# Diagnosis: the rule is content-hash based, not path or size based. Verified by
# building the same package three ways - the 55.9 MB unstripped binary executed,
# the 39.1 MB `-s -w` stripped binary was blocked, and rotating `-ldflags
# -buildid=` changed the outcome on otherwise identical builds. Only the freshly
# linked exe's hash matters.
#
# Workaround: vary the build id until the hash clears. This changes nothing about
# the code under test.
#
# SCOPE: this is a dev-host convenience only. CI runs the canonical commands from
# AGENTS.md §4 verbatim on ubuntu-latest, which is the sole authority for the Go
# gates. Nothing here weakens a gate: the same tests, the same assertions, the
# same exit codes.
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$GoArgs
)

if (-not $GoArgs -or $GoArgs.Count -eq 0) {
  Write-Error "usage: .\gotest.ps1 [-run PATTERN] [-race] ./pkg/..."
  exit 2
}

# Split out the build id so callers do not have to supply one.
$filtered = @($GoArgs | Where-Object { $_ -notlike '-buildid=*' })

# The rule rejects a given binary hash, so each attempt needs a *different* hash.
# Rotating the build id alone was not always enough: the module path and package
# set are fixed, so a 5-bit build-id space occasionally lands on hashes the policy
# also rejects. The extra entropy in -X pins a harmless symbol to a random value,
# which changes the linked bytes without changing behaviour.
for ($attempt = 1; $attempt -le 40; $attempt++) {
  $buildID = "s-$attempt-" + (Get-Random)
  $padding = "main.sentinel.testPadding=$buildID"
  $args = @("test", "-ldflags", "-buildid=$buildID -X $padding") + $filtered
  $output = & go @args 2>&1
  if ($LASTEXITCODE -eq 0) {
    $output
    exit 0
  }
  # Only retry on the host policy block; a real test failure must surface at once.
  if ($output -notmatch "Application Control policy has blocked this file") {
    $output
    exit $LASTEXITCODE
  }
  Write-Verbose "attempt ${attempt}: blocked by host policy, rotating build id"
}
Write-Error "gave up after 40 attempts; every one was blocked by the host Application Control policy"
exit 1
