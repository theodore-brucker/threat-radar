#!/usr/bin/env bats
# The sensor's forced-command wrapper, run the way sshd runs it: the only
# input is SSH_ORIGINAL_COMMAND. Everything it refuses must exit non-zero
# with nothing on stdout, and everything it answers must be exact.

setup() {
  WRAPPER="$BATS_TEST_DIRNAME/../../sensor/bin/pull-logs.sh"
  LOGS="$BATS_TEST_TMPDIR/logs"; DL="$BATS_TEST_TMPDIR/downloads"
  mkdir -p "$LOGS" "$DL"
  printf '0123456789' > "$LOGS/cowrie.json"
  printf 'rotated' > "$LOGS/cowrie.json.2026-09-20"
  printf 'text' > "$LOGS/cowrie.log"
  printf 'sample-body' > "$DL/$(printf 'sample-body' | sha256sum | cut -d' ' -f1)"
  export PULL_LOGDIR="$LOGS" PULL_DLDIR="$DL"
}

ask() { SSH_ORIGINAL_COMMAND="$1" run bash "$WRAPPER"; }

@test "manifest lists only log files, with sizes" {
  ask "manifest"
  [ "$status" -eq 0 ]
  [ "$output" = "cowrie.json 10
cowrie.json.2026-09-20 7" ]
}

@test "chunk returns exactly the requested range" {
  ask "chunk cowrie.json 3 4"
  [ "$status" -eq 0 ]
  [ "$output" = "3456" ]
}

@test "chunk stops at the end of the file" {
  ask "chunk cowrie.json 8 100"
  [ "$output" = "89" ]
}

@test "samples-list and samples-get agree on the capture" {
  ask "samples-list"
  [ "$status" -eq 0 ]
  sha=$(echo "$output" | cut -d' ' -f2)
  ask "samples-get $sha"
  [ "$status" -eq 0 ]
  [ "$output" = "sample-body" ]
}

@test "the retired logs request is refused" {
  ask "logs"
  [ "$status" -ne 0 ]
  [ -z "$output" ] || [[ "$output" == refused* ]]
}

refused() {
  ask "$1"
  [ "$status" -ne 0 ]
  # nothing that looks like file content may come back
  [[ "$output" != *0123456789* && "$output" != *rotated* && "$output" != *root:* ]]
}

@test "path traversal in a log name is refused"      { refused "chunk ../../etc/passwd 0 10"; }
@test "a log name outside the pattern is refused"    { refused "chunk cowrie.log 0 10"; }
@test "a negative offset is refused"                 { refused "chunk cowrie.json -1 10"; }
@test "a non-decimal length is refused"              { refused "chunk cowrie.json 0 1e9"; }
@test "an offset past the end is refused"            { refused "chunk cowrie.json 999 1"; }
@test "missing arguments are refused"                { refused "chunk cowrie.json 0"; }
@test "extra arguments are refused"                  { refused "manifest extra"; }
@test "a glob is not expanded"                       { refused "chunk * 0 10"; }
@test "a non-hex sample name is refused"             { refused "samples-get ../x"; }
@test "a sample name of the wrong length is refused" { refused "samples-get abcdef"; }
@test "shell syntax is not interpreted"              { refused "manifest; cat /etc/passwd"; }
@test "command substitution is not interpreted"      { refused '$(cat /etc/passwd)'; }
@test "an unknown request is refused"                { refused "rm -rf /"; }
@test "an empty request is refused"                  { refused ""; }
