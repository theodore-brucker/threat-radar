#!/usr/bin/env bats
# mirror-host.sh copies host facts into the persona. Stubbed commands stand in
# for the host, so these run anywhere and the filter on the sensor's own
# machinery can be checked.

setup() {
  SCRIPT="$BATS_TEST_DIRNAME/../../sensor/bin/mirror-host.sh"
  export COWRIE="$BATS_TEST_TMPDIR/cowrie" MIRROR_PROC="$BATS_TEST_TMPDIR/proc"
  mkdir -p "$COWRIE" "$MIRROR_PROC" "$BATS_TEST_TMPDIR/bin"
  printf '1893445.12 1790000.55\n' > "$MIRROR_PROC/uptime"
  printf '0.08 0.03 0.01 1/187 41234\n' > "$MIRROR_PROC/loadavg"
  printf 'MemTotal:        1983712 kB\n' > "$MIRROR_PROC/meminfo"
  printf 'processor\t: 0\nmodel name\t: AMD EPYC-Rome Processor\n' > "$MIRROR_PROC/cpuinfo"
  printf 'Linux version 6.8.0-117-generic (buildd@lcy02) #117-Ubuntu SMP\n' > "$MIRROR_PROC/version"
  printf '/dev/sda1 / ext4 rw 0 0\n/dev/sda1 /opt/cowrie/var ext4 rw 0 0\n' > "$MIRROR_PROC/mounts"
  printf '[shell]\nkernel_version = 6.8.0-117-generic\n' > "$COWRIE/cowrie.cfg"
  stub lscpu 'echo "CPU(s): 1"'
  stub nproc 'echo 1'
  stub lspci 'echo "00:00.0 Host bridge: Intel Corporation 82G33/G31/P35/P31 Express DRAM Controller"'
  stub df 'printf "Filesystem Size\n/dev/sda1 38G\noverlay 38G /var/lib/docker/x\n"'
  stub mount 'printf "/dev/sda1 on / type ext4\ntmpfs on /run/user type tmpfs\n"'
  stub getconf 'echo 64'
  PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

stub() { printf '#!/bin/sh\n%s\n' "$2" > "$BATS_TEST_TMPDIR/bin/$1"; chmod +x "$BATS_TEST_TMPDIR/bin/$1"; }

@test "proc copies uptime, loadavg and meminfo" {
  run bash "$SCRIPT" proc
  [ "$status" -eq 0 ]
  [ "$(cat "$COWRIE/honeyfs/proc/uptime")" = "1893445.12 1790000.55" ]
  [ "$(cat "$COWRIE/honeyfs/proc/loadavg")" = "0.08 0.03 0.01 1/187 41234" ]
  [ -f "$COWRIE/honeyfs/proc/meminfo" ]
  [ ! -e "$COWRIE/share/cowrie/txtcmds/usr/bin/lscpu" ]
}

@test "static writes command output and drops the sensor's own machinery" {
  run bash "$SCRIPT" static
  [ "$status" -eq 0 ]
  T="$COWRIE/share/cowrie/txtcmds/usr/bin"
  [ "$(cat "$T/nproc")" = "1" ]
  [ "$(cat "$T/getconf")" = "64" ]
  grep -q "AMD EPYC" "$COWRIE/honeyfs/proc/cpuinfo"
  grep -q "^/dev/sda1 38G" "$T/df"
  ! grep -q docker "$T/df"
  ! grep -q cowrie "$COWRIE/honeyfs/proc/mounts"
  grep -q "Operation not permitted" "$T/dmesg"
  [ -f "$COWRIE/honeyfs/proc/uptime" ]
}

@test "a missing command keeps the existing file" {
  mkdir -p "$COWRIE/share/cowrie/txtcmds/usr/bin"
  echo "kept" > "$COWRIE/share/cowrie/txtcmds/usr/bin/lspci"
  rm "$BATS_TEST_TMPDIR/bin/lspci"
  PATH="$BATS_TEST_TMPDIR/bin:/usr/bin:/bin" run bash "$SCRIPT" static
  [ "$status" -eq 0 ]
  if command -v lspci >/dev/null; then skip "host has lspci"; fi
  [ "$(cat "$COWRIE/share/cowrie/txtcmds/usr/bin/lspci")" = "kept" ]
}

@test "a kernel that no longer matches cowrie.cfg is reported" {
  printf '[shell]\nkernel_version = 6.8.0-100-generic\n' > "$COWRIE/cowrie.cfg"
  run bash "$SCRIPT" static
  [ "$status" -eq 0 ]
  [[ "$output" == *"uname and /proc/version now disagree"* ]]
}

@test "no mode is a usage error" {
  run bash "$SCRIPT"
  [ "$status" -eq 2 ]
}
