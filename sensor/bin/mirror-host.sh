#!/usr/bin/env bash
# Copy the sensor host's own kernel and hardware facts into the persona.
#
#   mirror-host.sh static   /proc/cpuinfo, /proc/version and the output of
#                           lscpu, nproc, lspci, df, mount, getconf, dmesg
#                           and top. Run before Cowrie starts.
#   mirror-host.sh proc     /proc/uptime, /proc/loadavg and /proc/meminfo.
#                           Run every minute by cowrie-proc.timer.
#
# Cowrie's shipped filesystem answers these questions for another machine: a
# Debian kernel in /proc/version, ext3 and /lib/init/rw from mount, a 2009
# dmesg, hostname svr04. A session that asks the same thing two ways (uname
# against /proc/version, free against /proc/meminfo, nproc against cpuinfo)
# gets two answers. The host itself is the one source guaranteed to agree with
# itself, so its answers are copied in. cowrie.service runs with
# ProcSubset=pid and cannot read these files, which is why root copies them
# and the shell-host-stats patch reads the copies.
#
# Runs as root. Writes only under honeyfs/proc and share/cowrie/txtcmds.
set -euo pipefail

COWRIE=${COWRIE:-/opt/cowrie}
PROC=${MIRROR_PROC:-/proc}
HONEYFS="$COWRIE/honeyfs"
TXT="$COWRIE/share/cowrie/txtcmds"
CFG="$COWRIE/cowrie.cfg"
# Lines naming the sensor's own machinery never reach the persona.
HIDE='cowrie|tailscale|docker|containerd|/opt/'

# put DEST: replace DEST with stdin in one rename, world-readable.
put() {
  local dest=$1 tmp
  mkdir -p "$(dirname "$dest")"
  tmp=$(mktemp "$dest.XXXXXX")
  cat > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$dest"
}

# capture DEST CMD...: run CMD and store its output, keeping the old copy if
# the command is missing or fails, so a bad run never blanks a file.
capture() {
  local dest=$1; shift
  local out
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "mirror-host: $1 not installed, kept existing ${dest#"$COWRIE"/}" >&2
    return 0
  fi
  if ! out=$("$@" 2>/dev/null); then
    echo "mirror-host: $* failed, kept existing ${dest#"$COWRIE"/}" >&2
    return 0
  fi
  printf '%s\n' "$out" | grep -Ev "$HIDE" | put "$dest"
}

do_proc() {
  local f
  for f in uptime loadavg meminfo; do
    put "$HONEYFS/proc/$f" < "$PROC/$f"
  done
}

do_static() {
  put "$HONEYFS/proc/cpuinfo" < "$PROC/cpuinfo"
  put "$HONEYFS/proc/version" < "$PROC/version"
  # /proc/mounts is a symlink in Cowrie's tree, so a copy at that path is
  # never read. The mount command below answers the same question.
  capture "$TXT/usr/bin/lscpu" lscpu
  capture "$TXT/usr/bin/nproc" nproc
  capture "$TXT/usr/bin/lspci" lspci
  capture "$TXT/usr/bin/df" df -h
  capture "$TXT/usr/bin/mount" mount
  capture "$TXT/usr/bin/getconf" getconf LONG_BIT
  # Ubuntu restricts the kernel log to root (kernel.dmesg_restrict=1) and the
  # userdb never admits root, so this is what any session would see.
  echo "dmesg: read kernel buffer failed: Operation not permitted" \
    | put "$TXT/usr/bin/dmesg"
  # txtcmds output is static, and a frozen process table with an old clock is
  # easy to spot. top run without a terminal it can drive prints this.
  echo "top: failed tty get" | put "$TXT/usr/bin/top"
  do_proc

  # uname inside Cowrie comes from cowrie.cfg, not the host. After a kernel
  # upgrade the two disagree until the config is edited, so say so.
  local want have
  want=$(sed -n 's/^kernel_version *= *//p' "$CFG" 2>/dev/null | tail -n1)
  have=$(sed -n 's/^Linux version \([^ ]*\).*/\1/p' "$PROC/version")
  if [ -n "$want" ] && [ -n "$have" ] && [ "$want" != "$have" ]; then
    echo "mirror-host: kernel_version in cowrie.cfg is $want but the host runs $have;" \
         "uname and /proc/version now disagree" >&2
  fi
}

case "${1:-}" in
  static) do_static ;;
  proc) do_proc ;;
  *) echo "usage: mirror-host.sh static|proc" >&2; exit 2 ;;
esac
