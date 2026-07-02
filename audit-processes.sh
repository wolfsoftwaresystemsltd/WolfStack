#!/bin/bash
# audit-processes.sh — incident-response process triage for a Linux host.
# Flags processes with characteristics commonly seen in compromises.
# Read-only — does NOT kill anything. Investigate flagged PIDs manually.
#
# Usage:  sudo bash audit-processes.sh

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

YELLOW=$'\033[33m'; RED=$'\033[31m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; RESET=$'\033[0m'

section() { echo ""; echo "${CYAN}=== $* ===${RESET}"; }
flag()    { echo "${RED}[!]${RESET} $*"; }
note()    { echo "${YELLOW}[?]${RESET} $*"; }
ok()      { echo "${DIM}    $*${RESET}"; }

# Paths that should NEVER host a running binary on a normal Proxmox host
SUSPICIOUS_PATHS_RE='^(/tmp|/var/tmp|/dev/shm|/run/user|/run/lock|/home/[^/]+/\.cache|/var/spool|/srv)/'

# ─── 1. Processes with deleted binaries ───────────────────────────────────────
section "Processes with DELETED binaries (classic fileless / memory-resident malware)"
found=0
for pid_dir in /proc/[0-9]*; do
  pid=${pid_dir##*/}
  exe_link=$(readlink "$pid_dir/exe" 2>/dev/null) || continue
  if [[ "$exe_link" == *"(deleted)"* ]]; then
    cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
    user=$(stat -c '%U' "$pid_dir" 2>/dev/null)
    flag "pid=$pid user=$user exe=$exe_link"
    ok  "cmd=$cmd"
    found=$((found+1))
  fi
done
[[ $found -eq 0 ]] && ok "none found"

# ─── 2. Processes running from temp / writable paths ──────────────────────────
section "Processes running from /tmp, /var/tmp, /dev/shm, user caches"
found=0
for pid_dir in /proc/[0-9]*; do
  pid=${pid_dir##*/}
  exe_link=$(readlink -f "$pid_dir/exe" 2>/dev/null) || continue
  if [[ "$exe_link" =~ $SUSPICIOUS_PATHS_RE ]]; then
    cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
    user=$(stat -c '%U' "$pid_dir" 2>/dev/null)
    flag "pid=$pid user=$user exe=$exe_link"
    ok  "cmd=$cmd"
    found=$((found+1))
  fi
done
[[ $found -eq 0 ]] && ok "none found"

# ─── 3. Userland processes masquerading as kernel threads ────────────────────
# Real kernel threads: PPID=2 (kthreadd) and exe link is empty/unreadable.
# Userland process with [bracketed] cmdline trying to hide.
section "Userland processes faking kernel-thread names ([brackets])"
found=0
for pid_dir in /proc/[0-9]*; do
  pid=${pid_dir##*/}
  [[ "$pid" == "2" ]] && continue
  ppid=$(awk '{print $4}' "$pid_dir/stat" 2>/dev/null) || continue
  [[ "$ppid" == "2" || "$ppid" == "0" ]] && continue  # real kernel thread

  cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
  [[ -z "$cmdline" ]] && continue  # genuinely empty → likely kernel thread

  comm=$(cat "$pid_dir/comm" 2>/dev/null)
  if [[ "$comm" =~ ^\[.*\]$ ]] || [[ "$cmdline" =~ ^\[.*\]$ ]]; then
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null)
    user=$(stat -c '%U' "$pid_dir" 2>/dev/null)
    flag "pid=$pid ppid=$ppid user=$user comm=$comm exe=$exe"
    found=$((found+1))
  fi
done
[[ $found -eq 0 ]] && ok "none found"

# ─── 4. Processes whose exe basename differs from comm ───────────────────────
section "Processes where /proc/PID/comm doesn't match the exe basename"
note "(legitimate for interpreters, login shells — review case by case)"
found=0
for pid_dir in /proc/[0-9]*; do
  pid=${pid_dir##*/}
  exe=$(readlink -f "$pid_dir/exe" 2>/dev/null) || continue
  [[ -z "$exe" ]] && continue
  exe_base=$(basename "$exe" | sed 's/ (deleted)$//')
  comm=$(cat "$pid_dir/comm" 2>/dev/null)
  # comm is truncated to 15 chars
  exe_base_truncated="${exe_base:0:15}"
  if [[ "$comm" != "$exe_base_truncated" ]]; then
    cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
    user=$(stat -c '%U' "$pid_dir" 2>/dev/null)
    # Filter out the obvious legit cases
    case "$comm" in
      bash|sh|dash|zsh|fish|python*|perl|ruby|node|java|systemd|sshd*|cron|init) continue ;;
    esac
    note "pid=$pid user=$user comm=$comm exe=$exe"
    ok  "cmd=$cmd"
    found=$((found+1))
  fi
done
[[ $found -eq 0 ]] && ok "no mismatches"

# ─── 5. Processes with LD_PRELOAD set (often hooking libc) ───────────────────
section "Processes with LD_PRELOAD set in environment"
found=0
for pid_dir in /proc/[0-9]*; do
  pid=${pid_dir##*/}
  [[ -r "$pid_dir/environ" ]] || continue
  ld=$(tr '\0' '\n' < "$pid_dir/environ" 2>/dev/null | grep '^LD_PRELOAD=' || true)
  if [[ -n "$ld" ]]; then
    cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
    user=$(stat -c '%U' "$pid_dir" 2>/dev/null)
    flag "pid=$pid user=$user $ld"
    ok  "cmd=$cmd"
    found=$((found+1))
  fi
done
[[ $found -eq 0 ]] && ok "none found"

# ─── 6. Suspicious parent → child relationships ──────────────────────────────
section "Unusual parent → child shells (web/db spawning bash is a major IOC)"
found=0
# Build pid → comm map once
declare -A PCOMM
for pid_dir in /proc/[0-9]*; do
  pid=${pid_dir##*/}
  PCOMM[$pid]=$(cat "$pid_dir/comm" 2>/dev/null)
done
for pid_dir in /proc/[0-9]*; do
  pid=${pid_dir##*/}
  comm=${PCOMM[$pid]:-}
  case "$comm" in bash|sh|dash|zsh|nc|ncat|socat|python*|perl|ruby) ;;
    *) continue ;;
  esac
  ppid=$(awk '{print $4}' "$pid_dir/stat" 2>/dev/null)
  parent_comm=${PCOMM[$ppid]:-?}
  case "$parent_comm" in
    apache2|nginx|httpd|php-fpm*|mysqld|mariadbd|postgres|redis-server|memcached|named|bind|dovecot|exim*|postfix|smtpd|pveproxy|pvedaemon)
      cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
      user=$(stat -c '%U' "$pid_dir" 2>/dev/null)
      flag "pid=$pid ($comm) spawned by ppid=$ppid ($parent_comm) user=$user"
      ok  "cmd=$cmd"
      found=$((found+1))
      ;;
  esac
done
[[ $found -eq 0 ]] && ok "none found"

# ─── 7. Hidden processes (in /proc but not in ps) ────────────────────────────
section "Hidden processes (in /proc but ps doesn't list them — rootkit IOC)"
found=0
ps_pids=$(ps -eo pid= | tr -d ' ' | sort -n)
proc_pids=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
for pid in $hidden; do
  [[ -d "/proc/$pid" ]] || continue  # process exited between listings
  comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "?")
  exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "?")
  flag "pid=$pid comm=$comm exe=$exe (in /proc but not in ps output)"
  found=$((found+1))
done
[[ $found -eq 0 ]] && ok "none found"

# ─── 8. Recently started long-running processes ──────────────────────────────
section "Processes started in the last 60 minutes (review for unexpected ones)"
ps -eo pid,etime,user,comm,cmd --sort=etime \
  | awk 'NR==1 || $2 ~ /^[0-9]+:[0-5][0-9]$/' \
  | awk '$2 != "00:00" && (NR==1 || ($2 ~ /^([0-9]|[1-5][0-9]):[0-5][0-9]$/))' \
  | head -30

# ─── 9. SUID/SGID binaries currently running ─────────────────────────────────
section "Running processes whose exe is SUID or SGID"
found=0
for pid_dir in /proc/[0-9]*; do
  pid=${pid_dir##*/}
  exe=$(readlink -f "$pid_dir/exe" 2>/dev/null) || continue
  [[ -z "$exe" || ! -f "$exe" ]] && continue
  perms=$(stat -c '%a' "$exe" 2>/dev/null) || continue
  # Check for SUID (4xxx) or SGID (2xxx)
  if [[ ${#perms} -eq 4 ]] && [[ "${perms:0:1}" =~ [2367] ]]; then
    cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
    note "pid=$pid perms=$perms exe=$exe"
    ok  "cmd=$cmd"
    found=$((found+1))
  fi
done
[[ $found -eq 0 ]] && ok "none found"

# ─── 10. Listening sockets — anything unusual ─────────────────────────────────
section "All listening TCP/UDP sockets"
ss -tulnp 2>/dev/null

echo ""
echo "${CYAN}=== TRIAGE COMPLETE ===${RESET}"
echo "Red [!] = high-confidence indicator, investigate immediately"
echo "Yellow [?] = needs human judgement, may be legitimate"
echo ""
echo "Next steps for any flagged PID:"
echo "  ls -l /proc/<pid>/exe       # see the on-disk binary path"
echo "  cat /proc/<pid>/status      # uids, parent, capabilities"
echo "  cat /proc/<pid>/maps        # loaded libs (look for /tmp /dev/shm)"
echo "  tr '\\0' '\\n' < /proc/<pid>/environ  # full environment"
echo "  lsof -p <pid>               # open files + sockets"
echo "  kill -STOP <pid>            # FREEZE without killing (preserves memory for analysis)"
