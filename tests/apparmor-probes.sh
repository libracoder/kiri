#!/bin/bash
# AppArmor on a Linux host: the same probes, each a command run as root in a
# container, on Kiri and on Docker Engine on the same host, side by side.
# Kiri's result must equal Docker's on every line, or be stricter where the
# line is in STRICTER below (Kiri refuses what Docker allows, on purpose),
# or a refusal on both sides where the line is in BOTH_REFUSE.
#
#   KIRI_HOST=unix:///run/kiri/docker.sock tests/apparmor-probes.sh
#   KIRI_HOST=... REF_HOST=unix:///var/run/docker.sock tests/apparmor-probes.sh
#   KIRI_HOST=... REF_HOST= tests/apparmor-probes.sh      # Kiri's column only
#
# KIRI_HOST and REF_HOST are DOCKER_HOST values (REF_HOST defaults to
# Docker's socket when it is there). Run it on the host the engines run on:
# with AppArmor enabled, both engines confine their containers; without it
# both columns say "unconfined" and the denials below are the other layers'
# (capabilities, seccomp, read-only and masked paths).
# PROBE_PREFIX names the containers it starts (default kiri-aa-probe);
# PROBE_ONLY is an extended regular expression of the probes to run.
#
# Exits non-zero when Kiri's result differs from Docker's (beyond STRICTER).
set -u
cd "$(dirname "$0")" || exit 1
KIRI_HOST=${KIRI_HOST:?set KIRI_HOST to the Kiri engine socket (unix:///...)}
if [ -z "${REF_HOST+x}" ]; then
  REF_HOST=; [ -S /var/run/docker.sock ] && REF_HOST=unix:///var/run/docker.sock
fi
PREFIX=${PROBE_PREFIX:-kiri-aa-probe}
ONLY=${PROBE_ONLY:-.}
IMG=alpine:3.21
# shellcheck source=SCRIPTDIR/lib/images.sh
. lib/images.sh

# Lines where Kiri is deliberately stricter than Docker: Kiri's profile
# refuses umount, which would take away a masked or read-only path the
# engine put in place (with CAP_SYS_ADMIN, `umount /proc/kcore` uncovers
# the real file; the profile refuses reading it all the same).
STRICTER=" sa-umount-kcore sa-umount-proc-sys "
# Lines both engines refuse, by different layers: with CAP_SYS_ADMIN,
# Docker's seccomp filter refuses pivot_root (EPERM) and Kiri's lets it
# through to the profile, which refuses it (EACCES).
BOTH_REFUSE=" sa-pivot-root "

# name @@ docker run options @@ command (busybox sh, as root)
PROBES=$(cat <<'EOF'
label @@  @@ cat /proc/self/attr/current
label-user @@ --user 1000 @@ cat /proc/self/attr/current
label-nnp @@ --security-opt no-new-privileges @@ cat /proc/self/attr/current
label-init @@ --init @@ cat /proc/1/attr/current; echo; cat /proc/self/attr/current
label-privileged @@ --privileged @@ cat /proc/self/attr/current
label-unconfined @@ --security-opt apparmor=unconfined @@ cat /proc/self/attr/current
label-privileged-named @@ --privileged --security-opt apparmor=@DEFAULT@ @@ cat /proc/self/attr/current
label-named-missing @@ --security-opt apparmor=kiri-no-such-profile @@ cat /proc/self/attr/current
file-write @@  @@ echo x > /tmp/f && cat /tmp/f >/dev/null
rootfs-write @@  @@ mkdir -p /opt/a && touch /opt/a/b && rm -r /opt/a
chown @@  @@ touch /tmp/c && chown 123:45 /tmp/c
mknod @@  @@ mknod /tmp/n c 1 3
dev-null @@  @@ dd if=/dev/zero of=/dev/null bs=1k count=1 2>/dev/null
ping-loopback @@  @@ ping -c1 -W1 127.0.0.1 >/dev/null
tcp-loopback @@  @@ wget -q -T 2 -O /dev/null http://127.0.0.1:1/
signal-own @@  @@ sleep 5 & kill $!
ps @@  @@ ps >/dev/null
environ-own @@  @@ cat /proc/1/environ >/dev/null
oom-score-adj @@  @@ echo 500 > /proc/self/oom_score_adj
sysrq-trigger @@  @@ echo h > /proc/sysrq-trigger
kcore @@  @@ head -c1 /proc/kcore >/dev/null
kmem @@  @@ head -c1 /proc/kmem >/dev/null
proc-mem @@  @@ head -c1 /proc/mem >/dev/null
kmsg @@  @@ head -c1 /proc/kmsg >/dev/null
timer-list @@  @@ head -c1 /proc/timer_list >/dev/null
sysctl-read @@  @@ cat /proc/sys/kernel/ostype >/dev/null
sysctl-write @@  @@ echo 0 > /proc/sys/net/ipv4/ip_forward
sysctl-write-kernel @@  @@ echo 1 > /proc/sys/kernel/sysrq
sys-firmware @@  @@ ls /sys/firmware >/dev/null
sys-security @@  @@ ls /sys/kernel/security/apparmor >/dev/null
sys-write @@  @@ echo 0 > /sys/kernel/mm/ksm/run
cgroup-write @@  @@ echo 1 > /sys/fs/cgroup/cgroup.freeze
powercap @@  @@ ls /sys/devices/virtual/powercap >/dev/null
attr-exec-unconfined @@  @@ printf 'exec unconfined' > /proc/self/attr/apparmor/exec
attr-change-unconfined @@  @@ printf 'changeprofile unconfined' > /proc/self/attr/apparmor/current
attr-legacy-change @@  @@ printf 'changeprofile unconfined' > /proc/self/attr/current
mount-nocap @@  @@ mount -t tmpfs none /mnt
unshare-user-default @@  @@ unshare -U true
sa-mount-tmpfs @@ --cap-add SYS_ADMIN @@ mount -t tmpfs none /mnt
sa-mount-bind @@ --cap-add SYS_ADMIN @@ mount --bind /etc /mnt
sa-remount-proc-sys @@ --cap-add SYS_ADMIN @@ mount -o remount,rw /proc/sys
sa-remount-root @@ --cap-add SYS_ADMIN @@ mount -o remount,ro /
sa-mount-proc @@ --cap-add SYS_ADMIN @@ mount -t proc proc /mnt
sa-mount-sysfs @@ --cap-add SYS_ADMIN @@ mount -t sysfs sysfs /mnt
sa-mount-securityfs @@ --cap-add SYS_ADMIN @@ mount -t securityfs none /mnt
sa-mount-cgroup2 @@ --cap-add SYS_ADMIN @@ mount -t cgroup2 none /mnt
sa-umount-kcore @@ --cap-add SYS_ADMIN @@ umount /proc/kcore
sa-umount-proc-sys @@ --cap-add SYS_ADMIN @@ umount /proc/sys
sa-kcore-after-umount @@ --cap-add SYS_ADMIN @@ umount /proc/kcore 2>/dev/null; head -c1 /proc/kcore >/dev/null
sa-pivot-root @@ --cap-add SYS_ADMIN @@ cd / && pivot_root . mnt
sa-unshare-mount @@ --cap-add SYS_ADMIN @@ unshare -m true
sa-unshare-mount-then-mount @@ --cap-add SYS_ADMIN @@ unshare -m mount -t tmpfs none /mnt
sa-hostname @@ --cap-add SYS_ADMIN @@ hostname kiri-probe
sa-unshare-user @@ --cap-add SYS_ADMIN @@ unshare -U -r id -u
sa-sysrq-trigger @@ --cap-add SYS_ADMIN @@ echo h > /proc/sysrq-trigger
sa-policy-load @@ --cap-add SYS_ADMIN --cap-add MAC_ADMIN @@ mount -t securityfs none /mnt && echo x > /mnt/apparmor/.load
su-unshare-user @@ --cap-add SYS_ADMIN --security-opt seccomp=unconfined @@ unshare -U -r id -u
su-mount-tmpfs @@ --cap-add SYS_ADMIN --security-opt seccomp=unconfined @@ mount -t tmpfs none /mnt
nu-unshare-user @@ --security-opt seccomp=unconfined @@ unshare -U -r id -u
nu-userns-mount @@ --security-opt seccomp=unconfined @@ unshare -U -r -m mount -t tmpfs none /mnt
nu-userns-proc-write @@ --security-opt seccomp=unconfined @@ unshare -U -r sh -c 'echo h > /proc/sysrq-trigger'
pt-environ @@ --cap-add SYS_PTRACE @@ sleep 5 & sleep 0.1; cat /proc/$!/environ >/dev/null
pt-fd @@ --cap-add SYS_PTRACE @@ sleep 5 & sleep 0.1; ls /proc/$!/fd >/dev/null
ph-signal-host-init @@ --pid host @@ kill -0 1
ph-environ-host-init @@ --pid host @@ cat /proc/1/environ >/dev/null
ph-fd-host-init @@ --pid host @@ ls /proc/1/fd >/dev/null
ph-signal-host-process @@ --pid host @@ kill -CONT @HOSTPID@
ph-signal-other-profile @@ --pid host @@ for p in /proc/[0-9]*; do l=$(cat $p/attr/current 2>/dev/null); case "$l" in ""|unconfined|*-default*) ;; *) kill -0 ${p#/proc/}; exit;; esac; done; echo none
pv-mount-tmpfs @@ --privileged @@ mount -t tmpfs none /mnt
uc-mount-tmpfs @@ --cap-add SYS_ADMIN --security-opt apparmor=unconfined @@ mount -t tmpfs none /mnt
EOF
)

# What a probe printed, made comparable between engines: "ok" or the error,
# and a label with the engine's default profile's name made generic.
normalize() {
  local out=$1 rc=$2
  out=$(printf %s "$out" | tr -d '\r' | sed -e 's/docker-default/DEFAULT/g' -e 's/kiri-default/DEFAULT/g')
  case $out in
    *"Permission denied"*) echo EACCES ;;
    *"Operation not permitted"*) echo EPERM ;;
    *"Read-only file system"*) echo EROFS ;;
    *"No such file or directory"*) echo ENOENT ;;
    *"Invalid argument"*) echo EINVAL ;;
    *"Device or resource busy"*) echo EBUSY ;;
    *"Connection refused"*) echo ECONNREFUSED ;;
    *"I/O error"*) echo EIO ;;
    *"Bad address"*) echo EFAULT ;;
    *)
      if [ "$rc" = 0 ]; then
        out=$(printf %s "$out" | tr '\n' ' ' | sed 's/ *$//')
        echo "ok${out:+ $out}"
      else
        echo "rc=$rc $(printf %s "$out" | tail -1 | cut -c1-60)"
      fi ;;
  esac
}

# probe HOST DEFAULT NAME OPTIONS COMMAND
probe() {
  local host=$1 def=$2 name=$3 opts=$4 cmd=$5 out rc
  opts=${opts//@DEFAULT@/$def}
  cmd=${cmd//@HOSTPID@/$HOSTPID}
  # shellcheck disable=SC2086 # options are words
  out=$(DOCKER_HOST=$host timeout 60 docker run --rm --name "$PREFIX-$name" $opts "$IMG" sh -c "$cmd" 2>&1); rc=$?
  DOCKER_HOST=$host docker rm -f "$PREFIX-$name" >/dev/null 2>&1
  # A run the engine refused (not the command's own failure).
  case $out in *"Error response from daemon"*|*"docker: "*) out="refused: $(printf %s "$out" | head -1)"; echo refused; return ;; esac
  normalize "$out" "$rc"
}

# The exec and inspect lines, which a single run does not show.
extra() {
  local host=$1 name=$2 out
  case $name in
    exec-label | exec-privileged-label | inspect-profile | inspect-profile-privileged)
      local opts=; [ "$name" = inspect-profile-privileged ] && opts=--privileged
      DOCKER_HOST=$host docker rm -f "$PREFIX-x" >/dev/null 2>&1
      # shellcheck disable=SC2086
      DOCKER_HOST=$host docker run -d --name "$PREFIX-x" $opts "$IMG" sleep 30 >/dev/null 2>&1
      case $name in
        exec-label) out=$(DOCKER_HOST=$host docker exec "$PREFIX-x" cat /proc/self/attr/current 2>&1) ;;
        exec-privileged-label) out=$(DOCKER_HOST=$host docker exec --privileged "$PREFIX-x" cat /proc/self/attr/current 2>&1) ;;
        *) out=$(DOCKER_HOST=$host docker inspect -f 'profile={{.AppArmorProfile}}' "$PREFIX-x" 2>&1) ;;
      esac
      DOCKER_HOST=$host docker rm -f "$PREFIX-x" >/dev/null 2>&1
      normalize "$out" 0 ;;
    info-security)
      out=$(DOCKER_HOST=$host docker info --format '{{range .SecurityOptions}}{{.}} {{end}}' 2>&1)
      case $out in *name=apparmor*) echo "ok apparmor listed" ;; *) echo "ok apparmor not listed" ;; esac ;;
  esac
}
EXTRA="exec-label exec-privileged-label inspect-profile inspect-profile-privileged info-security"

engines="kiri"; [ -n "$REF_HOST" ] && engines="kiri docker"
for e in $engines; do
  h=$KIRI_HOST; [ "$e" = docker ] && h=$REF_HOST
  D="docker" DOCKER_HOST=$h kiri_seed_images "$IMG" >/dev/null 2>&1 || echo "apparmor-probes: $IMG could not be fetched for $e"
done

# A process of this host's, outside any container and any profile, for the
# --pid host lines to signal (SIGCONT: harmless to a sleep).
sleep 900 >/dev/null 2>&1 &
HOSTPID=$!
trap 'kill $HOSTPID 2>/dev/null' EXIT

PASS=0 FAIL=0 N=0
printf '%-30s | %-28s | %-28s | %s\n' probe kiri docker verdict
printf '%s\n' "-------------------------------|------------------------------|------------------------------|--------"
row() {
  local name=$1 k=$2 d=$3 v
  N=$((N + 1))
  if [ -z "$REF_HOST" ]; then v=-
  elif [ "$k" = "$d" ]; then v=same; PASS=$((PASS + 1))
  elif [[ "$STRICTER" == *" $name "* && ( "$k" = EACCES || "$k" = EPERM ) ]]; then v=stricter; PASS=$((PASS + 1))
  elif [[ "$BOTH_REFUSE" == *" $name "* && ( "$k" = EACCES || "$k" = EPERM ) && ( "$d" = EACCES || "$d" = EPERM ) ]]; then v="both refuse"; PASS=$((PASS + 1))
  else v=DIFFERS; FAIL=$((FAIL + 1)); fi
  printf '%-30s | %-28s | %-28s | %s\n' "$name" "$k" "${d:--}" "$v"
}
while IFS= read -r line; do
  [ -n "$line" ] || continue
  name=$(printf %s "$line" | awk -F' @@ ' '{print $1}' | tr -d ' ')
  opts=$(printf %s "$line" | awk -F' @@ ' '{print $2}')
  cmd=${line#* @@ * @@ }
  [[ "$name" =~ $ONLY ]] || continue
  k=$(probe "$KIRI_HOST" kiri-default "$name" "$opts" "$cmd")
  d=; [ -n "$REF_HOST" ] && d=$(probe "$REF_HOST" docker-default "$name" "$opts" "$cmd")
  row "$name" "$k" "$d"
done <<< "$PROBES"
for name in $EXTRA; do
  [[ "$name" =~ $ONLY ]] || continue
  k=$(extra "$KIRI_HOST" "$name")
  d=; [ -n "$REF_HOST" ] && d=$(extra "$REF_HOST" "$name")
  row "$name" "$k" "$d"
done
if [ -n "$REF_HOST" ]; then
  echo "apparmor-probes: $N probes, $PASS as Docker (or stricter on purpose), $FAIL differ"
  [ "$FAIL" = 0 ]
else
  echo "apparmor-probes: $N probes on Kiri only (no Docker to compare with)"
fi
