#!/bin/bash
#
# Forensic acquisition of a block device to OVHcloud US Object Storage (Swift).
#
#   ./split.sh /dev/sda1
#
# Reads the device with dcfldd, cuts it into chunks below the 5 GiB Swift object
# limit, compresses (gzip) then encrypts (GPG AES-256) each chunk, and uploads it
# to a dedicated Swift container.
#
# The .log file is the chain of custody: per-chunk sha256, dcfldd error log,
# sha1 of every uploaded object, sha1 of the whole device, and the scheduled
# purge date. It is re-uploaded after every part so that it survives an
# interrupted acquisition.
#
# A .state file is written next to the log after every confirmed upload. Re-run
# the same command after a disconnection and the acquisition resumes where it
# stopped -- from a fresh screen session, no need to source anything.
#
# RETENTION: every object is stamped with an expiration date. The definitive
# value is "preservation completion date + 1 year"; override the window with
# RETENTION_SECONDS.
#
# Prerequisites: source your openrc.sh first, and run inside screen.

set -o pipefail

# ---------------------------------------------------------------- configuration

# Retention window applied to every stored object (default 365 days).
RETENTION_SECONDS=${RETENTION_SECONDS:-31536000}

# Chunk size in bytes. Must stay below the 5 GiB (5368709120 B) Swift object
# limit once gzip overhead on incompressible data and GPG framing are added.
# Left unset, it is reduced automatically to fit the staging area -- on a rescue
# system that area is a RAM disk. Set it explicitly to pin it.
if [ -n "${CHUNKSIZE_BYTES:-}" ]; then CHUNKSIZE_EXPLICIT=1; else CHUNKSIZE_EXPLICIT=0; fi
CHUNKSIZE_BYTES=${CHUNKSIZE_BYTES:-$(( 5000 * 1024 * 1024 ))}
# autosize_chunk() mutates CHUNKSIZE_BYTES to fit the staging area. With several
# devices in one run each one must be sized from the same starting point, not
# from whatever the previous device was reduced to.
CHUNKSIZE_ORIG=$CHUNKSIZE_BYTES

# Block size for dcfldd in bytes.
BS=$(( 4 * 1024 ))

# rclone remote name, configured from the environment (openrc.sh).
SNAME=myremote

# Absolute path to this script, so it can re-exec itself inside screen.
SELF=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/$(basename -- "${BASH_SOURCE[0]}")

# Name of the screen session started automatically when not already in one.
SCREEN_NAME=${SCREEN_NAME:-split}

# -------------------------------------------------------------------- helpers

LOGFILE=""

_ts() { date "+%Y/%m/%d %H:%M:%S"; }

log() {
    printf '%s %s\n' "$(_ts)" "$*"
    [ -n "$LOGFILE" ] && printf '%s %s\n' "$(_ts)" "$*" >> "$LOGFILE"
    return 0
}

warn() { log "WARNING: $*" >&2; }

die() {
    printf '%s ERROR: %s\n' "$(_ts)" "$*" >&2
    [ -n "$LOGFILE" ] && printf '%s ERROR: %s\n' "$(_ts)" "$*" >> "$LOGFILE"
    exit 1
}

# retry <attempts> <command...>
retry() {
    local attempts="$1" n=1 delay=5
    shift
    while true; do
        if "$@"; then return 0; fi
        if [ "$n" -ge "$attempts" ]; then
            warn "command failed after $n attempts: $*"
            return 1
        fi
        warn "attempt $n/$attempts failed, retrying in ${delay}s: $*"
        sleep "$delay"
        n=$(( n + 1 ))
        delay=$(( delay * 2 ))
    done
}

human_date() { date -u -d "@$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || printf 'epoch %s' "$1"; }

key_fingerprint() { printf '%s' "$1" | sha256sum | cut -c1-16; }

# ------------------------------------------------------------------ dependencies

# Every external command the script relies on, with the Debian package that
# provides it. A rescue system is minimal: assume nothing is present, including
# screen, awk, util-linux or gzip. Keep this table in sync with the code.
DEPS=(
    "rclone:rclone"
    "swift:python3-swiftclient"
    "python3:python3"
    "dcfldd:dcfldd"
    "gpg:gnupg"
    "jq:jq"
    "curl:curl"
    "screen:screen"
    "gzip:gzip"
    "openssl:openssl"
    "colrm:bsdextrautils"
    "awk:mawk"
    "grep:grep"
    "lsblk:util-linux"
    "blockdev:util-linux"
    "blkid:util-linux"
    "flock:util-linux"
    "fdisk:fdisk"
    "hostname:hostname"
    "sha1sum:coreutils"
    "sha256sum:coreutils"
    "df:coreutils"
    "basename:coreutils"
)

# Python modules the swift client needs for Keystone v2/v3 auth. These are
# LIBRARIES, not commands: `command -v swift` succeeds while the client is still
# unable to authenticate. A rescue system runs from a RAM disk, so whatever was
# installed during an earlier session is gone after a reboot -- this has to be
# re-checked on every run.
PYDEPS=(
    "keystoneclient:python3-keystoneclient"
)

# Wanted, but the run goes ahead without them. pigz is a parallel gzip producing
# a byte-compatible stream, so `gunzip` on the analyst's side is unaffected --
# measured on a 6-core EPYC: 67 MB/s with gzip against 241 MB/s with pigz through
# the same dcfldd pipeline, for the same compression ratio.
OPTDEPS=(
    "pigz:pigz"
)

# Selected by init_compressor() once the dependency pass has run.
COMPRESSOR=(gzip -4)

check_dependencies() {
    printf 'Dependency verification: '
    local entry cmd pkg mod missing=""
    local -a needed=() pkgs=()

    for entry in "${DEPS[@]}"; do
        cmd="${entry%%:*}"; pkg="${entry#*:}"
        command -v "$cmd" >/dev/null 2>&1 || needed+=("$pkg")
    done

    for entry in "${PYDEPS[@]}"; do
        mod="${entry%%:*}"; pkg="${entry#*:}"
        python3 -c "import $mod" >/dev/null 2>&1 || needed+=("$pkg")
    done

    # Asked for in the same apt pass, but never required afterwards.
    for entry in "${OPTDEPS[@]}"; do
        cmd="${entry%%:*}"; pkg="${entry#*:}"
        command -v "$cmd" >/dev/null 2>&1 || needed+=("$pkg")
    done

    # One apt pass for everything missing: fewer round trips, and
    # DEBIAN_FRONTEND keeps it from ever stopping on a prompt.
    if [ "${#needed[@]}" -gt 0 ]; then
        mapfile -t pkgs < <(printf '%s\n' "${needed[@]}" | sort -u)
        printf '\nInstalling: %s\n' "${pkgs[*]}"
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1 \
                || printf 'apt-get reported an error, checking what is usable anyway\n'
        else
            printf 'no apt-get on this system -- install manually: %s\n' "${pkgs[*]}"
        fi
    fi

    # rclone: absent, or present but too old to be usable.
    #
    # Debian 10 -- which is what the production rescue image boots -- ships
    # 1.45, predating both --header-upload (1.50) and --disable-http2 (1.51).
    # Without the first, objects cannot be stamped with their expiration as
    # they are stored; without the second, a single upload is capped at the
    # HTTP/2 per-stream window, about 1 MiB/s over a 60 ms link, a factor of
    # fourteen. Neither is worth living with when the rescue filesystem is a RAM
    # disk: installing a current rclone costs nothing and the next reboot undoes
    # it. The old one stays in place if the upstream installer cannot run.
    local rclone_why="" rclone_flags=""
    if ! command -v rclone >/dev/null 2>&1; then
        rclone_why="it is not installed"
    else
        # Captured into a variable, then matched. Piping straight into `grep -q`
        # is wrong under `set -o pipefail`: grep exits the moment it matches,
        # rclone takes a SIGPIPE and dies non-zero, and pipefail reports the
        # whole pipeline as failed *because* the flag was found. It produced the
        # self-contradicting "rclone v1.75.1 predates --header-upload" and a
        # pointless re-download on every single acquisition.
        rclone_flags=$(rclone help flags 2>/dev/null)
        if ! grep -q -- '--header-upload' <<< "$rclone_flags"; then
            rclone_why="$(rclone version 2>/dev/null | head -n 1) predates --header-upload"
        fi
    fi
    if [ -n "$rclone_why" ] && command -v curl >/dev/null 2>&1; then
        printf 'Installing a current rclone from rclone.org (%s)...\n' "$rclone_why"
        curl -s https://rclone.org/install.sh | bash >/dev/null 2>&1
        if command -v rclone >/dev/null 2>&1; then
            printf 'rclone is now: %s\n' "$(rclone version 2>/dev/null | head -n 1)"
        fi
    fi

    for entry in "${DEPS[@]}"; do
        cmd="${entry%%:*}"
        command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
    done
    for entry in "${PYDEPS[@]}"; do
        mod="${entry%%:*}"; pkg="${entry#*:}"
        python3 -c "import $mod" >/dev/null 2>&1 || missing="$missing $pkg"
    done
    if [ -n "$missing" ]; then
        printf '\n'
        die "still missing after installation:$missing
Install them by hand, then rerun. rclone: https://rclone.org/install/"
    fi
    printf 'dependencies met!\n'
}

# gzip is single-threaded and, on real (incompressible) data, the slowest stage
# of the whole acquisition -- 67 MB/s measured through the dcfldd pipeline on a
# 6-core EPYC, against 241 MB/s with pigz for the same output size. On a 894 GiB
# disk that is hours of extra downtime for the customer whose server is offline.
#
# pigz output is an ordinary gzip stream: `gunzip` reads it unchanged, so
# unsplit.sh and the analyst's retrieval script need no change. Verified by
# round-trip against the source sha1.
init_compressor() {
    if command -v pigz >/dev/null 2>&1; then
        COMPRESSOR=(pigz -4)
        log "compressing with pigz on $(nproc 2>/dev/null || echo '?') threads"
    else
        COMPRESSOR=(gzip -4)
        warn "pigz is not available -- falling back to single-threaded gzip.
That is roughly 3.6x slower on real data, which on a large disk means hours more
downtime. Install it with: apt-get install -y pigz"
    fi
}

# Every `swift` and every `rclone` invocation authenticates against Keystone from
# scratch, and an acquisition makes thousands of them -- three per object in the
# finalisation alone. Measured on a 347-part disk that is roughly 2800 token
# requests per device, and Keystone starts answering:
#
#   Authorization Failure. Authorization failed: HTTP Client Error (HTTP 429)
#
# which killed the finalisation of a completed two-hour acquisition and made the
# test suite intermittently red for no reason of its own.
#
# So authenticate ONCE and hand both clients the result. `swift auth` prints the
# storage URL and a token; with those in the environment neither client contacts
# Keystone again. Tokens expire, so it is refreshed on a timer -- one request
# every SWIFT_TOKEN_TTL rather than one per operation.
SWIFT_TOKEN_TS=0
SWIFT_TOKEN_TTL=${SWIFT_TOKEN_TTL:-1800}

refresh_swift_token() {
    local now auth
    now=$(date +%s)
    if [ "${1:-}" != "force" ] && [ "$SWIFT_TOKEN_TS" -gt 0 ] \
       && [ $(( now - SWIFT_TOKEN_TS )) -lt "$SWIFT_TOKEN_TTL" ]; then
        return 0
    fi
    # Cleared on the way in: with a token already in the environment, `swift
    # auth` hands back that same token instead of asking Keystone for a fresh
    # one, and the refresh would silently never renew anything.
    auth=$(env -u OS_AUTH_TOKEN -u OS_STORAGE_URL swift auth 2>/dev/null) || return 1
    eval "$auth" || return 1
    [ -n "${OS_STORAGE_URL:-}" ] && [ -n "${OS_AUTH_TOKEN:-}" ] || return 1
    export OS_STORAGE_URL OS_AUTH_TOKEN
    export RCLONE_CONFIG_MYREMOTE_STORAGE_URL="$OS_STORAGE_URL"
    export RCLONE_CONFIG_MYREMOTE_AUTH_TOKEN="$OS_AUTH_TOKEN"
    SWIFT_TOKEN_TS="$now"
    return 0
}

# Fail in two seconds with the real reason, rather than after the pre-flight with
# a guess. Deliberately run BEFORE check_screen, so the message lands in the
# operator's own terminal instead of a screen session that is about to close.
check_swift_auth() {
    local err
    if refresh_swift_token force && swift stat >/dev/null 2>&1; then
        log "authenticated once; both clients will reuse the token (refreshed every $(( SWIFT_TOKEN_TTL / 60 )) min)"
        return 0
    fi
    err=$(env -u OS_AUTH_TOKEN -u OS_STORAGE_URL swift stat 2>&1 >/dev/null)
    die "cannot authenticate against Swift:

$err
Check that you sourced your openrc.sh (OS_AUTH_URL, OS_USERNAME, OS_PASSWORD,
OS_TENANT_ID...) in THIS shell, and that Keystone v3 support is installed:
  apt-get install -y python3-keystoneclient"
}

# gpg >= 2.1 needs --pinentry-mode loopback to accept a passphrase on a file
# descriptor; gpg 1.x does not know the option.
GPG_OPTS=(--yes --batch --passphrase-fd 3)
init_gpg_opts() {
    local opts
    # A here-string, not a pipe. Under `set -o pipefail`, `gpg --dump-options |
    # grep -q` reports failure precisely WHEN the option is found: grep exits on
    # the match, gpg dies of SIGPIPE, and pipefail surfaces gpg's status. The
    # flag was therefore never added -- acquisitions only kept working because
    # gpg 2.2 tolerates --passphrase-fd with --batch on its own.
    opts=$(gpg --dump-options 2>/dev/null)
    if grep -q -- '--pinentry-mode' <<< "$opts"; then
        GPG_OPTS+=(--pinentry-mode loopback)
    fi
}

# -------------------------------------------------------------------- pre-flight

# Not in screen? Start one and re-exec into it, rather than telling the operator
# to do it by hand. An acquisition runs for hours: losing it to a dropped SSH
# session is the failure this guard exists to prevent.
check_screen() {
    [ -n "${STY:-}" ] && return 0

    if [ "${SPLIT_NO_SCREEN:-0}" = "1" ]; then
        printf 'WARNING: running outside screen -- a disconnection will abort the acquisition\n' >&2
        return 0
    fi

    command -v screen >/dev/null 2>&1 || die "screen is missing and could not be installed.
Install it, or set SPLIT_NO_SCREEN=1 to run without it -- a disconnection then
aborts the acquisition."

    # screen needs a terminal to attach to; without one, say how to detach.
    if [ ! -t 0 ]; then
        die "not a screen session, and no terminal to start one.
Detached:       screen -dmS $SCREEN_NAME bash $SELF $*
Without screen: SPLIT_NO_SCREEN=1 bash $SELF $*"
    fi

    printf 'Not in a screen session -- restarting inside "screen -S %s"\n' "$SCREEN_NAME"
    # Marks the child so it holds the session open at the end: the encryption key
    # is printed on the terminal and stored nowhere else.
    export SPLIT_OWNS_SCREEN=1
    # Invoked through bash on purpose: a script that was just copied onto a
    # rescue system often lost its executable bit.
    exec screen -S "$SCREEN_NAME" bash "$SELF" "$@"
}

# When we started the screen session ourselves, closing it on exit would wipe the
# encryption key off the operator's terminal before it could be copied.
pause_before_close() {
    [ "${SPLIT_OWNS_SCREEN:-0}" = "1" ] || return 0
    [ -t 0 ] || return 0
    printf '\n-- this screen session was started automatically --\n' >&2
    # Only mention the key when one was actually produced: a run that stopped in
    # pre-flight has none, and telling the operator to copy it sends them hunting
    # for something that does not exist.
    if [ "${KEY_SHOWN:-0}" = "1" ]; then
        printf 'Copy the encryption key above FIRST (it is stored nowhere else),\n' >&2
        printf 'then press Enter to close.\n' >&2
    else
        printf 'No encryption key was generated: the run stopped before that point.\n' >&2
        printf 'Read the message above, then press Enter to close.\n' >&2
    fi
    read -r _ || true
}

# A RAID1 serves each read from EITHER member. If the two halves have diverged,
# reading the assembled array is not reproducible -- and the acquired image can
# mix sectors from both, matching neither member. Observed in the field on an
# OVH EFI partition (metadata 0.90): `sha1sum /dev/md1` alternated between two
# values, which turned out to be the sha1 of each half.
#
# So the array is sampled at three offsets. A difference is conclusive and gets a
# loud warning; agreement proves nothing about the rest, so the generic caution
# is printed either way. Detecting divergence properly means reading both members
# in full, which costs as much as the acquisition itself -- that is what
# `mdadm --action=check` is for, and the operator is pointed at it.
check_md_mirrors() {
    local name level members=() m off count=0 first="" this
    # The KERNEL name, not the path the operator typed. mdadm routinely creates
    # /dev/md/<name> symlinks, and basename on one of those yields something
    # absent from /sys/block -- which made this whole check skip itself in
    # silence, on exactly the arrays it exists to warn about.
    name=$(lsblk -ndo KNAME "$FILE" 2>/dev/null | head -n 1)
    [ -n "$name" ] || name=$(basename "$(readlink -f "$FILE")")
    [ -d "/sys/block/$name/md" ] || return 0

    level=$(cat "/sys/block/$name/md/level" 2>/dev/null)
    case "$level" in raid1) ;; *) return 0 ;; esac

    for m in "/sys/block/$name/md/dev-"*; do
        [ -d "$m" ] || continue
        members+=("/dev/$(basename "$m" | sed 's/^dev-//')")
    done
    [ "${#members[@]}" -ge 2 ] || return 0

    warn "$FILE is a RAID1 array: every read is served from one member or the other.
If its halves have diverged, this acquisition is not reproducible and the image
may mix both. Consider acquiring the members separately instead:
  ${members[*]}
To find out first -- 'check' only READS both halves and counts:
  mdadm --action=check $FILE   then   cat /sys/block/$name/md/mismatch_cnt
That counter reads 0 until a check has completed, so 0 alone proves nothing.
NEVER run --action=repair on evidence: it writes one member over the other."

    for off in 0 64 128; do
        first=""
        for m in "${members[@]}"; do
            this=$(dd if="$m" bs=1M skip="$off" count=4 2>/dev/null | sha1sum | cut -d' ' -f1)
            if [ -z "$first" ]; then first="$this"
            elif [ "$this" != "$first" ]; then count=$(( count + 1 )); break
            fi
        done
    done

    if [ "$count" -gt 0 ]; then
        warn "THE MIRRORS OF $FILE DIFFER -- sampling found a mismatch in $count of 3 windows.
Reading $FILE gives whichever half the kernel picks, so the image below is NOT a
faithful copy of either member and its hash will not be reproducible. Acquire
${members[*]} individually instead."
    fi
    return 0
}

check_device() {
    [ -b "$FILE" ] || die "$FILE is not a block device"
    check_md_mirrors

    local workdev
    workdev=$(df -P . 2>/dev/null | awk 'NR==2 {print $1}')

    if [ "$workdev" = "$FILE" ]; then
        die "the working directory lives on $FILE, the very device being acquired -- cd to another filesystem first (writing here would alter the evidence)"
    fi

    local devdisk workdisk
    devdisk=$(lsblk -no PKNAME "$FILE" 2>/dev/null | head -n 1)
    workdisk=$(lsblk -no PKNAME "$workdev" 2>/dev/null | head -n 1)
    if [ -n "$devdisk" ] && [ "$devdisk" = "$workdisk" ]; then
        warn "working directory is on the same physical disk ($devdisk) as the acquired device: throughput will be halved"
    fi
}

# A rescue system drops the operator in /root, whose rootfs df cannot measure.
# Refusing to start there would mean typing `cd /tmp` before every single
# acquisition, so move there instead. The choice is deterministic -- same
# candidate order every run -- so that a resume launched from /root again lands
# in the same place and finds its state file.
#
# Runs BEFORE check_device, which must judge the directory we actually use.
select_workdir() {
    local avail candidate previous
    avail=$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -n "$avail" ] && [ "$avail" -gt 0 ] 2>/dev/null; then
        return 0
    fi

    previous=$(pwd)
    for candidate in "${SPLIT_WORKDIR:-}" /tmp /var/tmp /dev/shm; do
        [ -n "$candidate" ] || continue
        [ -d "$candidate" ] || continue
        [ -w "$candidate" ] || continue
        avail=$(df -Pk "$candidate" 2>/dev/null | awk 'NR==2 {print $4}')
        # Not a number means df could not measure it either.
        case "$avail" in ''|*[!0-9]*) continue ;; esac
        [ "$avail" -gt 0 ] || continue
        cd "$candidate" || continue
        printf '\n'
        log "staging in $candidate -- df cannot measure $previous (a rescue RAM disk)"
        log "the log and the state file are written to $candidate, NOT to $previous"
        printf '\n'
        return 0
    done

    die "cannot measure free space in $previous, and no usable fallback found.
Set SPLIT_WORKDIR to a directory on a filesystem df can measure, then rerun."
}

check_free_space() {
    local avail_kb need_kb
    avail_kb=$(df -Pk . | awk 'NR==2 {print $4}')
    # gzip + gpg copies of one chunk coexist briefly, hence 2x -- and once per
    # device being acquired concurrently, since they share this filesystem. On a
    # rescue system that filesystem is RAM, so over-committing it is an OOM, not
    # a disk-full message.
    # What this iteration is about to ADD: the gzip and the gpg copy of the part
    # being produced. Not the whole working set.
    #
    # Asking for the full budget here double-counts: the chunks still in flight
    # are already on this filesystem, so they have been subtracted from the
    # measured free space AND counted again in the requirement. That is exactly
    # how a real acquisition died -- 16 GB of staging, one 4.3 GiB part in
    # flight, 11.4 GB left, and a demand for 15 GB. Sizing the chunk so the
    # whole working set fits is autosize_chunk's job, done once, up front.
    need_kb=$(( 2 * CHUNKSIZE_BYTES / 1024 ))

    if [ -z "$avail_kb" ] || [ "$avail_kb" -eq 0 ] 2>/dev/null; then
        die "cannot measure free space in $(pwd) -- df reports none.
Set SPLIT_WORKDIR to a directory on a filesystem df can measure, then rerun."
    fi

    if [ "$avail_kb" -lt "$need_kb" ]; then
        die "not enough free space in $(pwd): $(( avail_kb / 1024 )) MB available, $(( need_kb / 1024 )) MB required.
Lower the chunk size, e.g.  export CHUNKSIZE_BYTES=\$((512 * 1024 * 1024))"
    fi
}

# The staging area holds a gzip and a gpg copy of the current chunk at once. On a
# rescue system that area is RAM, and the machine being seized may have far less
# of it than this one. Shrink the chunk to fit instead of refusing to start --
# unless the operator pinned CHUNKSIZE_BYTES, in which case their value stands.
#
# Called ONCE, before the geometry is derived: changing the chunk size later
# would renumber the parts mid-acquisition.
autosize_chunk() {
    local avail_kb avail_bytes target fstype mem_kb
    [ "$CHUNKSIZE_EXPLICIT" = "1" ] && return 0

    avail_kb=$(df -Pk . | awk 'NR==2 {print $4}')
    [ -n "$avail_kb" ] && [ "$avail_kb" -gt 0 ] 2>/dev/null || return 0

    # Staging on a tmpfs -- always the case in rescue -- spends RAM, and df
    # reports the tmpfs size limit rather than the memory actually free. A
    # machine whose tmpfs limit exceeds its free memory would otherwise be
    # allowed a chunk it cannot hold, and the acquisition would die on OOM
    # instead of on a clear message. Budget against whichever is smaller.
    fstype=$(df -PT . 2>/dev/null | awk 'NR==2 {print $2}')
    case "$fstype" in
        tmpfs|ramfs)
            mem_kb=$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo 2>/dev/null)
            if [ -n "$mem_kb" ] && [ "$mem_kb" -gt 0 ] 2>/dev/null \
               && [ "$mem_kb" -lt "$avail_kb" ]; then
                log "staging on $fstype: budgeting against $(( mem_kb / 1024 )) MB of free memory, not the $(( avail_kb / 1024 )) MB the filesystem advertises"
                avail_kb="$mem_kb"
            fi
            ;;
    esac

    avail_bytes=$(( avail_kb * 1024 ))
    # Concurrent devices share the staging area, so each gets its own slice.
    # Slots: the gzip and gpg copies of the part being produced, one per upload
    # still in flight, and one of slack for the log, the state file and the OS
    # to breathe.
    #
    # The same figure is used to decide whether to resize and to compute the new
    # size. They used to differ by one slot, so a chunk could be accepted with
    # no slack at all -- 5000 MiB kept on a 16 GB tmpfs because 3 x 5000 fits,
    # and then the acquisition ran out on its second part.
    local slots=$(( UPLOAD_PARALLEL + 3 ))
    local budget=$(( avail_bytes / PARALLEL_DEVICES ))
    [ $(( slots * CHUNKSIZE_BYTES )) -le "$budget" ] && return 0

    target=$(( budget / slots ))
    target=$(( target - (target % BS) ))
    if [ "$target" -lt $(( 256 * 1024 * 1024 )) ]; then
        die "only $(( budget / 1024 / 1024 )) MB usable in $(pwd) for this device -- not enough to stage even a 256 MB chunk.
$( [ "$PARALLEL_DEVICES" -gt 1 ] && printf 'Lower --parallel, or w' || printf 'W' )ork from a larger filesystem, or free memory on this rescue system."
    fi

    log "chunk size reduced to $(( target / 1024 / 1024 )) MiB to fit the $(( budget / 1024 / 1024 )) MB this device may use in $(pwd)"
    CHUNKSIZE_BYTES="$target"
}

# ------------------------------------------------------- whole-device hash
#
# The hash the chain of custody is verified against later, by re-reading the
# original. Every mainstream forensic imager records one (E01, AFF4), alongside
# per-block hashes rather than instead of them, so it is not something to drop.
#
# It used to be `sha1sum "$FILE" &` -- a SECOND complete read of the device,
# racing the acquisition for bandwidth. On a 894 GiB disk that is hours of extra
# downtime for a customer whose server is offline.
#
# Instead the plaintext already flowing out of dcfldd is teed into one long-lived
# sha1sum. sha1 runs at ~2 GB/s with SHA-NI while the pipeline caps at 241 MB/s,
# so it costs nothing measurable and the device is read exactly once.
#
# Two cases fall back to the separate read, because the in-pass stream would not
# equal the device:
#   - a resume, since the stream covers only the chunks cut in THIS invocation;
#   - a device whose size is not a multiple of the block size, where dcfldd's
#     conv=sync pads the final chunk and the stream is longer than the device.
DEVSHA_FIFO=""
DEVSHA_PID=""
DEVSHA_MODE="background"
DEVSHA_SINK="/dev/null"

start_device_hash() {
    DEVSHA_FIFO=""; DEVSHA_PID=""; DEVSHA_SINK="/dev/null"
    rm -f "$OUTPUT.device.sha1"

    # A finalisation-only resume already has it: the run that read the device
    # wrote it to the log. Re-reading 894 GiB to recompute a hash that is
    # sitting three lines up is pure downtime on a seized machine.
    if [ "$FINALISE_ONLY" -eq 1 ] \
       && grep -qa 'whole-device sha1:' "$LOGFILE" 2>/dev/null; then
        DEVSHA_MODE="already"
        log "the whole-device sha1 is already recorded in $LOGFILE -- not re-reading $FILE"
        return 0
    fi

    if [ "$RESUME_PART" -eq 0 ] && [ $(( FSIZE % BS )) -eq 0 ]; then
        DEVSHA_FIFO=$(mktemp -u "${TMPDIR:-/tmp}/devsha.XXXXXX")
        if mkfifo -m 600 "$DEVSHA_FIFO" 2>/dev/null; then
            sha1sum > "$OUTPUT.device.sha1" < "$DEVSHA_FIFO" &
            DEVSHA_PID=$!
            # Held open by us so the hash does not see EOF between chunks.
            exec 7> "$DEVSHA_FIFO"
            DEVSHA_MODE="inpass"
            DEVSHA_SINK="$DEVSHA_FIFO"
            log "device hash computed in the same pass -- the device is read once"
            return 0
        fi
        warn "cannot create the hash pipe; falling back to a separate read of $FILE"
    elif [ "$RESUME_PART" -ne 0 ]; then
        log "resuming, so the device hash needs its own read of $FILE"
    else
        log "$FILE is not a multiple of $BS bytes, so the device hash needs its own read"
    fi

    DEVSHA_MODE="background"
    sha1sum "$FILE" > "$OUTPUT.device.sha1" 2>/dev/null &
    DEVSHA_PID=$!
    return 0
}

finish_device_hash() {
    [ "$DEVSHA_MODE" = "already" ] && return 0
    if [ "$DEVSHA_MODE" = "inpass" ]; then
        exec 7>&-          # the hash sees EOF and finishes
    fi
    [ -n "$DEVSHA_PID" ] && wait "$DEVSHA_PID" 2>/dev/null
    [ -n "$DEVSHA_FIFO" ] && rm -f "$DEVSHA_FIFO"
    return 0
}

setup_rclone() {
    export RCLONE_CONFIG_MYREMOTE_TYPE=swift
    export RCLONE_CONFIG_MYREMOTE_ENV_AUTH=true

    # HTTP/2 caps ONE upload at 65535 bytes in flight -- the protocol's default
    # per-stream flow-control window, which neither rclone's Go stack nor curl
    # ever grows. Over a 61 ms RTT (a server in US-EAST-VA writing to Swift in
    # US-WEST-OR) that is 65535/0.0614 = 1.02 MiB/s, and it is exactly the
    # ~1 MiB/s every acquisition has been stuck at. Measured on that path, same
    # host, same second, 32 MiB: 39.1 s over HTTP/2, 2.7 s over HTTP/1.1 -- a
    # factor of 14.6. python-swiftclient looked "fast" for the sole reason that
    # it only speaks HTTP/1.1.
    #
    # The env form covers every rclone call, including the lsjson a resume
    # depends on, so no call site can be forgotten.
    #
    # Probed, not assumed: --disable-http2 arrived in rclone 1.51, and an older
    # rescue image ships older rclone -- Debian 10 has 1.45. Setting an option
    # that build does not know would fail every single upload, which is a far
    # worse outcome than a slow one.
    local rclone_flags
    rclone_flags=$(rclone help flags 2>/dev/null)

    if grep -q -- '--disable-http2' <<< "$rclone_flags"; then
        export RCLONE_DISABLE_HTTP2=true
    else
        unset RCLONE_DISABLE_HTTP2
        warn "this rclone has no --disable-http2 ($(rclone version 2>/dev/null | head -n 1)).
Uploads will use HTTP/2, whose 65535-byte per-stream window caps one transfer at
65535/RTT -- about 1 MiB/s over a 60 ms link. Acceptable in-region; painful
across the country. A newer rclone fixes it:  curl https://rclone.org/install.sh | bash"
    fi

    # --header-upload arrived in rclone 1.50; Debian 10 ships 1.45, where
    # passing it fails every single upload. Without it the object lands with no
    # expiration and enforce_object_expiry stamps it a second later, so the
    # window in which evidence sits unexpired is seconds rather than never --
    # worth saying out loud, and far better than not storing it at all.
    if grep -q -- '--header-upload' <<< "$rclone_flags"; then
        RCLONE_HAS_HEADER_UPLOAD=1
    else
        RCLONE_HAS_HEADER_UPLOAD=0
        warn "this rclone has no --header-upload, so objects cannot carry their
expiration from the moment they are stored. Each one is stamped immediately
after upload instead; the gap is a second or two per object, not none."
    fi

    mkdir -p ~/.config/rclone/ && touch ~/.config/rclone/rclone.conf
    SWIFT="${SNAME}:${CONTAINER}"
}

# ------------------------------------------------------------ object storage I/O

# Echo the X-Delete-At epoch carried by object $1, empty if none.
object_expiry() {
    swift stat "$CONTAINER" "$1" 2>/dev/null \
        | awk -F':' '/[Xx]-[Dd]elete-[Aa]t/ { gsub(/[ \t]/, "", $2); print $2; exit }'
}

# Make sure object $1 carries expiration $2, stamping it if rclone did not.
#
# The POST and the read-back are retried as a pair, not just the POST. Object
# metadata can take a moment to become visible after a POST, and a single
# read-back that misses it looks identical to a POST that failed. Getting this
# wrong kills the run at the very last step: the finalisation loop treats a
# false negative as "expiration could not be enforced" and dies -- after hours
# of work, with every part already uploaded. Observed for real: Swift started
# refusing requests part-way through a test run.
enforce_object_expiry() {
    local obj="$1" want="$2" got n=1
    got=$(object_expiry "$obj")
    [ "$got" = "$want" ] && return 0

    if [ -z "$got" ]; then
        log "stamping expiration on $obj (rclone did not propagate the header)"
    else
        log "re-stamping expiration on $obj: $got -> $want"
    fi

    while [ "$n" -le 4 ]; do
        swift post -H "X-Delete-At: $want" "$CONTAINER" "$obj" >/dev/null 2>&1
        got=$(object_expiry "$obj")
        [ "$got" = "$want" ] && return 0
        # No sleep on the happy path above; only once we are already retrying.
        sleep $(( n * 2 ))
        got=$(object_expiry "$obj")
        [ "$got" = "$want" ] && return 0
        warn "expiration on $obj not confirmed yet (attempt $n/4)"
        n=$(( n + 1 ))
    done
    return 1
}

# Set by setup_rclone once the installed rclone has been probed.
RCLONE_HAS_HEADER_UPLOAD=0

# rclone_upload <file> <expiry epoch> [extra rclone args...]
# One place that knows whether this rclone can stamp on upload.
rclone_upload() {
    local f="$1" exp="$2"
    shift 2
    if [ "$RCLONE_HAS_HEADER_UPLOAD" -eq 1 ]; then
        rclone copy "$@" --header-upload "X-Delete-At: $exp" "$f" "$SWIFT"
    else
        rclone copy "$@" "$f" "$SWIFT"
    fi
}

# Upload local file $1, then confirm it is stored AND carries an expiration.
upload_object() {
    local f="$1" obj
    obj=$(basename "$f")

    retry 3 rclone_upload "$f" "$PROVISIONAL_EXPIRY" --progress || return 1

    if ! swift stat "$CONTAINER" "$obj" >/dev/null 2>&1; then
        warn "$obj is not readable back from the container after upload"
        return 1
    fi

    enforce_object_expiry "$obj" "$PROVISIONAL_EXPIRY" || {
        warn "could not enforce an expiration date on $obj"
        return 1
    }
    return 0
}

# Number of contiguous parts (0..n-1) already present in the container.
container_contiguous_parts() {
    local names idx=0 want n=1
    # Retried: this decides where a resume restarts, and a transient listing
    # failure would abort the resume of an acquisition that is perfectly fine.
    while :; do
        names=$(rclone lsjson "$SWIFT" 2>/dev/null | jq -r '.[].Name' 2>/dev/null) && break
        [ "$n" -ge 3 ] && return 1
        sleep $(( n * 5 ))
        n=$(( n + 1 ))
    done
    while true; do
        want=$(printf '%s.part%03d.gz.aes' "$OUTPUT" "$idx")
        # Here-string rather than a pipe: `printf | grep -q` under pipefail
        # reports failure when grep matches early enough to SIGPIPE the writer,
        # which would stop this count short and send a resume further back than
        # it needs to go. Harmless while the name list fits a pipe buffer, wrong
        # beyond roughly two thousand parts.
        grep -qxF "$want" <<< "$names" || break
        idx=$(( idx + 1 ))
    done
    printf '%s' "$idx"
}

# ------------------------------------------------------------- chunk hashing
#
# The per-chunk sha256 is computed HERE, not by dcfldd.
#
# dcfldd's own hashing cannot be relied on across rescue images. On Debian 10's
# 1.3.4-1 -- which several providers' rescue images still ship, and which a real
# acquisition ran on -- the process segfaults on exit whenever errlog= is passed,
# and the sha256log file is left empty because the crash comes before it is
# flushed. The middle layer of the chain of custody would simply
# vanish, and unsplit.sh would quietly downgrade to skipping per-chunk checks.
#
# Computing it from the same stream is equivalent, and that is measured rather
# than assumed: on that build dcfldd still prints its own "Total (sha256)" to
# stderr, and it matches `sha256sum` of the same range byte for byte.
#
# The byte count is taken on the same pass. Without it, a dcfldd that died
# half-way would produce a short chunk whose recorded hash matches its own short
# data -- every per-chunk check would pass and only the whole-device hash, at
# the very end of a multi-hour run, would reveal it.
CHUNK_FIFO_SHA=""
CHUNK_FIFO_LEN=""
CHUNK_PID_SHA=""
CHUNK_PID_LEN=""

start_chunk_hash() {
    CHUNK_FIFO_SHA="$FLIGHT_DIR/chunk.sha.fifo"
    CHUNK_FIFO_LEN="$FLIGHT_DIR/chunk.len.fifo"
    rm -f "$CHUNK_FIFO_SHA" "$CHUNK_FIFO_LEN"
    mkfifo -m 600 "$CHUNK_FIFO_SHA" "$CHUNK_FIFO_LEN" || return 1
    sha256sum > "$FLIGHT_DIR/chunk.sha.out" < "$CHUNK_FIFO_SHA" &
    CHUNK_PID_SHA=$!
    wc -c     > "$FLIGHT_DIR/chunk.len.out" < "$CHUNK_FIFO_LEN" &
    CHUNK_PID_LEN=$!
    return 0
}

# finish_chunk_hash <newfile> <expected bytes>
# Writes the fragment in dcfldd's own format, so unsplit.sh and the retrieval
# script -- which look for "Total (sha256): <hex>" -- need no change.
finish_chunk_hash() {
    local newfile="$1" want="$2" h got
    [ -n "$CHUNK_PID_SHA" ] || return 1
    wait "$CHUNK_PID_SHA" 2>/dev/null
    wait "$CHUNK_PID_LEN" 2>/dev/null
    CHUNK_PID_SHA=""; CHUNK_PID_LEN=""
    rm -f "$CHUNK_FIFO_SHA" "$CHUNK_FIFO_LEN"

    h=$(cut -d' ' -f1 < "$FLIGHT_DIR/chunk.sha.out" 2>/dev/null)
    got=$(tr -d ' ' < "$FLIGHT_DIR/chunk.len.out" 2>/dev/null)
    rm -f "$FLIGHT_DIR/chunk.sha.out" "$FLIGHT_DIR/chunk.len.out"

    [ -n "$h" ] || { warn "no sha256 was produced for $newfile"; return 1; }
    if [ "$got" != "$want" ]; then
        warn "$newfile: $got bytes read, $want expected -- the read was cut short"
        return 1
    fi
    printf '\nTotal (sha256): %s\n' "$h" > "${newfile}.sha256"
    return 0
}

# ---------------------------------------------------------- concurrent uploads
#
# Producing a part and uploading it used to alternate: the device idle while a
# part uploaded, the network idle while the next one was read, hashed,
# compressed and encrypted. Measured on a whole-disk run those two cost 28 s and
# 27 s per part, so overlapping them approaches max() rather than sum() -- close
# to half the time on data that does not compress.
#
# What must not change is the ORDER of the chain of custody. unsplit.sh and the
# retrieval script map the "Total (sha256)" lines onto parts by position, so one
# fragment appended out of order silently mis-maps every hash after it, and the
# count still matches so nothing complains. Each part therefore writes its
# fragment to its own file and the main loop appends them strictly in part
# order, only once every earlier part is confirmed stored.
#
# Default 1: production and upload measured almost equal, so a single upload in
# flight already overlaps them fully. Higher values only help when the link is
# the slower side, and each one costs a chunk of staging -- which on a rescue
# system is RAM.
UPLOAD_PARALLEL=${UPLOAD_PARALLEL:-1}
FLIGHT_DIR=""
NEXT_CONFIRMED=0

# The upload jobs are waited for BY PID, never with a bare `wait`.
#
# A bare `wait` waits for every background child, and the in-pass device hash is
# one of them: a `sha1sum` reading the FIFO, which by design does not exit until
# the write end is closed at the very end of the acquisition. Waiting for it
# from inside the acquisition loop deadlocks the run -- the process tree shows
# split.sh blocked with a single idle sha1sum child, and nothing else.
UPLOAD_PIDS=()

flight_tag() { printf '%03d' "$1"; }

# One of these runs in the background per part. It writes the part's fragment of
# the chain of custody only after the object is confirmed stored, and holds it
# back for the main loop to append in order.
upload_part_async() {
    local idx="$1" newfile="$2" tag
    tag=$(flight_tag "$idx")
    if ! upload_object "${newfile}.gz.aes"; then
        : > "$FLIGHT_DIR/fail.$tag"
        return 1
    fi
    {
        cat "${newfile}.sha256" 2>/dev/null
        cat "${newfile}.errlog" 2>/dev/null
        sha1sum "${newfile}.gz.aes"
    } > "$FLIGHT_DIR/frag.$tag"
    rm -f "${newfile}.sha256" "${newfile}.errlog" "${newfile}.gz.aes"
    : > "$FLIGHT_DIR/ok.$tag"
    return 0
}

# Append the fragments of every contiguous confirmed part, in order, and move
# the state file over them. NEXT_PART must never jump a hole: a part stored
# beyond a gap is simply re-sent on the next run, which is what
# container_contiguous_parts() already assumes.
drain_confirmed_parts() {
    local tag drained=0
    while :; do
        tag=$(flight_tag "$NEXT_CONFIRMED")
        [ -f "$FLIGHT_DIR/ok.$tag" ] || break
        cat "$FLIGHT_DIR/frag.$tag" >> "$LOGFILE"
        rm -f "$FLIGHT_DIR/ok.$tag" "$FLIGHT_DIR/frag.$tag"
        NEXT_CONFIRMED=$(( NEXT_CONFIRMED + 1 ))
        drained=1
    done
    if [ "$drained" -eq 1 ]; then
        write_state "$NEXT_CONFIRMED"
        # Keep the custody trail server-side even if we are interrupted here.
        rclone_upload "$LOGFILE" "$PROVISIONAL_EXPIRY" \
            || warn "could not refresh $LOGFILE in the container"
    fi
    return 0
}

any_upload_failed() {
    local f
    for f in "$FLIGHT_DIR"/fail.*; do
        [ -e "$f" ] && return 0
    done
    return 1
}

# Reap the oldest upload still tracked. In practice they finish in order, and
# taking them in order keeps this correct without `wait -n`, which cannot be
# restricted to a subset of the jobs on every bash we might run on.
reap_oldest_upload() {
    local pid
    [ "${#UPLOAD_PIDS[@]}" -gt 0 ] || return 1
    pid="${UPLOAD_PIDS[0]}"
    UPLOAD_PIDS=("${UPLOAD_PIDS[@]:1}")
    wait "$pid" 2>/dev/null
    return 0
}

reap_all_uploads() {
    local pid
    for pid in "${UPLOAD_PIDS[@]}"; do
        wait "$pid" 2>/dev/null
    done
    UPLOAD_PIDS=()
    return 0
}

# ------------------------------------------------------------------- state file

write_state() {
    local next="$1"
    ( umask 077; cat > "$STATEFILE" <<EOF
CONTAINER=$CONTAINER
DEVICE=$FILE
FSIZE=$FSIZE
BS=$BS
CHUNKSIZE_BYTES=$CHUNKSIZE_BYTES
TOTAL_PART=$TOTAL_PART
NEXT_PART=$next
ENCKEY_FP=$ENCKEY_FP
RETENTION_SECONDS=$RETENTION_SECONDS
PROVISIONAL_EXPIRY=$PROVISIONAL_EXPIRY
START_TS=$START_TS
WEBEX_ROOM_ID=${WEBEX_ROOM_ID:-}
WEBEX_PARENT_ID=${WEBEX_PARENT_ID:-}
EOF
    )
}

# Parse the state file into ST_* variables (never source it).
read_state() {
    local key value
    ST_CONTAINER=""; ST_DEVICE=""; ST_FSIZE=""; ST_NEXT_PART=""
    ST_ENCKEY_FP=""; ST_PROVISIONAL_EXPIRY=""; ST_START_TS=""
    ST_WEBEX_ROOM_ID=""; ST_WEBEX_PARENT_ID=""; ST_TOTAL_PART=""
    ST_CHUNKSIZE_BYTES=""; ST_BS=""
    while IFS='=' read -r key value; do
        case "$key" in
            CONTAINER)          ST_CONTAINER="$value" ;;
            DEVICE)             ST_DEVICE="$value" ;;
            FSIZE)              ST_FSIZE="$value" ;;
            CHUNKSIZE_BYTES)    ST_CHUNKSIZE_BYTES="$value" ;;
            BS)                 ST_BS="$value" ;;
            TOTAL_PART)         ST_TOTAL_PART="$value" ;;
            NEXT_PART)          ST_NEXT_PART="$value" ;;
            ENCKEY_FP)          ST_ENCKEY_FP="$value" ;;
            PROVISIONAL_EXPIRY) ST_PROVISIONAL_EXPIRY="$value" ;;
            START_TS)           ST_START_TS="$value" ;;
            WEBEX_ROOM_ID)      ST_WEBEX_ROOM_ID="$value" ;;
            WEBEX_PARENT_ID)    ST_WEBEX_PARENT_ID="$value" ;;
            *) ;;
        esac
    done < "$1"
}

# ------------------------------------------------------------------------ webex

webex_notify() {
    [ -n "${WEBEX_TOKEN:-}" ] || return 0
    [ -n "${WEBEX_ROOM_ID:-}" ] || return 0
    local payload
    if [ -n "${WEBEX_PARENT_ID:-}" ]; then
        payload=$(jq -n --arg r "$WEBEX_ROOM_ID" --arg m "$1" --arg p "$WEBEX_PARENT_ID" \
            '{roomId:$r, markdown:$m, parentId:$p}')
    else
        payload=$(jq -n --arg r "$WEBEX_ROOM_ID" --arg m "$1" '{roomId:$r, markdown:$m}')
    fi
    curl -sS --max-time 20 'https://webexapis.com/v1/messages' -X POST \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $WEBEX_TOKEN" \
        --data-binary "$payload" >/dev/null 2>&1 \
        || warn "Webex notification failed (non-blocking)"
    return 0
}

# Post the thread starter and remember its id so later updates are replies.
webex_start_thread() {
    [ -n "${WEBEX_TOKEN:-}" ] || return 0
    [ -n "${WEBEX_ROOM_ID:-}" ] || return 0
    [ -n "${WEBEX_PARENT_ID:-}" ] && return 0
    local payload id
    payload=$(jq -n --arg r "$WEBEX_ROOM_ID" --arg m "$1" '{roomId:$r, markdown:$m}')
    id=$(curl -sS --max-time 20 'https://webexapis.com/v1/messages' -X POST \
            -H 'Content-Type: application/json' \
            -H "Authorization: Bearer $WEBEX_TOKEN" \
            --data-binary "$payload" 2>/dev/null | jq -r '.id // empty')
    WEBEX_PARENT_ID="$id"
    return 0
}

setup_webex() {
    if [ -z "${WEBEX_TOKEN+x}" ]; then
        echo "Webex bearer token (empty to disable notifications)."
        echo "Get one at: https://developer.webex.com/docs/getting-started"
        read -rs WEBEX_TOKEN
        echo
    fi
    if [ -n "${WEBEX_TOKEN:-}" ] && [ -z "${WEBEX_ROOM_ID:-}" ]; then
        echo -n "Enter Webex space link or ID: "
        read -r WEBEX_ROOM_ID
        if [[ $WEBEX_ROOM_ID == *"webexteams"* ]]; then
            WEBEX_ROOM_ID=$(echo "$WEBEX_ROOM_ID" | cut -d"=" -f2)
        fi
    fi
}

# -------------------------------------------------------------------- summary

# One entry per device attempted, filled as the run proceeds. The point of
# keeping it in memory rather than printing as we go is that the summary must
# still be printable when the run dies half-way: by then the keys of the devices
# already acquired are irreplaceable, and losing them because device 3 failed
# would be worse than the failure.
SUM_DEV=(); SUM_CONTAINER=(); SUM_KEY=(); SUM_FP=(); SUM_EXPIRY=(); SUM_STATUS=()
SUM_IDX=-1
SUMMARY_PRINTED=0

# Set only while concurrent children are running; they use it to report back.
SUMFIFO=""

# How many devices are being acquired at once. Read by check_free_space() and
# autosize_chunk(), which must share the staging area between them.
PARALLEL_DEVICES=1

summary_begin() {
    SUM_DEV+=("$1")
    SUM_CONTAINER+=(""); SUM_KEY+=(""); SUM_FP+=(""); SUM_EXPIRY+=("")
    SUM_STATUS+=("INCOMPLETE -- interrupted before finalisation")
    SUM_IDX=$(( ${#SUM_DEV[@]} - 1 ))
}

summary_set() {
    [ "$SUM_IDX" -ge 0 ] || return 0
    case "$1" in
        container) SUM_CONTAINER[SUM_IDX]="$2" ;;
        key)       SUM_KEY[SUM_IDX]="$2" ;;
        fp)        SUM_FP[SUM_IDX]="$2" ;;
        expiry)    SUM_EXPIRY[SUM_IDX]="$2" ;;
        status)    SUM_STATUS[SUM_IDX]="$2" ;;
    esac
    return 0
}

# Append a row the parent did not build itself -- used to bring back what a
# concurrent child produced in its own subshell.
summary_add_row() {
    SUM_DEV+=("$1"); SUM_CONTAINER+=("$2"); SUM_KEY+=("$3")
    SUM_FP+=("$4"); SUM_EXPIRY+=("$5"); SUM_STATUS+=("$6")
    SUM_IDX=$(( ${#SUM_DEV[@]} - 1 ))
}

# What a child sends back to the parent. Written to a FIFO, never to a file: the
# key must not touch a filesystem, and a pipe keeps it in kernel memory.
summary_emit() {
    [ -n "${SUMFIFO:-}" ] || return 0
    [ "$SUM_IDX" -ge 0 ] || return 0
    printf '%s|%s|%s|%s|%s|%s\n' \
        "${SUM_DEV[SUM_IDX]}" "${SUM_CONTAINER[SUM_IDX]}" "${SUM_KEY[SUM_IDX]}" \
        "${SUM_FP[SUM_IDX]}" "${SUM_EXPIRY[SUM_IDX]}" "${SUM_STATUS[SUM_IDX]}" \
        > "$SUMFIFO" 2>/dev/null
    return 0
}

summary_add_skipped() {
    SUM_DEV+=("$1"); SUM_CONTAINER+=("$2"); SUM_KEY+=("(not shown -- acquired earlier in this run)")
    SUM_FP+=(""); SUM_EXPIRY+=(""); SUM_STATUS+=("SKIPPED -- already complete per $MANIFEST")
    SUM_IDX=$(( ${#SUM_DEV[@]} - 1 ))
}

# Printed for a multi-device run, or whenever anything did not complete. A single
# device that finished cleanly already printed the same facts, and repeating them
# would only push them off the screen.
print_run_summary() {
    [ "$SUMMARY_PRINTED" = "1" ] && return 0
    [ "${#SUM_DEV[@]}" -gt 0 ] || return 0

    local i incomplete=0
    for i in "${!SUM_DEV[@]}"; do
        case "${SUM_STATUS[$i]}" in COMPLETE*) ;; *) incomplete=1 ;; esac
    done
    if [ "${#SUM_DEV[@]}" -eq 1 ] && [ "$incomplete" -eq 0 ]; then return 0; fi

    SUMMARY_PRINTED=1
    printf '\n'
    printf '###############################################################\n'
    printf '#  RUN SUMMARY -- %d device(s)\n' "${#SUM_DEV[@]}"
    printf '#  The keys below exist NOWHERE else. Copy this block before\n'
    printf '#  closing this terminal.\n'
    printf '###############################################################\n'
    for i in "${!SUM_DEV[@]}"; do
        printf '\n  [%d/%d] %s\n' "$(( i + 1 ))" "${#SUM_DEV[@]}" "${SUM_DEV[$i]}"
        printf '    Status         : %s\n' "${SUM_STATUS[$i]}"
        printf '    Container      : %s\n' "${SUM_CONTAINER[$i]:-(none created)}"
        printf '    Encryption key : %s\n' "${SUM_KEY[$i]:-(none generated)}"
        [ -n "${SUM_FP[$i]}" ]     && printf '    Fingerprint    : %s\n' "${SUM_FP[$i]}"
        [ -n "${SUM_EXPIRY[$i]}" ] && printf '    Auto-deletion  : %s\n' "${SUM_EXPIRY[$i]}"
        [ -n "${SUM_CONTAINER[$i]}" ] && \
            printf '    Retrieve with  : ./gen_temp_url.sh %s\n' "${SUM_CONTAINER[$i]}"
    done
    printf '\n###############################################################\n'
    return 0
}

# Runs on every exit path, including die(). Summary first, then the pause that
# holds a self-started screen session open, so the operator reads one before the
# other.
on_exit() {
    # Uploads may still be in flight when the run stops. Signal them and reap
    # them BEFORE removing the directory they write into: otherwise a part that
    # finishes uploading a moment later tries to write its fragment into a
    # directory that has vanished, and says so on the operator's terminal right
    # under the summary they are supposed to be reading.
    local pid
    for pid in "${UPLOAD_PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null; done
    for pid in "${UPLOAD_PIDS[@]}"; do wait "$pid" 2>/dev/null; done
    UPLOAD_PIDS=()

    # An interrupted run never reaches the normal cleanup, and would leave its
    # hash FIFO and upload-tracking directory behind -- once per attempt, so
    # resumes accumulate them.
    [ -n "${DEVSHA_FIFO:-}" ] && rm -f "$DEVSHA_FIFO"
    [ -n "${FLIGHT_DIR:-}" ] && rm -rf "$FLIGHT_DIR"
    print_run_summary
    pause_before_close
}

# ------------------------------------------------------------------- manifest

# A device that finished has no .state left, so a relaunch would happily start
# it again from scratch. The manifest records device -> container -> status for
# the run, and completed devices are announced and skipped.
MANIFEST=""

manifest_init() {
    local newest="" f
    # Newest by mtime, without parsing ls output.
    for f in ./*.run; do
        [ -f "$f" ] || continue
        if [ -z "$newest" ] || [ "$f" -nt "$newest" ]; then newest="$f"; fi
    done
    if [ -n "$newest" ] && [ -f "$newest" ]; then
        MANIFEST="$newest"
        log "reusing the run manifest $MANIFEST"
    else
        MANIFEST="./$(hostname -s 2>/dev/null || echo host)-$(date +%s).run"
        : > "$MANIFEST" || die "cannot write the run manifest $MANIFEST"
    fi
}

# manifest_field <device> <1=container|2=status>
manifest_field() {
    [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ] || return 1
    awk -F'|' -v d="$1" -v f="$2" '$1 == d { v = (f == 1) ? $2 : $3 } END { print v }' "$MANIFEST"
}

# Read-modify-write, so it MUST be serialised: under --parallel two children
# update the manifest at the same time, both read the old content, and the
# second write erases the first device's "done" line. A relaunch would then
# acquire a device that had already completed.
#
# The lock is a separate file because `mv` replaces the manifest's inode, and a
# lock held on the old inode protects nothing.
manifest_set() {
    [ -n "$MANIFEST" ] || return 0
    (
        flock -x -w 30 200 || exit 1
        local tmp
        tmp=$(mktemp) || exit 1
        grep -vF "$1|" "$MANIFEST" > "$tmp" 2>/dev/null
        printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$tmp"
        mv -f "$tmp" "$MANIFEST"
    ) 200>>"${MANIFEST}.lock"
    return 0
}

# --------------------------------------------------------------- device survey

# Unmounted partitions and md arrays, for --all. Deliberately printed and
# confirmed rather than acted on: selecting devices to seize without showing
# them first would be dangerous.
enumerate_all_devices() {
    local name type mnt dev staging out
    staging=$(df -P . 2>/dev/null | awk 'NR==2 {print $1}')

    # MOUNTPOINT, singular. The plural column arrived in util-linux 2.37, and
    # Debian 10 -- still the base of many rescue images -- ships 2.33, where the
    # whole call fails with "unknown column: MOUNTPOINTS".
    # Its stderr was being discarded, so that failure surfaced as an empty list
    # and a confident "nothing to acquire" on a machine holding five md arrays
    # and seven partitions. Silencing stderr hid a total failure; it is checked
    # now.
    if ! out=$(lsblk -rno NAME,TYPE,MOUNTPOINT 2>&1); then
        warn "lsblk could not list block devices, so none can be enumerated:
$out"
        return 1
    fi
    {
        while read -r name type mnt; do
            case "$type" in part|raid0|raid1|raid4|raid5|raid6|raid10) ;; *) continue ;; esac
            # A mountpoint of any kind, including [SWAP], means it is in use.
            [ -n "$mnt" ] && continue
            dev="/dev/$name"
            [ -b "$dev" ] || continue
            [ "$dev" = "$staging" ] && continue
            # A partition that is a member of an md array has that array as a
            # holder. Acquire the array, not its halves -- otherwise every byte
            # is taken twice and neither copy is the filesystem.
            [ -n "$(ls -1 "/sys/class/block/$name/holders" 2>/dev/null)" ] && continue
            printf '%s\n' "$dev"
        done <<< "$out"
    # An md array appears once under EVERY disk that carries a member, so a
    # two-disk RAID1 lists each array twice. Acquiring it twice would produce two
    # containers, two keys and twice the work for one device. Deduplicate while
    # preserving the discovery order, which is what the operator is shown.
    } | awk '!seen[$0]++'
}

human_size() {
    awk -v b="$1" 'BEGIN {
        if (b == "" || b + 0 <= 0) { printf "?"; exit }
        split("B KiB MiB GiB TiB PiB", u, " ")
        i = 1
        while (b >= 1024 && i < 6) { b /= 1024; i++ }
        printf "%.1f %s", b, u[i]
    }'
}

# What --all would take, printed and nothing else. Reads no data and writes
# nothing, and deliberately skips the dependency, Swift and screen pre-flight:
# deciding what to seize should work on a bare rescue before anything is
# installed.
show_devices() {
    local dev size type fstype label members m disk psum unalloc n

    command -v lsblk >/dev/null 2>&1 \
        || die "lsblk is needed to list devices: apt-get install -y util-linux"

    printf '\n=== Whole disks ===\n'
    printf 'Acquiring these captures everything: partition tables, the gaps between\n'
    printf 'partitions, md superblocks, swap, and each half of a mirror separately.\n\n'
    while read -r disk; do
        [ -n "$disk" ] || continue
        # -r throughout: without it lsblk pads its columns, and a padded "0"
        # defeats every test below.
        size=$(lsblk -bdnro SIZE "/dev/$disk" 2>/dev/null)
        # A rescue image carries a pile of unused nbd nodes of size 0.
        case "$size" in ''|0) continue ;; esac
        # %.0f, not %d: mawk's %d overflows on a sum of this size and silently
        # reported 2 GiB of partitions on a disk holding 650.
        psum=$(lsblk -bnro TYPE,SIZE "/dev/$disk" 2>/dev/null \
               | awk '$1=="part" {s+=$2} END {printf "%.0f", s+0}')
        n=$(lsblk -bnro TYPE "/dev/$disk" 2>/dev/null | grep -c '^part$')
        unalloc=$(( size - psum ))
        printf '  %-16s %12s  %s\n' "/dev/$disk" "$(human_size "$size")" \
            "$(lsblk -bdnro MODEL "/dev/$disk" 2>/dev/null | sed 's/\\x20/ /g; s/  *$//')"
        printf '      in %d partition(s): %s\n' "$n" "$(human_size "$psum")"
        if [ "$unalloc" -gt $(( 64 * 1024 * 1024 )) ]; then
            printf '      UNPARTITIONED     : %s  -- in no partition and in no md array,\n' \
                "$(human_size "$unalloc")"
            printf '                          so acquiring the partitions alone misses it\n'
        fi
    done < <(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2=="disk" {print $1}')

    printf '\n=== Unmounted partitions and md arrays ===\n'
    printf 'This is exactly what --all would acquire, in this order.\n\n'
    printf '  %-18s %12s  %-7s %-8s %s\n' "DEVICE" "SIZE" "TYPE" "FSTYPE" "LABEL"
    n=0
    while read -r dev; do
        [ -n "$dev" ] || continue
        n=$(( n + 1 ))
        size=$(lsblk -bdnro SIZE "$dev" 2>/dev/null)
        type=$(lsblk -dnro TYPE "$dev" 2>/dev/null)
        fstype=$(lsblk -dnro FSTYPE "$dev" 2>/dev/null)
        label=$(lsblk -dnro LABEL "$dev" 2>/dev/null)
        printf '  %-18s %12s  %-7s %-8s %s\n' \
            "$dev" "$(human_size "$size")" "${type:-?}" "${fstype:--}" "${label:--}"

        # For a mirror, name the members: if their halves have diverged, those
        # are what should be acquired instead of the array.
        case "$type" in
            raid1)
                members=""
                for m in "/sys/class/block/$(lsblk -ndo KNAME "$dev" 2>/dev/null)/md/dev-"*; do
                    [ -d "$m" ] || continue
                    members="$members /dev/$(basename "$m" | sed 's/^dev-//')"
                done
                [ -n "$members" ] && printf '      mirror of:%s\n' "$members"
                ;;
        esac
    done < <(enumerate_all_devices)
    [ "$n" -eq 0 ] && printf '  (none)\n'

    printf '\nExcluded: anything mounted (including swap in use), the filesystem this\n'
    printf 'script is staging on, and partitions that are members of an md array --\n'
    printf 'the array is listed instead, so no byte is taken twice.\n\n'
    printf 'To acquire:  split.sh <device> [<device> ...]\n'
    printf '             split.sh --parallel 2 <device> <device>\n'
    printf '             split.sh --all\n\n'
    return 0
}

# ------------------------------------------------------------------------- main

usage() {
    cat <<EOF
Usage: split.sh <device> [<device> ...]
       split.sh --show
       split.sh --all
       split.sh --parallel [N] <device> <device> ...

Acquires each device, one Swift container and one encryption key each.

  --show          list every unmounted partition and md array -- what --all
                  would take -- and exit. Reads no data, writes nothing, and
                  needs no credentials, so it works on a bare rescue
  --all           acquire every unmounted partition and md array, after showing
                  the list and asking once
  --parallel [N]  acquire up to N devices at once (default 2). Only worth it for
                  devices on SEPARATE physical disks; two partitions of one disk
                  will contend for the same spindle or controller.

At the end -- and also if the run fails part-way -- a consolidated summary
prints the key and container for every device, so nothing has to be recovered by
scrolling back through screen.

In parallel mode each device's console goes to <name>.console so the outputs do
not interleave, and the run refuses to start if any device would need to prompt
for a resume; finish those sequentially first.
EOF
}

# Acquire several devices at once. Worth it because separate physical disks do
# not contend: on the reference server, imaging both NVMe drives concurrently
# halves the customer's downtime, and every device already has its own
# container, key, log and state file, so there is no shared state to corrupt --
# unlike parallelising uploads within one device.
parallel_acquire() {
    local max="$1"; shift
    local devices=("$@")
    local dev running=0 expected=0 pids=() rc=0

    SUMFIFO=$(mktemp -u "${TMPDIR:-/tmp}/split-summary.XXXXXX")
    mkfifo -m 600 "$SUMFIFO" || die "cannot create the summary pipe $SUMFIFO"
    # Held open read-write by the parent so it never sees EOF while children
    # come and go.
    exec 8<> "$SUMFIFO"

    for dev in "${devices[@]}"; do
        local base console
        base=$(echo "$dev" | tr "/" "_")
        console="$base.console"
        log "starting $dev in the background, console in $console"
        (
            # A child's summary row travels back through the FIFO; its own
            # arrays die with the subshell.
            SUM_DEV=(); SUM_CONTAINER=(); SUM_KEY=(); SUM_FP=(); SUM_EXPIRY=(); SUM_STATUS=()
            SUM_IDX=-1
            # Replaces the parent's on_exit in this child, so it has to do the
            # same FIFO cleanup itself.
            trap 'summary_emit
                  [ -n "${DEVSHA_FIFO:-}" ] && rm -f "$DEVSHA_FIFO"
                  [ -n "${FLIGHT_DIR:-}" ] && rm -rf "$FLIGHT_DIR"' EXIT
            acquire_one_device "$dev"
        ) > "$console" 2>&1 &
        pids+=($!)
        expected=$(( expected + 1 ))
        running=$(( running + 1 ))
        if [ "$running" -ge "$max" ]; then
            wait -n 2>/dev/null || rc=1
            running=$(( running - 1 ))
        fi
    done

    local p
    for p in "${pids[@]}"; do
        wait "$p" || rc=1
    done

    # Rows are small and there are at most a handful, so they all fit in the
    # pipe buffer and are waiting to be read now that every child has exited.
    local got=0 d c k f e s
    while [ "$got" -lt "$expected" ]; do
        IFS='|' read -r -t 5 d c k f e s <&8 || break
        [ -n "$d" ] || continue
        summary_add_row "$d" "$c" "$k" "$f" "$e" "$s"
        got=$(( got + 1 ))
    done

    exec 8>&-
    rm -f "$SUMFIFO"
    SUMFIFO=""

    if [ "$got" -lt "$expected" ]; then
        warn "only $got of $expected devices reported back; check the .console files"
    fi
    return "$rc"
}

acquire_one_device() {
    FILE="$1"
    OUTPUT=$(echo "$FILE" | tr "/" "_")
    STATEFILE="$OUTPUT.state"

    # LOGFILE stays empty until the per-device checks have passed: log() and
    # die() append to it, and check_device may be refusing precisely because the
    # current directory lives on the device being acquired -- creating the log
    # there would alter the very evidence we are refusing to touch.
    LOGFILE=""

    # Each device is sized from the original chunk size, not from whatever the
    # previous one was reduced to.
    CHUNKSIZE_BYTES=$CHUNKSIZE_ORIG

    # A fresh Webex thread per disk; a resume restores its own from .state.
    WEBEX_PARENT_ID=""

    # Reset per device, so one device's leftover stamping problem cannot be
    # attributed to the next.
    EXPIRY_INCOMPLETE=""

    # Set when a resume finds every part already confirmed: nothing will be
    # read or encrypted, only the finalisation replayed.
    FINALISE_ONLY=0

    # Same, for the previous device's upload tracking.
    [ -n "$FLIGHT_DIR" ] && rm -rf "$FLIGHT_DIR"
    FLIGHT_DIR=""
    NEXT_CONFIRMED=0
    UPLOAD_PIDS=()

    summary_begin "$FILE"

    check_device
    autosize_chunk
    check_free_space
    LOGFILE="$OUTPUT.log"

    # --- geometry, computed from the device size only (no fdisk parsing) ---
    FSIZE=$(blockdev --getsize64 "$FILE") || die "cannot read the size of $FILE"
    SIZE=$(( (FSIZE + BS - 1) / BS ))                            # blocks, rounded up
    CHUNKSIZE=$(( CHUNKSIZE_BYTES / BS ))                        # blocks per chunk
    TOTAL_PART=$(( (FSIZE + CHUNKSIZE_BYTES - 1) / CHUNKSIZE_BYTES ))

    # --- resume or fresh acquisition ---
    ENCKEY=""
    ENCKEY_FP=""
    RESUME_PART=0
    # Reset, not inherited: with several devices in one run, keeping the previous
    # device's container would upload this device's parts into it.
    CONTAINER=""

    if [ -f "$STATEFILE" ]; then
        read_state "$STATEFILE"
        if [ "$ST_DEVICE" != "$FILE" ] || [ "$ST_FSIZE" != "$FSIZE" ]; then
            warn "$STATEFILE describes a different device ($ST_DEVICE, $ST_FSIZE bytes) -- ignoring it"
        else
            echo
            echo "An interrupted acquisition was found:"
            echo "  state file : $STATEFILE"
            echo "  container  : $ST_CONTAINER"
            echo "  device     : $ST_DEVICE ($ST_FSIZE bytes)"
            echo "  progress   : $ST_NEXT_PART/$ST_TOTAL_PART parts uploaded"
            echo "  key        : fingerprint $ST_ENCKEY_FP"
            echo "  purge date : $(human_date "$ST_PROVISIONAL_EXPIRY") (provisional)"
            echo -n "Resume this acquisition? (y/n): "
            read -r resume_choice
            if [ "$resume_choice" = "y" ] || [ "$resume_choice" = "Y" ]; then
                # The geometry MUST be the one the stored parts were cut with.
                # Free RAM differs between runs on a rescue system, so the
                # auto-sized chunk almost certainly differs -- resuming with it
                # would renumber the remaining parts and corrupt the image.
                if [ -n "$ST_CHUNKSIZE_BYTES" ] && [ "$ST_CHUNKSIZE_BYTES" != "$CHUNKSIZE_BYTES" ]; then
                    log "honouring the chunk size recorded in $STATEFILE: $(( ST_CHUNKSIZE_BYTES / 1024 / 1024 )) MiB (this run computed $(( CHUNKSIZE_BYTES / 1024 / 1024 )) MiB)"
                    CHUNKSIZE_BYTES="$ST_CHUNKSIZE_BYTES"
                fi
                if [ -n "$ST_BS" ] && [ "$ST_BS" != "$BS" ]; then
                    log "honouring the block size recorded in $STATEFILE: $ST_BS"
                    BS="$ST_BS"
                fi
                # Re-derive it: the chunk or block size may just have changed.
                SIZE=$(( (FSIZE + BS - 1) / BS ))
                CHUNKSIZE=$(( CHUNKSIZE_BYTES / BS ))
                TOTAL_PART=$(( (FSIZE + CHUNKSIZE_BYTES - 1) / CHUNKSIZE_BYTES ))
                if [ -n "$ST_TOTAL_PART" ] && [ "$ST_TOTAL_PART" != "$TOTAL_PART" ]; then
                    die "recomputed part count ($TOTAL_PART) differs from the one recorded in $STATEFILE ($ST_TOTAL_PART) -- refusing to resume, the parts would not line up"
                fi

                CONTAINER="$ST_CONTAINER"
                PROVISIONAL_EXPIRY="$ST_PROVISIONAL_EXPIRY"
                START_TS="$ST_START_TS"
                ENCKEY_FP="$ST_ENCKEY_FP"
                WEBEX_ROOM_ID="${WEBEX_ROOM_ID:-$ST_WEBEX_ROOM_ID}"
                WEBEX_PARENT_ID="${WEBEX_PARENT_ID:-$ST_WEBEX_PARENT_ID}"
                RESUME_PART="$ST_NEXT_PART"
                setup_rclone

                # Trust the container over the state file: the state may have
                # been written for an upload that never landed.
                stored=$(container_contiguous_parts) \
                    || die "cannot list container $CONTAINER -- did you source openrc.sh?"
                if [ "$stored" -lt "$RESUME_PART" ]; then
                    warn "container holds $stored contiguous parts, state file claimed $RESUME_PART -- resuming from $stored"
                    RESUME_PART="$stored"
                fi

                # Nothing left to encrypt: every part is stored and confirmed,
                # and only the finalisation remains. Asking for the key here
                # would block a run that does not need it -- and would strand an
                # operator who no longer has it, even though the evidence is
                # entirely uploaded and only a metadata pass is outstanding.
                if [ "$RESUME_PART" -ge "$TOTAL_PART" ]; then
                    log "all $TOTAL_PART parts are stored and confirmed -- only the finalisation is left"
                    log "the encryption key is not needed for that, and is not asked for"
                    FINALISE_ONLY=1
                fi

                # The key is never stored: ask for it and verify the fingerprint,
                # so that we can never encrypt the tail with a different key.
                local tries=0
                while [ "$FINALISE_ONLY" -eq 0 ] && [ "$tries" -lt 3 ]; do
                    echo -n "Encryption key for this acquisition: "
                    read -rs ENCKEY
                    echo
                    if [ "$(key_fingerprint "$ENCKEY")" = "$ENCKEY_FP" ]; then
                        break
                    fi
                    ENCKEY=""
                    tries=$(( tries + 1 ))
                    echo "Key does not match fingerprint $ENCKEY_FP ($tries/3)."
                done
                if [ "$FINALISE_ONLY" -eq 0 ]; then
                    [ -n "$ENCKEY" ] || die "wrong encryption key -- refusing to continue, the archive would be undecryptable"
                    echo "Key verified. Resuming at part $(printf '%03d' "$RESUME_PART")."
                fi
            else
                echo "Starting a new acquisition."
                CONTAINER=""
            fi
        fi
    fi

    echo "Output files will be: $OUTPUT"

    if [ -z "$CONTAINER" ]; then
        START_TS=$(date +%s)
        PROVISIONAL_EXPIRY=$(( START_TS + RETENTION_SECONDS ))
        # First address only: `hostname -I` lists every address and ends with a
        # trailing space, which produced names like
        # "203.0.113.10_2001:db8::1_-_dev_sda1-1788027410".
        IPADDR=$(hostname -I 2>/dev/null | awk '{print $1}')
        [ -n "$IPADDR" ] || IPADDR=$(hostname -s 2>/dev/null || echo host)
        # Swift accepts ':' in a container name, but it must be escaped in URLs
        # and quoted on the command line; keep the name to [A-Za-z0-9._-].
        IPADDR=$(printf '%s' "$IPADDR" | tr -c 'A-Za-z0-9._-' '_')
        CONTAINER="${IPADDR}-${OUTPUT}-${START_TS}"
        setup_rclone
        retry 3 swift post "$CONTAINER" \
            || die "could not create the container $CONTAINER -- check connectivity and that you sourced openrc.sh"
        echo "Container is $CONTAINER"
    else
        setup_rclone
        log "**Resuming acquisition** in container $CONTAINER at part $RESUME_PART"
    fi

    # Recorded as soon as it exists: a failure from here on must still be able to
    # tell the operator which container holds the partial evidence.
    summary_set container "$CONTAINER"
    manifest_set "$FILE" "$CONTAINER" "in-progress"

    log "starting acquisition of $FILE"
    log "container: $CONTAINER"
    log "retention: $RETENTION_SECONDS s -- provisional purge $(human_date "$PROVISIONAL_EXPIRY")"
    log "size: $FSIZE bytes = $SIZE blocks of $BS bytes"
    log "chunks of $CHUNKSIZE blocks, $TOTAL_PART parts total"
    fdisk -l 2>/dev/null | grep "dev" >> "$LOGFILE"

    webex_start_thread "_${CONTAINER}:_ **Starting** preservation of disk $FILE for ${IPADDR:-this host} ($TOTAL_PART parts). Note that I will only be able to post updates for the next 12 hours, due to Webex token expiration."

    # --- encryption key ---
    # Only ever generated for a run that will actually encrypt something. A
    # finalisation-only resume must not invent a key: it would be displayed as
    # if it were the archive's, and it decrypts nothing.
    if [ -z "$ENCKEY" ] && [ "$FINALISE_ONLY" -eq 0 ]; then
        ENCKEY=$(openssl rand -base64 16 | colrm 17)
        ENCKEY_FP=$(key_fingerprint "$ENCKEY")
    fi
    if [ -n "$ENCKEY" ]; then
        echo "=============================================================="
        echo " Device        : $FILE"
        echo " Encryption key: $ENCKEY"
        echo " Fingerprint   : $ENCKEY_FP"
        echo " Transmit it to anyone who needs to decipher the data."
        echo " It is NOT stored anywhere -- losing it loses the evidence."
        echo "=============================================================="
        KEY_SHOWN=1
        summary_set key "$ENCKEY"
    else
        summary_set key "(not shown -- finalisation only, the key was never asked for)"
    fi
    log "encryption key fingerprint: $ENCKEY_FP"
    summary_set fp "$ENCKEY_FP"

    write_state "$RESUME_PART"

    start_device_hash

    # ------------------------------------------------------------ acquisition
    local i=0 SKIP=0 count NEWFILE inflight=0
    NEXT_CONFIRMED=$RESUME_PART
    FLIGHT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/inflight.XXXXXX") \
        || die "cannot create the upload tracking directory"

    while [ "$SKIP" -lt "$SIZE" ]; do
        NEWFILE=$(printf "%s.part%03d" "$OUTPUT" "$i")

        if [ "$i" -lt "$RESUME_PART" ]; then
            log "part $NEWFILE already stored, skipping"
            i=$(( i + 1 ))
            SKIP=$(( SKIP + CHUNKSIZE ))
            continue
        fi

        # Exact block count for the last, shorter chunk.
        count=$CHUNKSIZE
        [ $(( SKIP + CHUNKSIZE )) -gt "$SIZE" ] && count=$(( SIZE - SKIP ))

        # A no-op until the token is due; one Keystone request per half hour.
        refresh_swift_token || warn "could not refresh the Swift token, continuing with the current one"

        log "creating $NEWFILE ($(( i + 1 ))/$TOTAL_PART), $count blocks from block $SKIP"
        webex_notify "_${CONTAINER}:_ Preserving **$NEWFILE** ($(( i + 1 ))/$TOTAL_PART)"

        check_free_space

        # Most time-consuming line of the script (read + hash + compress).
        #
        # No hash=/sha256log= for dcfldd: we hash the stream ourselves, see
        # start_chunk_hash. Its stderr is captured rather than left on the
        # terminal, and that capture is now the ONLY source of read errors.
        #
        # No errlog= either, and that is the important one. On dcfldd 1.3.4-1
        # (Debian 10, the production rescue image) errlog= is the sole cause of
        # the segfault: measured on the same device, same geometry, exit 0
        # without it and 139 with it, on a clean chunk AND on one containing an
        # unreadable block. On a clean chunk the crash lands after all the data
        # is written, so it is merely noisy. On a chunk with a bad sector it
        # lands ON the error -- the output is truncated at the first failed
        # block (4096 of 4194304 bytes measured), the length check below fires,
        # and the acquisition of a failing disk stops dead at its first bad
        # sector. Which is the one case this tool exists for.
        #
        # The option bought nothing even when it worked: on this build the
        # errlog file is 0 bytes in every case, while the identical message is
        # always on stderr, which is captured below and appended to
        # ${NEWFILE}.errlog anyway.
        start_chunk_hash || die "cannot create the chunk hash pipes in $FLIGHT_DIR"

        dcfldd if="$FILE" bs="$BS" count="$count" skip="$SKIP" \
               conv=noerror,sync \
               2> "${NEWFILE}.dcfldd" \
          | tee "$DEVSHA_SINK" "$CHUNK_FIFO_SHA" "$CHUNK_FIFO_LEN" \
          | "${COMPRESSOR[@]}" > "${NEWFILE}.gz"
        # Per stage, not the pipeline as a whole: dcfldd's exit status is not
        # trustworthy on every image, but tee's and the compressor's are, and a
        # failure in either of those means the chunk on disk is wrong.
        local st=("${PIPESTATUS[@]}")

        if [ "${st[1]}" -ne 0 ] || [ "${st[2]}" -ne 0 ]; then
            webex_notify "_${CONTAINER}:_ :warning: **FAILED** writing $NEWFILE -- acquisition stopped"
            die "tee exited ${st[1]} and the compressor ${st[2]} on $NEWFILE -- the chunk on disk
cannot be trusted. Nothing deleted, rerun the script to resume."
        fi

        if ! finish_chunk_hash "$NEWFILE" "$(( count * BS ))"; then
            webex_notify "_${CONTAINER}:_ :warning: **FAILED** reading $NEWFILE -- acquisition stopped"
            die "the read of $NEWFILE did not produce a complete chunk -- nothing deleted,
rerun the script to resume"
        fi

        # Only now is dcfldd's own exit status worth mentioning: the chunk is
        # complete and hashed, so the status alone is not evidence of a problem.
        # Debian 10's dcfldd segfaults on exit on every single chunk.
        if [ "${st[0]}" -ne 0 ]; then
            warn "dcfldd exited ${st[0]} on $NEWFILE, but the chunk is complete:
$(( count * BS )) bytes read and hashed. This is the crash-on-exit of older
dcfldd (Debian 10 ships 1.3.4-1); the data is intact and this line records it."
        fi

        # Read errors, without the progress spam, into the chain of custody.
        grep -avE 'blocks \([0-9]+[KMGT]?b?\) written\.|records (in|out)' \
            "${NEWFILE}.dcfldd" 2>/dev/null | grep -av '^[[:space:]]*$' \
            >> "${NEWFILE}.errlog"
        rm -f "${NEWFILE}.dcfldd"

        if ! gpg "${GPG_OPTS[@]}" --output "${NEWFILE}.gz.aes" \
                 --symmetric --cipher-algo AES256 "${NEWFILE}.gz" 3<<<"$ENCKEY"; then
            webex_notify "_${CONTAINER}:_ :warning: **FAILED** encrypting $NEWFILE -- acquisition stopped"
            die "gpg failed on $NEWFILE -- nothing deleted, rerun the script to resume"
        fi
        rm -f "${NEWFILE}.gz"

        # Wait for a slot, reaping finished uploads as they land.
        while [ "$inflight" -ge "$UPLOAD_PARALLEL" ]; do
            reap_oldest_upload || break
            inflight=$(( inflight - 1 ))
            drain_confirmed_parts
        done

        # The overlap: this returns immediately and the loop goes on to read,
        # hash, compress and encrypt the next part while this one uploads.
        upload_part_async "$i" "$NEWFILE" &
        UPLOAD_PIDS+=($!)
        inflight=$(( inflight + 1 ))

        drain_confirmed_parts
        if any_upload_failed; then
            reap_all_uploads
            inflight=0
            drain_confirmed_parts
            webex_notify "_${CONTAINER}:_ :warning: **FAILED** uploading -- acquisition stopped, local chunks kept"
            die "an upload failed -- the local chunks were KEPT and the state file stops at the
last contiguous confirmed part, so rerunning resumes from there. Fix
connectivity and rerun."
        fi

        i=$(( i + 1 ))
        SKIP=$(( SKIP + CHUNKSIZE ))
    done

    # Everything is produced; let the last uploads land.
    if [ "$inflight" -gt 0 ]; then
        log "waiting for $inflight upload(s) still in flight"
        reap_all_uploads
        inflight=0
        drain_confirmed_parts
    fi
    if any_upload_failed; then
        webex_notify "_${CONTAINER}:_ :warning: **FAILED** on the last uploads -- acquisition stopped"
        die "an upload failed on the final parts -- rerun to resume from the last confirmed part"
    fi
    if [ "$NEXT_CONFIRMED" -ne "$TOTAL_PART" ]; then
        die "only $NEXT_CONFIRMED of $TOTAL_PART parts are confirmed -- refusing to finalise an
incomplete acquisition. Rerun to resume."
    fi

    # ------------------------------------------------------------- finalisation
    # blkid last: it has been observed to crash on damaged filesystems.
    {
        echo "BLK information:"
        lsblk -a 2>/dev/null
        blkid "$FILE" 2>/dev/null
    } >> "$LOGFILE"

    finish_device_hash
    if [ "$DEVSHA_MODE" = "already" ]; then
        : # it is in the log from the run that read the device
    elif [ -s "$OUTPUT.device.sha1" ]; then
        # Normalised to "<hash>  <device>" in both modes: reading from a pipe,
        # sha1sum names the file "-", and unsplit.sh and the retrieval script
        # both look for the device name on that line.
        log "whole-device sha1: $(cut -d' ' -f1 < "$OUTPUT.device.sha1")  $FILE"
        rm -f "$OUTPUT.device.sha1"
    else
        warn "device hash could not be computed"
    fi

    # Definitive expiration: preservation completion date + retention window.
    COMPLETION_TS=$(date +%s)
    FINAL_EXPIRY=$(( COMPLETION_TS + RETENTION_SECONDS ))
    log "preservation completed at $(human_date "$COMPLETION_TS")"
    log "stamping every object with X-Delete-At $FINAL_EXPIRY ($(human_date "$FINAL_EXPIRY"))"

    rclone_upload "$LOGFILE" "$PROVISIONAL_EXPIRY" \
        || warn "could not refresh $LOGFILE in the container"

    # The listing is fetched and checked BEFORE the loop, not piped into it.
    # Piped, a transient failure yields an empty listing, the loop body never
    # runs, `failed` stays empty and the script then logs "expiration enforced on
    # all objects" -- a false success, with every object left on the provisional
    # date. Silence has to be an error here, not a pass.
    # The object names are DERIVED, not listed.
    #
    # Asking the container what it holds made the finalisation hostage to
    # listing consistency: a container lists a just-uploaded object late, and a
    # 463-part disk failed here reporting "463 of 464 objects" for half a minute
    # before giving up -- on a container that did hold all 464. Waiting longer
    # only widens the window; the listing is simply the wrong source.
    #
    # Every name is fully determined by the geometry already in hand, so the
    # enumeration is complete by construction, and `swift post`/`swift stat`
    # address an object directly and never consult the listing.
    #
    # The longest stretch of back-to-back API calls in the whole run: three per
    # object, several hundred objects. The token is refreshed on the way in and
    # periodically, so it cannot expire in the middle.
    refresh_swift_token || warn "could not refresh the Swift token before finalising"

    local failed="" obj idx=0
    while [ "$idx" -lt "$TOTAL_PART" ]; do
        obj=$(printf '%s.part%03d.gz.aes' "$OUTPUT" "$idx")
        [ $(( idx % 100 )) -eq 0 ] && [ "$idx" -gt 0 ] && refresh_swift_token
        enforce_object_expiry "$obj" "$FINAL_EXPIRY" || failed="$failed $obj"
        idx=$(( idx + 1 ))
    done
    enforce_object_expiry "$(basename "$LOGFILE")" "$FINAL_EXPIRY" \
        || failed="$failed $(basename "$LOGFILE")"

    # A cross-check, deliberately non-fatal: if the container turns out to hold
    # something the geometry does not predict, say so rather than stamp it
    # silently or refuse the run over it.
    local listed
    listed=$(swift list "$CONTAINER" 2>/dev/null | grep -c .)
    if [ "$listed" -gt $(( TOTAL_PART + 1 )) ]; then
        warn "the container lists $listed objects, $(( TOTAL_PART + 1 )) expected -- something not
produced by this acquisition is in it, and did not get an expiration from here:
  swift list $CONTAINER"
    fi

    # A second, third and fourth pass over just the stragglers. Retrying the SET
    # beats retrying each object harder in place: these failures are transient,
    # and a later pass lands in a different moment.
    #
    # It matters at scale. Measured on a 347-part disk, ~0.7% of stamps failed
    # even after four in-place attempts, which makes the odds of the whole pass
    # succeeding 0.993^348, about one run in eleven. Without this, finalising a
    # large disk fails almost every time.
    local pass=2 retry_list
    while [ -n "$failed" ] && [ "$pass" -le 4 ]; do
        retry_list="$failed"
        failed=""
        warn "expiration not confirmed on$retry_list -- retrying that set (pass $pass/4)"
        sleep $(( pass * 15 ))
        for obj in $retry_list; do
            enforce_object_expiry "$obj" "$FINAL_EXPIRY" || failed="$failed $obj"
        done
        pass=$(( pass + 1 ))
    done

    EXPIRY_INCOMPLETE=""
    if [ -n "$failed" ]; then
        # Deliberately NOT fatal. Those objects still carry the PROVISIONAL
        # expiration set at upload, so the invariant that matters -- no evidence
        # stored without an expiration -- holds. They simply purge one
        # acquisition-duration earlier than the rest, which against a one-year
        # hold is noise. Throwing away a complete, verified, multi-hour
        # acquisition over a metadata field would be the worse outcome.
        EXPIRY_INCOMPLETE="$failed"
        webex_notify "_${CONTAINER}:_ :warning: definitive expiration not applied to:$failed"
        warn "the definitive expiration could not be applied to:$failed

THE EVIDENCE IS SAFE. Those objects kept the provisional expiration set when
they were uploaded, so nothing is stored without one -- they will simply purge
$(( (FINAL_EXPIRY - PROVISIONAL_EXPIRY) / 60 )) minutes earlier than the rest.
To align them:
  for o in$failed; do swift post -H 'X-Delete-At: $FINAL_EXPIRY' '$CONTAINER' \"\$o\"; done"
    fi

    log "expiration enforced on all objects -- data will be deleted on $(human_date "$FINAL_EXPIRY")"
    log "Finished"

    # Re-upload the log a final time, and stamp it with the definitive date too.
    rclone_upload "$LOGFILE" "$FINAL_EXPIRY" \
        || warn "could not upload the final $LOGFILE"
    enforce_object_expiry "$(basename "$LOGFILE")" "$FINAL_EXPIRY" \
        || warn "could not stamp the final expiration on $LOGFILE"

    rm -f "$STATEFILE"
    rm -rf "$FLIGHT_DIR"
    FLIGHT_DIR=""

    if [ -n "$EXPIRY_INCOMPLETE" ]; then
        summary_set status "COMPLETE -- $TOTAL_PART parts, but $(printf '%s' "$EXPIRY_INCOMPLETE" | wc -w) object(s) kept the provisional expiry"
    else
        summary_set status "COMPLETE -- $TOTAL_PART parts"
    fi
    summary_set expiry "$(human_date "$FINAL_EXPIRY")"
    manifest_set "$FILE" "$CONTAINER" "done"

    echo "=============================================================="
    echo " Device         : $FILE"
    echo " Container      : $CONTAINER"
    if [ -n "$ENCKEY" ]; then
        echo " Encryption key : $ENCKEY"
        echo " Fingerprint    : $ENCKEY_FP"
        echo " Auto-deletion  : $(human_date "$FINAL_EXPIRY")"
        echo " Local log      : $(pwd)/$LOGFILE"
        echo " Transmit the key to anyone who needs to decipher the data."
    else
        # Finalisation-only resume: the key was never asked for, so printing an
        # empty field and telling the operator to transmit it is worse than
        # saying plainly that it is not here.
        echo " Encryption key : NOT SHOWN -- this run only replayed the finalisation,"
        echo "                  so the key was never asked for. Use the one from the"
        echo "                  acquisition itself; its fingerprint is below."
        echo " Fingerprint    : $ENCKEY_FP"
        echo " Auto-deletion  : $(human_date "$FINAL_EXPIRY")"
        echo " Local log      : $(pwd)/$LOGFILE"
    fi
    echo "=============================================================="
    echo " Next: generate the analyst's retrieval script with"
    echo "   ./gen_temp_url.sh $CONTAINER"
    echo "=============================================================="

    webex_notify "_${CONTAINER}:_ This disk is **finished** ($TOTAL_PART parts). Data will be automatically deleted on $(human_date "$FINAL_EXPIRY"). Wait for all disks to be finished and release this server to the customer."

    # Non-zero when some object kept the provisional date: the acquisition is
    # complete and verified, but something was left for the operator to do.
    [ -z "$EXPIRY_INCOMPLETE" ]
}

main() {
    local devices=() all=0 arg
    # Kept before the parse loop consumes them: check_screen re-execs the script
    # inside screen with its original argument list, and shifting them away
    # first would silently drop every device from that re-exec.
    local orig_args=("$@")

    local parallel=1 show=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --show)    show=1; shift ;;
            --all)     all=1; shift ;;
            --parallel)
                       shift
                       # The count is optional, so only consume it if it is one.
                       case "${1:-}" in
                           ''|*[!0-9]*) parallel=2 ;;
                           *)           parallel="$1"; shift ;;
                       esac
                       [ "$parallel" -ge 1 ] || die "--parallel needs a count of 1 or more"
                       ;;
            -h|--help) usage; return 0 ;;
            -*)        usage >&2; printf '\nunknown option: %s\n' "$1" >&2; return 2 ;;
            *)         devices+=("$1"); shift ;;
        esac
    done

    # Read-only, so it runs before every pre-flight and needs none of them.
    if [ "$show" -eq 1 ]; then
        [ "${#devices[@]}" -eq 0 ] && [ "$all" -eq 0 ] || die "--show takes no other argument"
        show_devices
        return 0
    fi

    if [ "$all" -eq 0 ] && [ "${#devices[@]}" -eq 0 ]; then
        usage >&2
        printf '\nNo device supplied. Block devices on this machine:\n' >&2
        lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null >&2
        return 1
    fi
    if [ "$all" -eq 1 ] && [ "${#devices[@]}" -gt 0 ]; then
        die "--all takes no device arguments"
    fi

    # The summary must survive every exit path, die() included: by the time a
    # later device fails, the keys of the ones already acquired exist nowhere
    # else. Scoped inside main so that sourcing the script -- which runs main in
    # a subshell -- never leaves a trap behind in the operator's shell.
    trap on_exit EXIT
    # bash does not run an EXIT trap when it dies on an untrapped signal, so a
    # Ctrl-C or a kill would take the summary -- and with it the only copy of
    # the keys -- down with the run. Turning the signals into an ordinary exit
    # puts the EXIT trap back in the path. Verified: SIGTERM printed nothing
    # before this, and prints the summary after.
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP

    # --- global pre-flight, once for the whole run ---
    check_dependencies
    init_compressor
    init_gpg_opts
    check_swift_auth
    check_screen "${orig_args[@]}"
    select_workdir

    if [ "$all" -eq 1 ]; then
        mapfile -t devices < <(enumerate_all_devices)
        [ "${#devices[@]}" -gt 0 ] || die "--all found no unmounted partition or md array to acquire"
        printf '\n'
        printf 'These %d device(s) would be acquired, in this order:\n\n' "${#devices[@]}"
        for arg in "${devices[@]}"; do
            printf '  %-16s %s\n' "$arg" "$(lsblk -dno SIZE "$arg" 2>/dev/null | tr -d ' ')"
        done
        printf '\nMounted filesystems and the staging device are excluded.\n'
        printf 'Acquire all of them? (yes/no): '
        read -r confirm
        case "$confirm" in
            yes|YES|y|Y) ;;
            *) die "aborted by the operator -- nothing was read or written" ;;
        esac
    fi

    manifest_init
    setup_webex

    printf '\n'
    log "run of ${#devices[@]} device(s): ${devices[*]}"

    # Devices already finished are dropped here, before anything else, so that
    # both paths below see the same list.
    local dev prev_status prev_container todo=() run_rc=0
    for dev in "${devices[@]}"; do
        prev_status=$(manifest_field "$dev" 2)
        if [ "$prev_status" = "done" ]; then
            prev_container=$(manifest_field "$dev" 1)
            printf '\n'
            log "$dev is recorded as complete in $MANIFEST (container $prev_container) -- skipping"
            log "delete that line, or the manifest, to acquire it again"
            summary_add_skipped "$dev" "$prev_container"
            continue
        fi
        todo+=("$dev")
    done

    if [ "${#todo[@]}" -eq 0 ]; then
        log "nothing left to acquire"
        print_run_summary
        return 0
    fi

    # A concurrent run cannot answer prompts: several children would read the
    # same terminal at once and the operator could not tell which is asking for
    # which key. Checked on what was REQUESTED, before the clamp below: with one
    # device left to do, the clamp turns --parallel 2 into 1, which used to slip
    # past this guard and drop the operator into an interactive resume they had
    # explicitly asked not to have -- silently, in a detached screen.
    if [ "$parallel" -gt 1 ]; then
        local blocked=""
        for dev in "${todo[@]}"; do
            [ -f "$(echo "$dev" | tr "/" "_").state" ] || continue
            # A resume with every part already confirmed asks for nothing.
            grep -q '^NEXT_PART=' "$(echo "$dev" | tr "/" "_").state" 2>/dev/null || continue
            blocked="$blocked $dev"
        done
        if [ -n "$blocked" ]; then
            die "--parallel cannot resume, because a resume may ask for the encryption key:$blocked
Finish those sequentially first (same command without --parallel), then re-run.
Their state files are in $(pwd)."
        fi
    fi

    [ "$parallel" -gt "${#todo[@]}" ] && parallel="${#todo[@]}"

    if [ "$parallel" -gt 1 ]; then
        PARALLEL_DEVICES="$parallel"
        printf '\n'
        log "acquiring ${#todo[@]} device(s), $parallel at a time"
        log "each device's console goes to its own .console file"
        # A child's die() ends only that child, so the parent has to propagate
        # the failure itself -- in sequential mode die() ends the whole run.
        parallel_acquire "$parallel" "${todo[@]}" || run_rc=1
    else
        for dev in "${todo[@]}"; do
            printf '\n'
            printf '===============================================================\n'
            log "acquiring $dev"
            printf '===============================================================\n'
            acquire_one_device "$dev" || run_rc=1
        done
    fi

    print_run_summary
    return "$run_rc"
}

# Run in a subshell when sourced, so that `die` never kills the operator's shell.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    ( main "$@" )
    return $?
else
    main "$@"
fi
