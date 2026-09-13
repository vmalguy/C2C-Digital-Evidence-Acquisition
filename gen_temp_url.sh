#!/bin/bash
#
# Issue Swift temporary download URLs for an acquisition container.
#
# Main use: build the single self-contained retrieval script that is handed to
# the remote analyst (law enforcement) for one disk.
#
#   ./gen_temp_url.sh -s retrieve-sda1.sh -e 604800 <container>
#
# The analyst receives that ONE file and nothing else. Running it downloads the
# chain of custody, verifies it, downloads every part in parallel, checks each
# one against the log, then asks for the decryption key and rebuilds the image.
#
# The decryption key is NEVER written into the generated script: send it through
# a separate channel. That separation is what keeps the evidence unreadable to
# anyone who only intercepts the URLs.
#
# Other modes, for local use:
#
#   ./gen_temp_url.sh <container>                  print the URLs
#   ./gen_temp_url.sh -o urls.txt <container>      save them (mode 600)
#   ./gen_temp_url.sh -d ./restore <container>     download here, now
#
# A temp URL is a bearer credential: whoever holds it can download the evidence,
# with no OVHcloud account, until it expires. Prefer the shortest expiry that
# fits the transfer.
#
# Prerequisites: source your openrc.sh first.

set -o pipefail

# ------------------------------------------------------------------- defaults

EXPIRY_SECONDS=604800          # 7 days
DOWNLOAD_DIR=""
URL_FILE=""
SCRIPT_FILE=""
PRINT_URLS=0
SET_KEY=0
CONTAINER=""

# -------------------------------------------------------------------- helpers

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

# Single-quote a value for safe embedding in the generated script.
shquote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

usage() {
    cat <<'EOF'
Usage: gen_temp_url.sh [options] <container>

By DEFAULT it writes the self-contained retrieval script for the remote analyst
(downloads + verifies + rebuilds) to ./retrieve-<image>.sh -- one file per disk,
which is the only thing the analyst needs.

  -s, --script FILE    write that script to FILE instead of the default name
  -d, --download DIR   skip the script; download every object into DIR now
  -o, --output FILE    skip the script; write the raw URLs to FILE (chmod 600)
      --urls           skip the script; print the raw URLs on stdout
  -e, --expire SECS    URL lifetime in seconds (default 604800 = 7 days)
      --set-key        generate an account Temp-URL-Key if none exists yet
  -h, --help           this message

The decryption key is never included anywhere: hand it to the analyst
separately. Source your openrc.sh first.
EOF
}

# ----------------------------------------------------------------- arguments

while [ $# -gt 0 ]; do
    case "$1" in
        -s|--script)   [ -n "${2:-}" ] || die "--script needs a file name"
                       SCRIPT_FILE="$2"; shift 2 ;;
        -d|--download) [ -n "${2:-}" ] || die "--download needs a directory"
                       DOWNLOAD_DIR="$2"; shift 2 ;;
        -o|--output)   [ -n "${2:-}" ] || die "--output needs a file name"
                       URL_FILE="$2"; shift 2 ;;
        -e|--expire)   [ -n "${2:-}" ] || die "--expire needs a number of seconds"
                       EXPIRY_SECONDS="$2"; shift 2 ;;
        --urls)        PRINT_URLS=1; shift ;;
        --set-key)     SET_KEY=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        -*)            die "unknown option: $1 (try --help)" ;;
        *)             if [ -z "$CONTAINER" ]; then
                           CONTAINER="$1"; shift
                       else
                           die "only one container can be given (got '$CONTAINER' and '$1')"
                       fi ;;
    esac
done

[ -n "$CONTAINER" ] || { usage >&2; die "no container name supplied"; }

case "$EXPIRY_SECONDS" in
    ''|*[!0-9]*) die "--expire must be a whole number of seconds, got '$EXPIRY_SECONDS'" ;;
esac
[ "$EXPIRY_SECONDS" -gt 0 ] || die "--expire must be greater than 0"

# --------------------------------------------------------------- dependencies

missing=""
for c in swift awk sed; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
done
[ -n "$DOWNLOAD_DIR" ] && { command -v curl >/dev/null 2>&1 || missing="$missing curl"; }
# A library, not a command: `swift` runs fine without it and only fails at auth
# time. On a rescue system it disappears at every reboot.
python3 -c 'import keystoneclient' >/dev/null 2>&1 \
    || missing="$missing python3-keystoneclient"
if [ -n "$missing" ]; then
    die "missing dependencies:$missing
Install them with: sudo apt-get install -y python3-swiftclient python3-keystoneclient curl"
fi

# ---------------------------------------------------------------------- auth

# `swift auth` prints shell assignments; it must be EVALUATED, not executed.
AUTH=$(swift auth 2>/dev/null) \
    || die "swift auth failed -- did you source your openrc.sh?"
eval "$AUTH"
[ -n "${OS_STORAGE_URL:-}" ] || die "swift auth returned no OS_STORAGE_URL -- check your credentials"

# Split https://host/v1/AUTH_xxx into the origin and the account path, without
# assuming a fixed number of slashes.
case "$OS_STORAGE_URL" in
    */v1/*) DOMAIN="${OS_STORAGE_URL%%/v1/*}"
            ACCOUNT_PATH="/v1/${OS_STORAGE_URL#*/v1/}" ;;
    *)      die "unexpected OS_STORAGE_URL layout: $OS_STORAGE_URL" ;;
esac

# -------------------------------------------------------------- temp-url key

# The key is an ACCOUNT-level secret shared by every temp URL. Never overwrite
# an existing one: that would silently invalidate URLs already handed out.
read_url_key() {
    swift stat 2>/dev/null \
        | awk -F':' 'tolower($0) ~ /temp-url-key/ { sub(/^[ \t]+/, "", $2); sub(/[ \t]+$/, "", $2); print $2; exit }'
}

URLKEY=$(read_url_key)

if [ -z "$URLKEY" ]; then
    if [ "$SET_KEY" -ne 1 ]; then
        die "this account has no Temp-URL-Key, so no temporary URL can be signed.
Re-run with --set-key to generate one, or set it yourself:
  swift post -m \"Temp-URL-Key:\$(openssl rand -hex 20)\"
Note it is account-wide and permanent: changing it later invalidates every URL
already issued."
    fi
    command -v openssl >/dev/null 2>&1 || die "openssl is needed to generate a Temp-URL-Key"
    info "No Temp-URL-Key on this account, generating one (account-wide, kept for future runs)."
    NEWKEY=$(openssl rand -hex 20)
    swift post -m "Temp-URL-Key:$NEWKEY" \
        || die "could not set the account Temp-URL-Key"
    URLKEY=$(read_url_key)
    [ -n "$URLKEY" ] || die "the Temp-URL-Key was posted but cannot be read back"
    info "Temp-URL-Key set."
fi

# ------------------------------------------------------------------- objects

mapfile -t OBJECTS < <(swift list "$CONTAINER" 2>/dev/null)
[ "${#OBJECTS[@]}" -gt 0 ] \
    || die "container '$CONTAINER' is empty or does not exist (check the name and your project)"

# The .log is the chain of custody and must be fetched first by the analyst.
LOGOBJ=""
for o in "${OBJECTS[@]}"; do
    case "$o" in *.log) LOGOBJ="$o"; break ;; esac
done
IMAGE="${LOGOBJ%.log}"

# Stored size of every object, so the generated script can budget disk space
# against what it will actually download. The parts are gzipped: assuming they
# weigh as much as the image asks for twice the image size, which on a 892 GB
# disk means demanding 1.78 TB and refusing to run on a 1 TB volume.
#
# `swift list --long` prints "<bytes> <date> <time> <content-type> <name>" plus
# a trailing "<total> total" line. Keying on the LAST field and looking the name
# up in the objects we already listed makes that summary line, and any column
# reshuffle between client versions, harmless.
declare -A OBJ_SIZE=()
while read -r sz rest; do
    case "$sz" in ''|*[!0-9]*) continue ;; esac
    [ -n "$rest" ] || continue
    OBJ_SIZE["${rest##* }"]="$sz"
done < <(swift list --long "$CONTAINER" 2>/dev/null)

# 0 means "unknown": the generated script then falls back to the conservative
# rule rather than trusting a total it could not build.
PARTS_TOTAL_BYTES=0
for o in "${OBJECTS[@]}"; do
    [ "$o" = "$LOGOBJ" ] && continue
    if [ -z "${OBJ_SIZE[$o]:-}" ]; then
        PARTS_TOTAL_BYTES=0
        info "NOTE: could not read the stored size of $o -- the retrieval script"
        info "      will fall back to a conservative free-space estimate."
        break
    fi
    PARTS_TOTAL_BYTES=$(( PARTS_TOTAL_BYTES + OBJ_SIZE[$o] ))
done

# Handing the analyst one self-contained script is the normal case, so it is what
# happens when no mode is asked for. The other modes are deliberate opt-ins.
if [ -z "$SCRIPT_FILE" ] && [ -z "$DOWNLOAD_DIR" ] && [ -z "$URL_FILE" ] && [ "$PRINT_URLS" -eq 0 ]; then
    [ -n "$IMAGE" ] || die "no .log object in $CONTAINER -- cannot name the retrieval script.
Use --urls or -d if this container was not produced by split.sh."
    SCRIPT_FILE="retrieve-${IMAGE}.sh"
fi

EXPIRES_AT=$(( $(date +%s) + EXPIRY_SECONDS ))
EXPIRES_HUMAN=$(date -u -d "@$EXPIRES_AT" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo "epoch $EXPIRES_AT")

info "Container : $CONTAINER"
info "Objects   : ${#OBJECTS[@]}"
info "Valid for : $EXPIRY_SECONDS s (until $EXPIRES_HUMAN)"
info ""

# Sign one object and echo the full URL.
sign_object() {
    local obj="$1" out
    out=$(swift tempurl GET "$EXPIRY_SECONDS" "${ACCOUNT_PATH}/${CONTAINER}/${obj}" "$URLKEY" 2>/dev/null) \
        || return 1
    [ -n "$out" ] || return 1
    # Depending on the client version this is either a bare path or a full URL.
    case "$out" in
        http://*|https://*) printf '%s' "$out" ;;
        *)                  printf '%s%s' "$DOMAIN" "$out" ;;
    esac
}

# Sign everything up front: every consumer below needs the full list.
URLS=()
i=0
for obj in "${OBJECTS[@]}"; do
    url=$(sign_object "$obj") || die "could not sign $obj"
    URLS+=("$url")
    i=$(( i + 1 ))
    if [ "${#OBJECTS[@]}" -gt 50 ] && [ $(( i % 25 )) -eq 0 ]; then
        printf '  signed %d/%d\r' "$i" "${#OBJECTS[@]}"
    fi
done
[ "${#OBJECTS[@]}" -gt 50 ] && printf '\n'

# ------------------------------------------------------------ raw URL output

if [ -n "$URL_FILE" ]; then
    : > "$URL_FILE" || die "cannot write to $URL_FILE"
    chmod 600 "$URL_FILE"
    printf '%s\n' "${URLS[@]}" >> "$URL_FILE"
    info "URLs written to $URL_FILE (mode 600)."
fi

if [ "$PRINT_URLS" -eq 1 ]; then
    printf '%s\n' "${URLS[@]}"
fi

# ------------------------------------------------------- retrieval script

if [ -n "$SCRIPT_FILE" ]; then
    [ -n "$LOGOBJ" ] || die "no .log object in $CONTAINER -- the retrieval script needs the chain of custody"

    # Bind the generated script to this exact log: the analyst can then detect a
    # log that was swapped or truncated in transit, before trusting any hash in
    # it. Anchored here because this side is authenticated, the analyst's is not.
    info "Anchoring the chain of custody..."
    LOGSHA256=$(swift download --output - "$CONTAINER" "$LOGOBJ" 2>/dev/null | sha256sum | cut -d' ' -f1)
    # The sha256 of nothing at all means the download produced no bytes, which
    # would anchor the script to an empty chain of custody.
    EMPTY_SHA256=$(printf '' | sha256sum | cut -d' ' -f1)
    if [ -z "$LOGSHA256" ] || [ "$LOGSHA256" = "$EMPTY_SHA256" ]; then
        die "could not read $LOGOBJ from $CONTAINER to anchor it"
    fi

    : > "$SCRIPT_FILE" || die "cannot write $SCRIPT_FILE"
    chmod 700 "$SCRIPT_FILE"
    SCRIPT_BASE=$(basename "$SCRIPT_FILE")

    {
        printf '#!/bin/bash\n'
        printf '#\n'
        printf '# Forensic evidence retrieval -- %s\n' "$IMAGE"
        printf '#\n'
        printf '# Generated %s from container:\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        printf '#   %s\n' "$CONTAINER"
        printf '#\n'
        printf '# This single file is all you need, together with the decryption key that was\n'
        printf '# sent to you SEPARATELY. The key is deliberately not in this file: anyone who\n'
        printf '# intercepts this script alone cannot read the evidence.\n'
        printf '#\n'
        printf '# It will:\n'
        printf '#   1. check the download links have not expired\n'
        printf '#   2. download the chain of custody (%s) and verify it\n' "$LOGOBJ"
        printf '#   3. download the %d part(s) in parallel, resuming what is already there\n' "$(( ${#OBJECTS[@]} - 1 ))"
        printf '#   4. verify every part against the chain of custody\n'
        printf '#   5. ask for the key and rebuild %s\n' "$IMAGE"
        printf '#\n'
        printf '# Usage:  ./%s [-d DIR] [-p N] [--verify-only]\n' "$SCRIPT_BASE"
        printf '#\n'
        printf '# Links expire on %s. After that, ask for a new script.\n' "$EXPIRES_HUMAN"
        printf '#\n\n'
        printf 'CONTAINER=%s\n'     "$(shquote "$CONTAINER")"
        printf 'IMAGE=%s\n'         "$(shquote "$IMAGE")"
        printf 'LOGOBJ=%s\n'        "$(shquote "$LOGOBJ")"
        printf 'LOGSHA256=%s\n'     "$(shquote "$LOGSHA256")"
        printf 'EXPIRES=%s\n'       "$EXPIRES_AT"
        printf 'EXPIRES_HUMAN=%s\n' "$(shquote "$EXPIRES_HUMAN")"
        # Stored (compressed + encrypted) size of the parts, so the free-space
        # check below can ask for parts + image instead of twice the image.
        printf 'PARTS_TOTAL_BYTES=%s\n' "$PARTS_TOTAL_BYTES"
        printf '\n'
        printf 'OBJ_NAMES=(\n'
        for o in "${OBJECTS[@]}"; do printf '%s\n' "$(shquote "$o")"; done
        printf ')\n\n'
        printf 'OBJ_URLS=(\n'
        for u in "${URLS[@]}"; do printf '%s\n' "$(shquote "$u")"; done
        printf ')\n\n'
        cat <<'RETRIEVER_BODY'
# ---------------------------------------------------------------------------
# Nothing below this line is specific to one acquisition.
# ---------------------------------------------------------------------------

set -o pipefail

DEST="."
PARALLEL=4
VERIFY_ONLY=0

die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

usage() {
    cat <<EOF
Usage: $0 [options]

  -d, --dir DIR        where to download and rebuild (default: current directory)
  -p, --parallel N     concurrent downloads (default 4)
      --verify-only    download and verify, but do not decrypt or rebuild
  -h, --help           this message

You will be asked for the decryption key. It is not stored in this file and
never written to disk.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--dir)      [ -n "${2:-}" ] || die "--dir needs a directory"; DEST="$2"; shift 2 ;;
        -p|--parallel) [ -n "${2:-}" ] || die "--parallel needs a number"; PARALLEL="$2"; shift 2 ;;
        --verify-only) VERIFY_ONLY=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown option: $1" ;;
    esac
done

case "$PARALLEL" in ''|*[!0-9]*) die "--parallel must be a number" ;; esac
[ "$PARALLEL" -ge 1 ] || PARALLEL=1

# `wait -n` (used to keep N downloads in flight) needs bash 4.3+.
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 3 ]; }; then
    PARALLEL=1
fi

# ------------------------------------------------------------- dependencies

# Everything else used here (sha1sum, sha256sum, gunzip, sed, grep, date, stat)
# ships with a base Debian install.
NEEDPKG=""
command -v gpg     >/dev/null 2>&1 || NEEDPKG="$NEEDPKG gnupg"
command -v gunzip  >/dev/null 2>&1 || NEEDPKG="$NEEDPKG gzip"

DL=""
if   command -v curl >/dev/null 2>&1; then DL=curl
elif command -v wget >/dev/null 2>&1; then DL=wget
else NEEDPKG="$NEEDPKG curl"
fi

if [ -n "$NEEDPKG" ]; then
    info "Missing tools. On Debian or Ubuntu, run:"
    info ""
    info "    sudo apt-get update && sudo apt-get install -y$NEEDPKG"
    info ""
    die "install the package(s) above, then re-run this script"
fi

# ------------------------------------------------------------------- expiry

NOW=$(date +%s)
if [ "$NOW" -ge "$EXPIRES" ]; then
    die "these download links expired on $EXPIRES_HUMAN.
Nothing can be downloaded with this file any more -- ask for a newly generated
script. The evidence itself is untouched."
fi

REMAIN=$(( EXPIRES - NOW ))
info "==============================================================="
info " Evidence      : $IMAGE"
info " Container     : $CONTAINER"
info " Objects       : ${#OBJ_NAMES[@]}"
info " Links valid   : ${REMAIN}s left (until $EXPIRES_HUMAN)"
info " Destination   : $DEST"
info " Parallel      : $PARALLEL"
info "==============================================================="
info ""
# 15 minutes, not an hour: a link deliberately issued for one hour would
# otherwise always warn, and an alarm that always fires stops being read.
if [ "$REMAIN" -lt 900 ]; then
    info "WARNING: under 15 minutes of validity left. A large transfer will not"
    info "         finish in time. Ask for a fresh script."
    info ""
fi

mkdir -p "$DEST" || die "cannot create $DEST"

# --------------------------------------------------------------- http helper

http_get() {
    # $1 = url, $2 = output path
    if [ "$DL" = curl ]; then
        curl -fsS --retry 5 --retry-delay 3 -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

# ------------------------------------------------- 1. chain of custody first

LOG_URL=""
for i in "${!OBJ_NAMES[@]}"; do
    if [ "${OBJ_NAMES[$i]}" = "$LOGOBJ" ]; then LOG_URL="${OBJ_URLS[$i]}"; break; fi
done
[ -n "$LOG_URL" ] || die "internal: no URL for $LOGOBJ"

info "Fetching the chain of custody: $LOGOBJ"
http_get "$LOG_URL" "$DEST/$LOGOBJ" || die "cannot download $LOGOBJ -- check your network and that the links have not expired"

GOT=$(sha256sum "$DEST/$LOGOBJ" | cut -d' ' -f1)
if [ "$GOT" != "$LOGSHA256" ]; then
    die "$LOGOBJ does not match the sha256 recorded when this script was generated:
  expected: $LOGSHA256
  received: $GOT
The chain of custody was altered or truncated in transit. Do not use this
download; report it and ask for a new script."
fi
info "Chain of custody verified against this script."
info ""

LOG="$DEST/$LOGOBJ"

# ------------------------------------------------------- 2. read the log

SUMS=$(grep -E '^[0-9a-f]{40} +.*\.gz\.aes$' "$LOG")
[ -n "$SUMS" ] || die "no per-part sha1 line in $LOGOBJ -- cannot verify anything"

declare -A SHA1_OF
while read -r h n; do
    [ -n "$n" ] && SHA1_OF["$n"]="$h"
done <<< "$SUMS"

DECLARED=$(grep -oE '[0-9]+ parts total' "$LOG" | head -n 1 | cut -d' ' -f1)
EXPECTED_BYTES=$(grep -oE 'size: [0-9]+ bytes' "$LOG" | head -n 1 | awk '{print $2}')

# Parts to fetch: every object except the log.
PART_IDX=()
for i in "${!OBJ_NAMES[@]}"; do
    [ "${OBJ_NAMES[$i]}" = "$LOGOBJ" ] && continue
    PART_IDX+=("$i")
done

if [ -n "$DECLARED" ] && [ "$DECLARED" != "${#PART_IDX[@]}" ]; then
    die "the chain of custody declares $DECLARED parts but this script carries ${#PART_IDX[@]} -- the set is incomplete, ask for a new script"
fi

info "Parts to retrieve : ${#PART_IDX[@]}"
[ -n "$EXPECTED_BYTES" ] && info "Rebuilt image     : $EXPECTED_BYTES bytes ($(( EXPECTED_BYTES / 1024 / 1024 )) MiB)"
[ "${PARTS_TOTAL_BYTES:-0}" -gt 0 ] && info "Parts to download : $PARTS_TOTAL_BYTES bytes ($(( PARTS_TOTAL_BYTES / 1024 / 1024 )) MiB, compressed)"

# The parts and the rebuilt image coexist on disk. The parts are gzipped, often
# by a large factor on a disk with free space in it, so budget their REAL stored
# size -- recorded when this script was generated -- plus the image. Assuming
# the parts weigh as much as the image would demand 1.78 TB for a 892 GB disk
# and refuse to run on a 1 TB volume that fits the job comfortably.
#
# Parts already downloaded are subtracted: on a resume they are on the volume
# already, and counting them again can push a legitimate rebuild over the edge.
if [ -n "$EXPECTED_BYTES" ]; then
    AVAIL_KB=$(df -Pk "$DEST" | awk 'NR==2 {print $4}')
    if [ "${PARTS_TOTAL_BYTES:-0}" -gt 0 ]; then
        HAVE_BYTES=0
        for i in "${PART_IDX[@]}"; do
            n="${OBJ_NAMES[$i]}"
            if [ -f "$DEST/$n" ]; then
                sz=$(stat -c '%s' "$DEST/$n" 2>/dev/null) || sz=0
                HAVE_BYTES=$(( HAVE_BYTES + sz ))
            fi
        done
        TOFETCH=$(( PARTS_TOTAL_BYTES - HAVE_BYTES ))
        [ "$TOFETCH" -lt 0 ] && TOFETCH=0
        NEED_KB=$(( (TOFETCH + EXPECTED_BYTES) / 1024 + 1024 ))
        NEED_WHAT="$(( TOFETCH / 1024 / 1024 )) MB of parts still to fetch plus the $(( EXPECTED_BYTES / 1024 / 1024 )) MB image"
    else
        # Stored sizes were unavailable at generation time: fall back to the old
        # conservative rule rather than risk running out mid-rebuild.
        NEED_KB=$(( 2 * (EXPECTED_BYTES / 1024) + 1024 ))
        NEED_WHAT="the parts plus the rebuilt image (conservative estimate)"
    fi
    if [ "$AVAIL_KB" -lt "$NEED_KB" ]; then
        die "not enough free space in $DEST: $(( AVAIL_KB / 1024 )) MB available, about $(( NEED_KB / 1024 )) MB needed for $NEED_WHAT"
    fi
fi
info ""

# ------------------------------------------------------- 3. download parts

FAILDIR=$(mktemp -d) || die "cannot create a temporary directory"
cleanup_faildir() { rm -rf "$FAILDIR"; }
trap cleanup_faildir EXIT

part_ok() {
    # $1 = object name -- true if present locally with the recorded sha1
    local name="$1" want="${SHA1_OF[$1]:-}" got
    [ -n "$want" ] || return 1
    [ -f "$DEST/$name" ] || return 1
    got=$(sha1sum "$DEST/$name" | cut -d' ' -f1)
    [ "$got" = "$want" ]
}

fetch_one() {
    local idx="$1" name="${OBJ_NAMES[$idx]}" url="${OBJ_URLS[$idx]}"
    # Resume: a part already downloaded and intact is not fetched again.
    if part_ok "$name"; then
        printf '  have  %s\n' "$name"
        return 0
    fi
    if ! http_get "$url" "$DEST/$name"; then
        printf '  FAIL  %s (download)\n' "$name" >&2
        : > "$FAILDIR/$idx"
        return 1
    fi
    if ! part_ok "$name"; then
        printf '  FAIL  %s (checksum mismatch)\n' "$name" >&2
        : > "$FAILDIR/$idx"
        return 1
    fi
    printf '  ok    %s\n' "$name"
}

info "Downloading and verifying ${#PART_IDX[@]} part(s), $PARALLEL at a time..."
RUNNING=0
for idx in "${PART_IDX[@]}"; do
    fetch_one "$idx" &
    RUNNING=$(( RUNNING + 1 ))
    if [ "$RUNNING" -ge "$PARALLEL" ]; then
        wait -n 2>/dev/null || true
        RUNNING=$(( RUNNING - 1 ))
    fi
done
wait

NFAIL=$(find "$FAILDIR" -type f | wc -l)
if [ "$NFAIL" -gt 0 ]; then
    die "$NFAIL part(s) failed to download or did not match the chain of custody.
Re-run this script: parts already verified are kept and only the missing ones
are fetched again."
fi

info ""
info "All ${#PART_IDX[@]} part(s) downloaded and matching the chain of custody."
info ""

if [ "$VERIFY_ONLY" -eq 1 ]; then
    info "--verify-only: stopping here, nothing was decrypted."
    exit 0
fi

# ----------------------------------------------------------- 4. rebuild

# Parts in numeric order -- never by timestamp.
mapfile -t FLIST < <(printf '%s\n' "${OBJ_NAMES[@]}" | grep -E '\.part[0-9]+\.gz\.aes$' | sort -V)
[ "${#FLIST[@]}" -gt 0 ] || die "no <name>.partNNN.gz.aes object in this script"

idx=0
for f in "${FLIST[@]}"; do
    expected=$(printf '%s.part%03d.gz.aes' "$IMAGE" "$idx")
    [ "$f" = "$expected" ] || die "missing or unexpected part: expected $expected, found $f"
    idx=$(( idx + 1 ))
done

OUT="$DEST/$IMAGE"
if [ -e "$OUT" ]; then
    read -r -p "$OUT already exists. Delete it and rebuild? [y/N] " response
    case "$response" in
        [yY]|[yY][eE][sS]) rm -f -- "$OUT" || die "cannot remove $OUT" ;;
        *) die "aborting, $OUT left untouched" ;;
    esac
fi

# gpg >= 2.1 needs --pinentry-mode loopback to read a passphrase from a fd.
GPG_OPTS=(--yes --batch --quiet --passphrase-fd 3)
gpg_opts_list=$(gpg --dump-options 2>/dev/null)
# A here-string, not a pipe: under `set -o pipefail`, `gpg --dump-options |
# grep -q` fails precisely when the option IS found, because grep exits on the
# match and gpg dies of SIGPIPE. The flag would never be added, and on a gpg
# build that needs it the analyst could not decrypt at all.
if grep -q -- '--pinentry-mode' <<< "$gpg_opts_list"; then
    GPG_OPTS+=(--pinentry-mode loopback)
fi

info "The decryption key was sent to you separately; it is not in this file."
printf 'Enter decryption key: '
read -rs ENCKEY
echo
[ -n "$ENCKEY" ] || die "no key entered"

# Validate on the first megabyte before spending hours on the whole set. A
# truncated stream always makes gpg fail, so match ONLY the wrong-key
# signatures: a correct key on a truncated stream says "Invalid packet".
GPGERR=$(mktemp) || die "cannot create a temporary file"
head -c 1048576 "$DEST/${FLIST[0]}" | gpg "${GPG_OPTS[@]}" --decrypt 3<<<"$ENCKEY" >/dev/null 2>"$GPGERR"
if grep -qiE 'bad session key|bad passphrase' "$GPGERR"; then
    rm -f "$GPGERR"
    die "that key does not decrypt the evidence. Check the key you were given
(watch for a copy/paste that swallowed a character), then try again."
fi
rm -f "$GPGERR"
info "Key accepted."
info ""

# Per-chunk plaintext hashes recorded by dcfldd at acquisition, one
# "Total (sha256): <hash>" per part in part order. They cover the raw device
# bytes before compression, so they must equal the sha256 of what we decrypt
# and decompress. Skipped if the count does not line up with the parts.
mapfile -t PLAIN_SHA < <(grep -oE 'Total \(sha256\): *[0-9a-f]{64}' "$LOG" | grep -oE '[0-9a-f]{64}')
VERIFY_PLAIN=1
if [ "${#PLAIN_SHA[@]}" -ne "${#FLIST[@]}" ]; then
    VERIFY_PLAIN=0
    info "NOTE: the log holds ${#PLAIN_SHA[@]} dcfldd sha256 line(s) for ${#FLIST[@]} part(s);"
    info "      per-chunk verification is skipped, the other two layers still apply."
fi

cleanup_partial() {
    if [ -e "$OUT" ]; then
        rm -f -- "$OUT" && info "The partial image was deleted."
    fi
}

info "Rebuilding $IMAGE ..."
n=0
for F in "${FLIST[@]}"; do
    n=$(( n + 1 ))
    printf '  [%d/%d] %s' "$n" "${#FLIST[@]}" "$F"
    if [ "$VERIFY_PLAIN" -eq 1 ]; then
        if ! got=$(gpg "${GPG_OPTS[@]}" --decrypt "$DEST/$F" 3<<<"$ENCKEY" | gunzip | tee -a "$OUT" | sha256sum | cut -d' ' -f1); then
            printf '\n'; cleanup_partial; die "failed to decrypt/decompress $F"
        fi
        want="${PLAIN_SHA[$(( n - 1 ))]}"
        if [ "$got" != "$want" ]; then
            printf '  MISMATCH\n'; cleanup_partial
            die "chunk $F does not match the sha256 recorded at acquisition:
  recorded: $want
  rebuilt : $got
That part is corrupt or was tampered with."
        fi
        printf '  sha256 OK\n'
    else
        if ! gpg "${GPG_OPTS[@]}" --decrypt "$DEST/$F" 3<<<"$ENCKEY" | gunzip >> "$OUT"; then
            printf '\n'; cleanup_partial; die "failed to decrypt/decompress $F"
        fi
        printf '\n'
    fi
done

# ------------------------------------------------------- 5. final integrity

info ""
info "Computing the sha1 of the rebuilt image (this takes a while)..."
sha1sum "$OUT" > "$OUT.sha1"
REBUILT=$(cut -d' ' -f1 < "$OUT.sha1")
info "Rebuilt image sha1: $REBUILT"

echo
if grep -qF "$REBUILT" "$LOG"; then
    info "==============================================================="
    info " INTEGRITY OK"
    info " $OUT matches the hash recorded when the evidence was seized."
    info " Chain of custody: $LOG"
    info "==============================================================="
else
    info "==============================================================="
    info " WARNING: $REBUILT does not appear in the chain of custody."
    info " Hash recorded at acquisition:"
    grep -E 'whole-device sha1|^[0-9a-f]{40} +/dev/' "$LOG" || info "  (none recorded)"
    info ""
    info " A mismatch is expected ONLY if the seized device size was not a"
    info " multiple of 4096 bytes, in which case the last block is zero-padded."
    info " Any other difference means the image differs from the seized device."
    info "==============================================================="
    exit 1
fi
RETRIEVER_BODY
    } >> "$SCRIPT_FILE"

    info ""
    info "Retrieval script written to $SCRIPT_FILE (mode 700)."
    info "  evidence   : $IMAGE"
    info "  objects    : ${#OBJECTS[@]} (log anchored by sha256)"
    info "  expires    : $EXPIRES_HUMAN"
    info ""
    info "Send this ONE file to the analyst."
    info "Send the decryption key through a DIFFERENT channel -- it is not in the file."
fi

# --------------------------------------------------------- local download

if [ -n "$DOWNLOAD_DIR" ]; then
    mkdir -p "$DOWNLOAD_DIR" || die "cannot create $DOWNLOAD_DIR"
    info "Downloading into $DOWNLOAD_DIR"
    failed=""
    for i in "${!OBJECTS[@]}"; do
        obj="${OBJECTS[$i]}"
        # -f: fail loudly on 401/404 instead of saving the error page.
        # -o: keep the real object name; a temp URL carries its signature in the
        #     query string, and wget --content-disposition would save it as
        #     "<obj>?temp_url_sig=..." which breaks part ordering downstream.
        if curl -fsS --retry 3 --retry-delay 2 -o "${DOWNLOAD_DIR}/${obj}" "${URLS[$i]}"; then
            printf 'OK  %12s  %s\n' "$(stat -c '%s' "${DOWNLOAD_DIR}/${obj}" 2>/dev/null)" "$obj"
        else
            failed="$failed $obj"
            printf 'DOWNLOAD FAILED  %s\n' "$obj" >&2
        fi
    done
    [ -z "$failed" ] || die "failed on:$failed"

    info ""
    if [ -n "$LOGOBJ" ]; then
        SUMS=$(mktemp) || die "cannot create a temporary file"
        grep -E '^[0-9a-f]{40} +.*\.gz\.aes$' "${DOWNLOAD_DIR}/${LOGOBJ}" > "$SUMS"
        if [ ! -s "$SUMS" ]; then
            rm -f "$SUMS"
            info "No per-part sha1 line in $LOGOBJ -- skipping the checksum verification."
        else
            info "Verifying $(wc -l < "$SUMS") checksums from $LOGOBJ..."
            ( cd "$DOWNLOAD_DIR" && sha1sum -c "$SUMS" ) \
                || { rm -f "$SUMS"; die "the download does NOT match the chain of custody -- re-download the failing parts"; }
            rm -f "$SUMS"
            info "All downloaded parts match the chain of custody."
        fi
    fi
    info ""
    info "Rebuild the image with:  cd $DOWNLOAD_DIR && /path/to/unsplit.sh"
fi

if [ -n "$URL_FILE" ]; then
    info "Anyone holding those URLs can download the evidence until they expire."
fi
