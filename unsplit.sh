#!/bin/bash
#
# Rebuild a disk image acquired with split.sh.
#
#   ./unsplit.sh
#
# Run it in the directory holding the downloaded <name>.log and
# <name>.partNNN.gz.aes files. Parts are ordered by part NUMBER (never by
# timestamp), gaps are detected before any work starts, and every decryption
# is checked -- a wrong key or a corrupt part aborts instead of silently
# producing a truncated image.
#
# Three independent integrity layers, all recorded in the .log at acquisition:
#   1. sha1 of each ENCRYPTED part    -- catches a damaged download
#   2. sha256 of each DECRYPTED chunk -- dcfldd's own hash of the raw device
#      bytes; catches a corruption that predates the upload, and names the
#      failing part instead of only failing at the end
#   3. sha1 of the whole rebuilt image -- catches everything else

set -o pipefail

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- dependencies

# Every external command used below, with the Debian package providing it.
# Installed automatically when running as root; otherwise the exact apt-get line
# is printed, since the analyst's machine may not grant root.
DEPS=(
    "gpg:gnupg"
    "gunzip:gzip"
    "awk:mawk"
    "grep:grep"
    "find:findutils"
    "sha1sum:coreutils"
    "sha256sum:coreutils"
    "sort:coreutils"
    "tee:coreutils"
    "mktemp:coreutils"
    "df:coreutils"
)

check_dependencies() {
    local entry cmd pkg missing=""
    local -a needed=() pkgs=()

    for entry in "${DEPS[@]}"; do
        cmd="${entry%%:*}"; pkg="${entry#*:}"
        command -v "$cmd" >/dev/null 2>&1 || needed+=("$pkg")
    done
    [ "${#needed[@]}" -eq 0 ] && return 0

    mapfile -t pkgs < <(printf '%s\n' "${needed[@]}" | sort -u 2>/dev/null || printf '%s\n' "${needed[@]}")

    if [ "$(id -u)" = "0" ] && command -v apt-get >/dev/null 2>&1; then
        printf 'Installing: %s\n' "${pkgs[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
    fi

    for entry in "${DEPS[@]}"; do
        cmd="${entry%%:*}"
        command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
    done
    [ -z "$missing" ] || die "missing tools:$missing
On Debian or Ubuntu, run:
    sudo apt-get update && sudo apt-get install -y ${pkgs[*]}"
}

check_dependencies

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

# ---------------------------------------------------------------- input files

# Files fetched through a Swift temp URL keep the signature in their name
# (foo.part000.gz.aes?temp_url_sig=...). Offer to clean that up first.
mapfile -t dirty < <(find . -maxdepth 1 -name '*\?temp_url_*' -printf '%f\n' 2>/dev/null)
if [ "${#dirty[@]}" -gt 0 ]; then
    echo "${#dirty[@]} file(s) still carry a temp URL signature in their name."
    read -r -p "Rename them to their clean name? [y/N] " answer
    case "$answer" in
        [yY]|[yY][eE][sS])
            for f in "${dirty[@]}"; do
                clean="${f%%\?*}"
                # mv -n would silently do nothing here, leaving the dirty name in
                # place and the gap check failing for a confusing reason.
                [ -e "$clean" ] && die "cannot rename $f: $clean already exists -- remove the duplicate first"
                mv -n -- "$f" "$clean" || die "cannot rename $f"
            done
            ;;
        *) die "clean the file names first, part ordering depends on them" ;;
    esac
fi

mapfile -t logs < <(find . -maxdepth 1 -name '*.log' -printf '%f\n' | sort)
[ "${#logs[@]}" -eq 1 ] || die "expected exactly one .log file in $(pwd), found ${#logs[@]}: ${logs[*]}"
LOG="${logs[0]}"
OUTPUT="${LOG%.log}"
echo "Chain of custody : $LOG"
echo "Rebuilding into  : $OUTPUT"

# Parts, ordered by part number -- NOT by modification time.
mapfile -t FLIST < <(find . -maxdepth 1 -name "${OUTPUT}.part*.gz.aes" -printf '%f\n' | sort -V)
[ "${#FLIST[@]}" -gt 0 ] || die "no ${OUTPUT}.partNNN.gz.aes file found in $(pwd)"

# Refuse to work with a hole in the numbering.
idx=0
for f in "${FLIST[@]}"; do
    expected=$(printf '%s.part%03d.gz.aes' "$OUTPUT" "$idx")
    [ "$f" = "$expected" ] || die "missing or unexpected part: expected $expected, found $f -- download the whole set before rebuilding"
    idx=$(( idx + 1 ))
done
echo "Parts found      : ${#FLIST[@]} (part000 to $(printf '%03d' $(( idx - 1 ))), no gap)"

# Cross-check against the part count recorded during acquisition, if present.
declared=$(grep -oE '[0-9]+ parts total' "$LOG" | head -n 1 | cut -d' ' -f1)
if [ -n "$declared" ] && [ "$declared" != "${#FLIST[@]}" ]; then
    die "the log declares $declared parts but ${#FLIST[@]} are present -- the set is incomplete"
fi

# The rebuilt image is written next to the parts, so it needs its own room on
# top of them. Fail now rather than half-way through a multi-hour rebuild.
EXPECTED_BYTES=$(grep -oE 'size: [0-9]+ bytes' "$LOG" | head -n 1 | awk '{print $2}')
if [ -n "$EXPECTED_BYTES" ]; then
    echo "Rebuilt size     : $EXPECTED_BYTES bytes ($(( EXPECTED_BYTES / 1024 / 1024 )) MiB)"
    avail_kb=$(df -Pk . | awk 'NR==2 {print $4}')
    need_kb=$(( EXPECTED_BYTES / 1024 + 1024 ))
    if [ "$avail_kb" -lt "$need_kb" ]; then
        die "not enough free space in $(pwd): $(( avail_kb / 1024 )) MB available, $(( need_kb / 1024 )) MB needed for the rebuilt image"
    fi
fi

# ------------------------------------------------------------ integrity check

read -r -p "Check the integrity of the encrypted parts against $LOG? [Y/n] " response
case "$response" in
    [nN]|[nN][oO])
        echo "Integrity check skipped."
        ;;
    *)
        SUMS=$(mktemp) || die "cannot create a temporary file"
        # The log is not a checksum file: pull out only its "<sha1>  <part>" lines.
        grep -E '^[0-9a-f]{40} +.*\.gz\.aes$' "$LOG" > "$SUMS"
        if [ ! -s "$SUMS" ]; then
            rm -f "$SUMS"
            die "no per-part sha1 line found in $LOG -- cannot verify integrity"
        fi
        echo "Verifying $(wc -l < "$SUMS") recorded checksums..."
        sha1sum -c "$SUMS" || { rm -f "$SUMS"; die "integrity check FAILED -- do not use this evidence, re-download the failing parts"; }
        rm -f "$SUMS"
        echo "All parts match the chain of custody."
        ;;
esac

# ----------------------------------------------------------------- decryption

if [ -e "$OUTPUT" ]; then
    read -r -p "$OUTPUT already exists. Delete it and rebuild? [y/N] " response
    case "$response" in
        [yY]|[yY][eE][sS]) rm -f -- "$OUTPUT" || die "cannot remove $OUTPUT" ;;
        *) die "aborting, $OUTPUT left untouched" ;;
    esac
fi

echo -n "Enter decryption key: "
read -rs ENCKEY
echo

# Validate the key on the first megabyte of the first part, before spending
# hours decrypting the whole set. Feeding gpg a truncated stream always ends in
# an error, so match ONLY the signatures that mean "wrong key". A correct key on
# a truncated stream reports "decryption failed: Invalid packet"; matching the
# generic "decryption failed" here would reject every correct key.
GPGERR=$(mktemp) || die "cannot create a temporary file"
head -c 1048576 "${FLIST[0]}" | gpg "${GPG_OPTS[@]}" --decrypt 3<<<"$ENCKEY" >/dev/null 2>"$GPGERR"
if grep -qiE 'bad session key|bad passphrase' "$GPGERR"; then
    rm -f "$GPGERR"
    die "the key does not decrypt ${FLIST[0]} -- wrong key, or that part is corrupt"
fi
rm -f "$GPGERR"
echo "Key accepted."

# Per-chunk plaintext hashes recorded by dcfldd during acquisition, one
# "Total (sha256): <hash>" line per part, in part order. They cover the raw
# device bytes before gzip, so they must equal the sha256 of what we decrypt and
# decompress. Only usable if there is exactly one per part: a run that retried a
# part would leave extra lines and the mapping would be wrong.
mapfile -t PLAIN_SHA < <(grep -oE 'Total \(sha256\): *[0-9a-f]{64}' "$LOG" | grep -oE '[0-9a-f]{64}')
VERIFY_PLAIN=1
if [ "${#PLAIN_SHA[@]}" -ne "${#FLIST[@]}" ]; then
    VERIFY_PLAIN=0
    echo "NOTE: $LOG holds ${#PLAIN_SHA[@]} dcfldd sha256 line(s) for ${#FLIST[@]} part(s)."
    echo "      Per-chunk verification is skipped; layers 1 and 3 still apply."
fi

# A failed rebuild must never leave a plausible-looking image behind: someone
# would eventually analyse it.
cleanup_partial() {
    if [ -e "$OUTPUT" ]; then
        rm -f -- "$OUTPUT" && echo "The partial image $OUTPUT was deleted." >&2
    fi
}

n=0
for F in "${FLIST[@]}"; do
    n=$(( n + 1 ))
    printf '  [%d/%d] %s' "$n" "${#FLIST[@]}" "$F"

    if [ "$VERIFY_PLAIN" -eq 1 ]; then
        # tee feeds the image and the hash from the same single pass.
        if ! got=$(gpg "${GPG_OPTS[@]}" --decrypt "$F" 3<<<"$ENCKEY" | gunzip | tee -a "$OUTPUT" | sha256sum | cut -d' ' -f1); then
            printf '\n'
            cleanup_partial
            die "failed to decrypt/decompress $F"
        fi
        want="${PLAIN_SHA[$(( n - 1 ))]}"
        if [ "$got" != "$want" ]; then
            printf '  MISMATCH\n'
            cleanup_partial
            die "chunk $F does not match the sha256 recorded by dcfldd at acquisition:
  recorded: $want
  rebuilt : $got
That part is corrupt or was tampered with -- re-download it and start over."
        fi
        printf '  sha256 OK\n'
    else
        if ! gpg "${GPG_OPTS[@]}" --decrypt "$F" 3<<<"$ENCKEY" | gunzip >> "$OUTPUT"; then
            printf '\n'
            cleanup_partial
            die "failed to decrypt/decompress $F"
        fi
        printf '\n'
    fi
done

# ------------------------------------------------------------- final integrity

echo "Computing the sha1 of the rebuilt image (this takes a while)..."
sha1sum "$OUTPUT" > "$OUTPUT.sha1"
REBUILT=$(cut -d' ' -f1 < "$OUTPUT.sha1")
echo "Rebuilt image sha1: $REBUILT"

if grep -qF "$REBUILT" "$LOG"; then
    echo "Integrity OK: the rebuilt image matches the hash recorded at acquisition time."
else
    echo "WARNING: $REBUILT does not appear in $LOG."
    echo "The whole-device hash recorded at acquisition is:"
    grep -E 'whole-device sha1|^[0-9a-f]{40} +/dev/' "$LOG" || echo "  (none recorded)"
    echo "A mismatch is expected only if the device size was not a multiple of the block size"
    echo "(the last block is zero-padded). Any other difference means the evidence is altered."
    exit 1
fi
