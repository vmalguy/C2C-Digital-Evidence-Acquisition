# Cloud Data Acquisition

Forensic preservation of a disk from a running cloud server to OpenStack Swift
object storage, with an end-to-end verifiable chain of custody.

Developed and used at OVHcloud US; nothing in it is provider-specific beyond
Swift itself.

## What it is for

Capturing an exact, verifiable copy of a disk before the machine it lives in is
rebuilt, decommissioned, or lost: incident response on a compromised server, a
failing disk that has to be captured before it dies, or any case where the copy
must outlive the hardware and still be provably identical to the original.

The design is deliberately restrictive about what it leaves behind:

- every chunk is encrypted with AES-256 before it leaves the machine, with a key
  the tool never writes down anywhere;
- every object carries an expiration, so nothing is stored indefinitely — and if
  that expiration cannot be set, the acquisition stops rather than proceed
  without one;
- the download links handed out are time-limited, and whoever holds them still
  cannot read the data without the key, which travels separately.

Whoever holds the links cannot read the data, and whoever holds the data cannot
keep it forever. Both properties are enforced by the tool, not by policy.

## What it does

`split.sh` reads a block device with `dcfldd`, cuts it into chunks below the 5 GiB
Swift object limit, compresses (gzip) and encrypts (GPG AES-256) each chunk, and
uploads it to a dedicated container. `unsplit.sh` rebuilds the image.
`gen_temp_url.sh` produces the download links handed to the requester.

The `<device>.log` file is the **chain of custody**: per-chunk sha256, the read
errors reported for each chunk, sha1 of every uploaded object, sha1 of the whole
device, and the scheduled purge date. It is re-uploaded after every part, so it survives an
interrupted acquisition.

## Retention

Every object is stamped with a Swift `X-Delete-At` expiration. Objects are
uploaded with a provisional date so that **no evidence is ever stored without an
expiration**, and once the acquisition completes every object is re-stamped with
the definitive value:

> **expiration = preservation completion date + 1 year**

Override the window with `RETENTION_SECONDS` (seconds) when the data must be
kept longer. If the expiration cannot be set and read back on an object, the
acquisition stops rather than storing acquired data indefinitely.

The container itself does not expire (Swift only expires objects); an empty
container remains after the purge, at no cost.

## Two machines

| Where | Script | Environment |
|---|---|---|
| The **source server**, booted into rescue | `split.sh` | RAM disk, wiped at every boot |
| Your **acquisition server** | `gen_temp_url.sh` | Ordinary persistent Debian |
| The **analyst's** machine | the generated `retrieve-*.sh` | Whatever they have |

Only `split.sh` ever runs in rescue. Everything below about RAM disks, wiped
packages and staging directories applies to it alone.

## Acquisition — on the source server

Acquisitions start by **rebooting the target server into OVH rescue**. The disks
are then never mounted, so nothing on them is modified, and everything runs from
the RAM-based OS.

```bash
ssh root@<server>             # rescue, root with the password OVH mailed you
                              # copy split.sh onto the box
source openrc.sh              # OpenStack credentials for the target project
./split.sh --show                           # list what is there, take nothing
./split.sh /dev/sda1                        # one device
./split.sh /dev/nvme0n1p1 /dev/md2 /dev/md3 # several, in one pass
./split.sh --parallel 2 /dev/nvme0n1 /dev/nvme1n1   # two disks at once
./split.sh --all                            # every unmounted device, after confirming
```

### Start with `--show`

It lists the whole disks and, for each, how much of it is **not in any
partition**; then every unmounted partition and md array, with size, filesystem
and label, and the members of each mirror. It reads no data, writes nothing and
needs no credentials, so it works on a bare rescue before anything is installed.

It calls the same enumeration `--all` uses, so what it prints is exactly what
`--all` would take — the two cannot drift apart.

On the reference server it makes the case for whole-disk imaging in one line:

```
  /dev/nvme0n1        894.3 GiB  SAMSUNG MZQL2960HCJR-00A07
      in 7 partition(s): 650.4 GiB
      UNPARTITIONED     : 243.8 GiB  -- in no partition and in no md array,
                          so acquiring the partitions alone misses it
```

### Downtime is the constraint, and it is a performance problem

The source server is offline for the whole acquisition, so whatever it serves is
down for the whole acquisition. That pressure should not be relieved by
shrinking the evidence — it is cheaper to make the acquisition fast.

Two things dominate, and neither is the disk:

- **`gzip` is single-threaded.** Measured through the dcfldd pipeline on a 6-core
  EPYC: **67 MB/s with gzip, 241 MB/s with pigz**, for the same compression
  ratio. `split.sh` uses `pigz` when it is present and says so; it falls back to
  `gzip` with a warning. pigz output is an ordinary gzip stream, so the analyst's
  side is unaffected.
- **Separate physical disks do not contend.** `--parallel N` acquires N devices
  at once. Only worth it across distinct disks: two partitions of one disk fight
  for the same controller.
- **The upload overlaps the next part.** Producing a part and uploading it used
  to alternate; now the upload runs in the background while the next part is
  read, compressed and encrypted. Measured 36% off the per-part cycle on
  incompressible data. `UPLOAD_PARALLEL` (default 1) sets how many uploads may
  be in flight — one already covers the overlap, since producing and uploading
  a part cost about the same; raising it only helps when the link is the slower
  side, and each unit costs a chunk of staging, which in rescue is RAM.

For the reference two-NVMe server, imaging **both disks whole** was projected at
roughly 3.4 h as it stood, ~2.2 h with pigz, and ~1.1 h with pigz plus
`--parallel 2`. Measured end to end on the production rescue image: **1 h 19 min
for 2 × 894 GiB** (~386 MiB/s aggregate, 569 parts per disk, zero data lost).
That is a complete image of both disks in about the time imaging only the md
arrays used to cost. That run also logged 1138 tolerated dcfldd segfaults; those
are gone now that `errlog=` is not passed — see "Which rescue image" below.

Plan the downtime from the *uncompressed* size, not the stored size. The same run
stored 103 GB per disk — a 10.7× ratio — but compression buys transfer time, not
read time, and the read is the floor. Expect a rate in the 300-400 MiB/s band per
pair of NVMe devices and size the window from that.

`--parallel` refuses to start if any device would need to prompt for a resume:
several children reading the same terminal cannot be told apart. Finish those
sequentially first. Each device's console goes to `<name>.console` so the outputs
do not interleave, and the consolidated summary at the end carries every key.

Staging is shared: with `--parallel N` each device gets `1/N` of the working
filesystem, and the chunk size auto-sizes to that. On a rescue system the working
filesystem is RAM, where over-committing is an OOM rather than a disk-full
message.

### One authentication, not thousands

Every `swift` and `rclone` invocation would otherwise authenticate against
Keystone from scratch — three token requests per object during finalisation
alone, roughly 2800 for a 347-part disk. Keystone answers **HTTP 429** long
before that, which used to kill the finalisation of an otherwise complete
acquisition.

`split.sh` now authenticates once and hands both clients the token, refreshing it
every 30 minutes. Nothing to do, but worth knowing when reading the logs: a
single `authenticated once` line at the start replaces what used to be thousands
of silent Keystone round trips.

If the definitive expiration cannot be applied to a few objects anyway, the run
says so and exits non-zero **without discarding the acquisition** — those objects
keep the provisional expiration set at upload, so nothing is stored without one.
The message includes the command to align them.

### Several devices in one pass

A server usually has more than one partition. Devices are acquired **in sequence**,
each with its own container, its own key and its own `.state` — the handover stays
one script per disk.

At the end, a **consolidated summary** prints the key, container, fingerprint,
purge date and ready-to-paste `gen_temp_url.sh` command for every device, so
nothing has to be recovered by scrolling back through `screen`.

**It prints even when the run fails.** If device 3 dies, the keys of devices 1
and 2 are already irreplaceable; losing them because the run stopped would be
worse than the failure itself.

A `<host>-<epoch>.run` manifest records device → container → status. Re-run the
same command and devices already finished are announced and skipped — a completed
device has no `.state` left, so without the manifest a relaunch would acquire it
again from scratch.

`--all` lists every unmounted partition and md array, **shows the list and asks
once** before starting. It excludes mounted filesystems, the staging device, and
partitions that are members of an md array — for those it takes the array, not
its halves. Swap partitions **are** included: they hold evidence.

### RAID1: "in sync" does not mean "identical"

A RAID1 serves each read from one member or the other. If the two halves hold
different bytes, reading `/dev/mdX` is **not reproducible** and the image can mix
sectors from both, matching neither member.

An array that reports `clean`, `[2/2] [UU]` can still be diverged. mdadm's
"in sync" guarantees only that everything written *through* the array reached
both members. Installers create arrays with `--assume-clean` to skip the initial
resync — so any block never written since creation keeps whatever each physical
disk already held, which after a previous install is different old data per disk.

Measured on the test server, on an array created a few hours earlier by the
installer and reporting `clean`:

```
mismatch_cnt = 384          # 512-byte sectors, i.e. 192 KiB over 510 MiB
```

and the divergence sat at 3–4 MiB, in **unallocated space** of a FAT32 volume
using 729 of 65365 clusters — freed clusters holding files from the previous
installation. That is exactly where deleted-file carving looks, so the difference
is in forensically interesting territory, not in irrelevant far-away zeros.

Observed on that array: the two members hash to `eba9652d…` and `a6d0ff25…`, and
an image acquired from the assembled array hashed to `7396583c…` — **a third
value, matching neither half**. The kernel served different sectors from
different members within one acquisition. The copy is internally consistent and
rebuilds correctly, but it is a faithful copy of no physical disk.

`split.sh` samples both members and warns, loudly when it finds a difference, but
sampling cannot prove agreement. Before a real acquisition:

```bash
mdadm --action=check /dev/md1           # READS both members and counts
cat /sys/block/md1/md/mismatch_cnt      # meaningless until a check has run
```

> **Never run `mdadm --action=repair` on evidence.** It *writes*: it copies one
> member over the other. `check` only reads. `mismatch_cnt` reads 0 until a
> check has actually completed, so 0 on its own proves nothing.

If the mirrors differ, acquire the **members** individually
(`/dev/nvme0n1p1`, `/dev/nvme1n1p1`) rather than the array. Each member is
deterministic and corresponds to a physical disk, which is standard forensic
practice anyway; the array can be reassembled at analysis time.

**Rescue runs entirely from a RAM disk, so every reboot wipes it**: `split.sh`
itself, any package installed, and anything staged. Copy it over again after
each boot. It reinstalls its own dependencies on every run for the same reason —
including `python3-keystoneclient`, without which `swift` authenticates against
nothing.

Two things it handles by itself, so there is nothing to type:

- **screen.** Acquisitions run for hours and a dropped SSH session would kill
  one, so it starts `screen -S split` and re-executes into it. It then holds the
  session open at the end, because the encryption key is on that terminal and
  nowhere else. `SPLIT_NO_SCREEN=1` opts out.
- **The working directory.** Rescue drops you in `/root`, whose rootfs `df`
  cannot measure. Rather than refuse, the script stages in `/tmp` and says so.
  Override with `SPLIT_WORKDIR`. The choice is deterministic, so a resume
  launched from `/root` again finds its state file.

The script prints an encryption key and its fingerprint. **The key is never
stored anywhere.** Transmit it out of band to whoever needs to decipher the
data. Losing it loses the evidence.

Chunks are staged in RAM, so the chunk size is reduced automatically to fit the
free memory unless `CHUNKSIZE_BYTES` is set explicitly. Pre-flight also refuses
to start if the working directory is on the device being acquired.

### Resuming after a disconnection

`split.sh` writes `<device>.state` next to the log after every confirmed upload.
Re-run the exact same command — from a fresh screen session, nothing to source:

```bash
./split.sh /dev/sda1
```

It shows what was already acquired and asks for the encryption key, which is
**verified against the fingerprint recorded in the state file**. A wrong key is
rejected: encrypting the tail with a different key would produce an archive that
can only be half decrypted.

The container is trusted over the state file — if the state claims more parts
than are actually stored, the acquisition resumes from what is really there.

If the resume finds **every** part already stored and confirmed, only the
finalisation is replayed: the key is not asked for (nothing will be encrypted)
and the device is not re-read, because the whole-device hash is already in the
log. That matters when the machine is offline for the duration — re-reading
894 GiB to recompute a hash sitting three lines up is pure downtime. This is the path to use when a run
completed the upload but died during finalisation.

### A disk with bad sectors

The usual reason a disk is being imaged in a hurry is that it is dying, so this
is the normal case, not the exceptional one.

Unreadable blocks are **zero-filled and the acquisition carries on**
(`conv=noerror,sync`). Nothing shifts: a bad block becomes exactly as many zero
bytes as it was long, at the offset it occupied, so every later byte stays where
it belongs. The `Input/output error` lines land in the `<device>.log` next to the
part that hit them, which is what lets an analyst tell *"these 4 KiB were
unreadable"* from *"these 4 KiB were zero on the disk"* — a distinction that is
lost forever if it is not recorded at acquisition time.

The whole-device sha1 in the log is the hash of **what was acquired**, zero-fill
included — not of the disk, which by definition cannot be read. It is still the
right anchor: it is what `unsplit.sh` checks the rebuilt image against, so it
proves the image the analyst holds is the image that left the source machine.

Two guards matter here and both are worth knowing about:

- every chunk's length is checked against `count * BS`, so a read that stops
  short **aborts the run** rather than storing a chunk that is quietly too small.
  Nothing is deleted; rerun to resume. If you see this, the read stopped early
  for a reason the tool could not compensate for — investigate before retrying,
  because a resume will start from the same place;
- a chunk is only ever deleted from staging after the object is confirmed stored.

If a disk is failing badly enough that reads hang rather than error, `dcfldd`
will block on the kernel, not time out. Watch the progress in the `.console`
file; a device that has stopped advancing needs `--parallel` dropped and the
device handled on its own, so one dying disk does not hold up the others.

## Rebuilding an image

In a directory holding the downloaded `.log` and `.partNNN.gz.aes` files:

```bash
./unsplit.sh
```

Parts are ordered by **part number**, gaps abort the rebuild, checksums are
verified against the log, and any decryption failure stops the process instead
of producing a truncated image.

### Opening a rebuilt whole-disk image

A whole-disk image carries a partition table, and on the reference two-NVMe
servers the partitions are **RAID1 members** — so reaching a filesystem takes
three layers, not one. Verified on Debian 13.6.

Everything below is read-only by construction. That is not caution for its own
sake: an image you mounted read-write is no longer the image whose hash the
chain of custody vouches for.

**Stop udev auto-assembling the arrays first.** This is the step that gets
skipped. The moment the partitions appear, udev runs `mdadm --incremental` and
assembles the arrays itself, under unpredictable names and possibly starting a
resync:

```bash
sudo cp /etc/mdadm/mdadm.conf /etc/mdadm/mdadm.conf.bak
echo 'AUTO -all' | sudo tee -a /etc/mdadm/mdadm.conf
```

Attach the images, partitions scanned, read-only:

```bash
L0=$(sudo losetup --find --show --read-only --partscan ./_dev_nvme0n1)
L1=$(sudo losetup --find --show --read-only --partscan ./_dev_nvme1n1)
lsblk -o NAME,SIZE,RO,TYPE,FSTYPE "$L0" "$L1"
```

`--read-only` is the real protection: the partitions inherit the flag, so writes
fail at the block layer whatever anything above tries to do.

Assemble each array **degraded, from a single disk**:

```bash
for n in 1 2 3 5 6; do
  sudo mdadm --assemble --readonly --run /dev/md12$n ${L0}p$n
done
cat /proc/mdstat
```

One member, not two, and deliberately: a RAID1 whose halves have diverged makes
md pick a version and want to resync. Degraded, the question does not arise —
and you can assemble the other half separately to **compare** them, which is
often the interesting finding (see the RAID1 section above). Partitions outside
any array (`p4`, `p7` on the reference hardware) are swap and BIOS boot.

Identify before mounting, rather than assuming a layout:

```bash
sudo lsblk -f /dev/md121 /dev/md122 /dev/md123 /dev/md125 /dev/md126
sudo pvs; sudo vgs; sudo lvs          # in case there is LVM on top
```

```bash
sudo mkdir -p /mnt/ev/md3
sudo mount -o ro,norecovery /dev/md123 /mnt/ev/md3
```

`norecovery` is not optional. Without it, `mount -o ro` on an ext4 that was not
cleanly unmounted tries to replay the journal, and that write fails on a
read-only device.

**If a tool genuinely needs to write**, overlay a copy-on-write device instead of
giving up read-only:

```bash
SZ=$(sudo blockdev --getsz /dev/md123)
truncate -s 8G /var/tmp/cow-md3.img
COW=$(sudo losetup --find --show /var/tmp/cow-md3.img)
echo "0 $SZ snapshot /dev/md123 $COW P 8" | sudo dmsetup create md3-rw
sudo mount /dev/mapper/md3-rw /mnt/ev/md3    # rw; the journal replays into the COW
```

Writes land in the COW file; the image is not touched.

Tear down in this order — a `losetup -d` on a loop device md still holds fails
silently and leaves ghosts behind:

```bash
sudo umount /mnt/ev/*
sudo dmsetup remove md3-rw 2>/dev/null; sudo losetup -d "$COW" 2>/dev/null
for n in 1 2 3 5 6; do sudo mdadm --stop /dev/md12$n; done
sudo losetup -d "$L0" "$L1"
sudo mv /etc/mdadm/mdadm.conf.bak /etc/mdadm/mdadm.conf
```

Record the sha1 of each image before attaching and after tearing down, and file
both. With `--read-only` they will match — but being able to *show* that is the
point, not the fact that it is true.

## Delivering the data to a remote analyst — on your acquisition server

Run from your own acquisition server, not from the rescue box: it only needs the
openrc for the project and a one-off
`apt-get install -y python3-swiftclient python3-keystoneclient curl`.

The normal case: you acquire, someone else analyses. Generate
**one self-contained script per disk** and send that single file.

```bash
source openrc.sh
./gen_temp_url.sh -e 604800 <container>     # writes ./retrieve-<image>.sh
```

That is the default: no flag needed. `-s FILE` only changes the file name.

Then, through **two separate channels**:

| Channel | What you send |
|---|---|
| Whatever carries the case file | `retrieve-sda1.sh` |
| A different one (phone, in person, sealed) | the encryption key |

That separation is the whole point: the script alone downloads nothing readable,
and the key alone reaches nothing. The key is never written into the script.

The analyst runs it on a plain Debian:

```bash
./retrieve-sda1.sh                 # download, verify, rebuild here
./retrieve-sda1.sh -d /evidence -p 8   # elsewhere, 8 parallel downloads
./retrieve-sda1.sh --verify-only   # download and check, decrypt later
```

It refuses to start once the links have expired, fetches the chain of custody
first and checks it against a sha256 anchored in the script itself, downloads
the parts in parallel, resumes an interrupted transfer (intact parts are kept),
verifies every part, then asks for the key and rebuilds — verifying each chunk
against the hash recorded at acquisition time, and the whole image at the end.

**Room needed on the analyst's side:** the compressed parts plus the full-size
image, and the script prints both figures before it starts. The parts are
gzipped, often by a large factor on a disk with free space in it, so this is
usually much less than twice the image — a 892 GiB disk that is nearly empty
rebuilds comfortably on a 1 TB volume.

The only package a base Debian is missing is `gnupg`; the script prints the
exact `apt-get` line and stops rather than failing halfway.

### Other delivery modes

```bash
./gen_temp_url.sh --urls <container>           # print the URLs
./gen_temp_url.sh -o urls.txt <container>      # save them, mode 600
./gen_temp_url.sh -d ./restore <container>     # download here yourself
```

All modes need a `Temp-URL-Key` on the account. The script refuses to run
without one (`--set-key` creates it) rather than emitting silently invalid
links. An existing key is never overwritten — that would invalidate every URL
already handed out.

**A temp URL is a bearer credential.** Anyone holding it downloads the evidence
without an OVHcloud account until it expires. Prefer the shortest `-e` that fits
the transfer.

## Other scripts

| Script | Use |
|---|---|
| `split.sh` | Acquisition, on the source server |
| `gen_temp_url.sh` | Builds the retrieval script handed to the analyst |
| `unsplit.sh` | Rebuilds an image from downloaded parts |

Earlier generations of this tool included variants for a plain file and for a VM
qcow2 image. They are not shipped here: all of them put the passphrase on the
command line, none set an expiration, and none could resume. There is currently
**no supported path for a plain file or a VM image** — acquire the block device
with `split.sh`.

## If uploads are inexplicably slow, it is probably HTTP/2

An acquisition to a Swift region on the other side of the country used to run at
~1 MiB/s, and every obvious suspect was wrong: not the region, not the client,
not the TCP send buffer, not segmentation.

HTTP/2 caps a **single** upload at its default 65535-byte per-stream
flow-control window, which neither rclone's Go stack nor curl ever grows. Over a
61 ms round trip that is 65535 / 0.0614 = 1.02 MiB/s — exactly the ceiling
observed. Measured on that path, same host, same second, 32 MiB: **39.1 s over
HTTP/2, 2.7 s over HTTP/1.1**, a factor of 14.6.

`split.sh` sets `RCLONE_DISABLE_HTTP2=true` for this reason. If you port this
tool to another client, that one line is worth more than any amount of
parallelism tuning.

## Requirements

Debian/Ubuntu throughout.

`split.sh` installs everything it needs on every run, since rescue starts from a
clean RAM disk each time: `rclone`, `python3-swiftclient`,
`python3-keystoneclient`, `dcfldd`, `gnupg`, `jq`, `curl`, `bsdextrautils`,
`screen`, plus the base tools it will not assume are present (`gzip`, `mawk`,
`util-linux`, `fdisk`, `hostname`, `coreutils`). It aborts naming whatever is
still missing afterwards. `python3-keystoneclient` is checked by importing it,
not by looking for a command: `swift` runs fine without it and only fails later,
at authentication.

`gen_temp_url.sh`, on your acquisition server, needs
`python3-swiftclient python3-keystoneclient curl` installed once.

The generated `retrieve-*.sh` needs `gnupg` and either `curl` or `wget`; on a
base Debian only `gnupg` is missing, and the script prints the exact `apt-get`
line rather than failing halfway.

## Test on the rescue image you will actually boot

Run acquisitions, and any testing, on **the same rescue image a real acquisition
boots**. Ours is Debian 10, and that matters more than it sounds:

- its **dcfldd 1.3.4-1 segfaults whenever `errlog=` is passed** — even on a
  perfectly readable chunk — and never writes its `sha256log`. On a clean chunk
  the crash lands after the data, so it is only noise; on a chunk containing a
  bad sector it lands *on* the error and truncates the read, which used to stop
  the acquisition of a failing disk at its first unreadable block. `split.sh`
  no longer passes `errlog=` (read errors are taken from stderr, which is where
  they always were), computes the per-chunk hash itself, and still tolerates a
  crash once the chunk is proved complete, as a safety net;
- its **rclone 1.45** predates `--header-upload` and `--disable-http2`, so
  `check_dependencies` installs a current rclone over it;
- its **lsblk 2.33** has no `MOUNTPOINTS` column, which used to make `--all` and
  `--show` report an empty machine.

All three are handled. The point is the method, not the list: **a green run on a
newer rescue image proves nothing about the one you will actually use.** Every
one of those defects was invisible until the code ran on the real image, and the
first two were found the hard way, during a real acquisition.

## Never commit

`openrc*.sh`, `rclone.conf`, and any acquisition artefact (`*.part*`, `*.aes`,
`*.log`, `*.state`) must never reach a repository — they are evidence and
OpenStack credentials respectively. Add them to `.gitignore` before your first
commit, not after.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).
