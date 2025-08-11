# C2C-Digital-Evidence-Acquisition

## Idea
You got a server running in the cloud.
You want to image it for forensic.
Just boot in single user, slice the partitions and send them to a remote cloud storage (S3) service.
End-to-end encryption and compression is in use.

## How to

### Extract data (split)
* reboot your cloud instance in single mode
* source openrc.sh credential
* run split.sh 
* record encryption key and container name in an encrypted form
* wait for the split script to finish... can take 8 hours on a 2To

### recover partition images using `unsplit.sh` 

> Tested OS: GNU/Linux (Debian 10 recommended). Run the recovery **as an unprivileged (non-root) user**.

---

## 0) High-level checklist

* OS: GNU/Linux (Debian tested).
* Tools needed: `gpg`, `zip`, `wget` or `curl` (install if missing).
* Disk: **at least 2×** the partition size free in the filesystem where you will run recovery.
* Work: use **one directory per partition**.
* Recommended: run the long job inside `screen` or `tmux` (so it survives disconnects).

---

## 1) Prepare environment / install prerequisites

(You may need `sudo` for package installation — script itself should be run as non-root.)

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y gnupg zip wget screen
# optional: aria2 for parallel downloads
sudo apt-get install -y aria2
```

RHEL / CentOS:

```bash
sudo yum install -y gnupg zip wget screen
# or dnf on newer systems
```

Verify tools:

```bash
gpg --version
zip --version
which wget || which curl
```

---

## 2) Create a dedicated directory and check disk space

Create a directory (one per partition) and check available space:

```bash
mkdir -p ~/recovery/partition-01
cd ~/recovery/partition-01

# show free space on current filesystem (human readable)
df -h .

# show size of current directory (quick sanity)
du -sh .
```

If `df -h .` does not show at least 2× the partition size available, move to a larger disk/location.

---

## 3) Start a persistent session (recommended)

Using `screen`:

```bash
screen -S recovery_partition01
# you are now in a screen session; to detach: Ctrl-a d
# to reattach later:
screen -r recovery_partition01
```

Or using `tmux`:

```bash
tmux new -s recovery_partition01
# detach: Ctrl-b d
# reattach: tmux attach -t recovery_partition01
```

If you prefer `nohup` (less interactive):

```bash
# will run in background, log to unsplit.log
nohup ./unsplit.sh > unsplit.log 2>&1 & echo $!
tail -f unsplit.log
```

---

## 4) Download the partition files

Two ways: single file per `wget`/`curl` or batch with a list.

**Single-file (example):**

```bash
wget "https://<link-to-part-001>" -O part-001.zip
wget "https://<link-to-part-002>" -O part-002.zip
...
```

**Batch:**
Create `files.txt` containing one URL per line:

```bash
cat > files.txt <<'EOF'
https://<link-to-part-001>
https://<link-to-part-002>
https://<link-to-part-003>
EOF

# download with wget
wget -i files.txt --content-disposition

# OR faster parallel download if aria2 installed
aria2c -i files.txt -j 8 -x 4 -s 4
```

**Tip:** if the server uses redirected filenames, `--content-disposition` lets `wget` use the server-suggested name.

---

## 5) Inspect `unsplit.sh` before running

Always inspect remote scripts before executing.

Fetch the script and open it for review:

```bash
# download the script
wget -O unsplit.sh "https://raw.githubusercontent.com/vmalguy/C2C-Digital-Evidence-Acquisition/refs/heads/main/unsplit.sh"

# view the script
less unsplit.sh
# or
nl -ba unsplit.sh | sed -n '1,200p'
```

Make it executable:

```bash
chmod +x unsplit.sh
```

---

## 6) Run `unsplit.sh` (interactive)

**Run as non-root (regular user).** Example recommended workflow inside `screen`:

```bash
# inside your recovery directory (and screen session)
./unsplit.sh
```

During execution the script will prompt for an **encryption key** — enter it when asked.

**If you prefer to capture output to a log:**

```bash
./unsplit.sh 2>&1 | tee unsplit.log
# or use nohup:
nohup ./unsplit.sh > unsplit.log 2>&1 &
```

**Security note:** avoid storing the encryption key in plain text files or shell history. If you must paste it in the terminal, prefer using `read -s` (below) so the key is not visible in the terminal or history.

**Optional secure interactive pass:**

```bash
# prompt for the key securely and feed it to the script via stdin (if script accepts stdin)
read -s -p "Enter encryption key: " ENCKEY
printf "%s\n" "$ENCKEY" | ./unsplit.sh
# be aware: only do this if the script reads the key from standard input.
```

If `unsplit.sh` *must* be strictly interactive, follow the on-screen prompt and paste/type the key.

---

## 7) What `unsplit.sh` typically does (what to expect)

* Reassembles split pieces into the original archive/image.
* Decrypts using the provided key (if files are encrypted) or passes the key to `gpg`/`openssl` inside the script.
* Unzips / extracts the recovered image(s).

Watch the output log for errors. If you used `tee` or `nohup`, monitor:

```bash
tail -f unsplit.log
```

---

## 8) Post-recovery checks

After the script finishes:

1. **List recovered files**:

```bash
ls -lh
```

2. **Verify recovered image integrity** (if checksums or signatures are available):

```bash
sha256sum recovered-image.img
# compare with expected hash
```

3. **If archive was zipped:** unzip / test:

```bash
unzip -t recovered-archive.zip   # test integrity
```

4. **Mount image (read-only) to inspect contents (optional):**

```bash
# create loop device and mount read-only
sudo losetup -fP recovered-image.img        # finds free loop device and maps partitions
# find loop device name:
losetup -a
# assume /dev/loop0 was used:
mkdir -p /mnt/recovery_image
sudo mount -o ro,loop,ro /dev/loop0 /mnt/recovery_image
# inspect
ls -la /mnt/recovery_image
# when done:
sudo umount /mnt/recovery_image
sudo losetup -d /dev/loop0
```

(Use `sudo` for mounting; the reassembly itself should be done as non-root.)

---

## 9) Cleanup (when you are sure everything is OK)

Remove temporary part files and keep only the recovered image:

```bash
# be careful! verify before deleting
rm -v part-*.zip
# or move parts to an archive location:
mkdir -p ~/archive/partition-01-parts
mv part-* ~/archive/partition-01-parts/
```

---

## 10) Troubleshooting / common issues

* **Insufficient disk space**: `df -h .` and `du -sh` to find where space is used. Move workdir to larger volume.
* **Interrupted download**: resume with `wget -c URL` or re-run batch `aria2c` with `--continue=true`.
* **Corrupt parts / failed checksum**: redownload the affected parts.
* **Script errors / permission denied**: ensure `unsplit.sh` is executable and run as a non-root user (no `sudo ./unsplit.sh`).
* **Key prompts not accepted via pipe**: the script may prompt interactively; run it in a `screen` session and paste the key manually.
* **Large images slower to extract**: be patient and monitor with `top`, `iotop` (if installed), or `dstat`.

---

## Quick command cheat-sheet (copy/paste)

```bash
# create dir and start screen
mkdir -p ~/recovery/partition-01 && cd ~/recovery/partition-01
screen -S recovery_partition01

# download list (example)
cat > files.txt <<'EOF'
https://host.example/part-001
https://host.example/part-002
EOF
wget -i files.txt --content-disposition

# verify (if provided)
sha256sum -c checksums.txt   # OR gpg --verify file.sig file.zip

# download and inspect script
wget -O unsplit.sh "https://raw.githubusercontent.com/vmalguy/C2C-Digital-Evidence-Acquisition/refs/heads/main/unsplit.sh"
less unsplit.sh
chmod +x unsplit.sh

# run the script (interactive; will ask for encryption key)
./unsplit.sh 2>&1 | tee unsplit.log

# monitor progress in another shell (if not using tee)
tail -f unsplit.log
```

---

## Final security reminders

* Verify the script contents before running.
* Keep the encryption key private; only transfer it over secure channels (avoid insecure email or plain text chat).
* Do not run the recovery script as `root`. Use a regular user account.

