# Linux Baseline & Forensic Triage Tool (LBFTT)
### Version 1.5.1 — EGA Technology Specialists, LLC.
**Author:** John G. Asmussen  
**License:** GNU General Public License v3.0

---

## Table of Contents

1. [Overview](#overview)
2. [Design Philosophy](#design-philosophy)
3. [Requirements](#requirements)
4. [USB Drive Layout](#usb-drive-layout)
5. [Output Structure](#output-structure)
6. [Usage](#usage)
7. [Collection Profiles](#collection-profiles)
8. [Collection Modules](#collection-modules)
9. [Memory Acquisition](#memory-acquisition)
10. [ClamAV Integration](#clamav-integration)
    - [ClamAV Portable Bundle](#clamav-portable-bundle)
11. [Chain of Custody & Manifest](#chain-of-custody--manifest)
12. [Forensic Safety Principles](#forensic-safety-principles)
13. [Adding New Profiles](#adding-new-profiles)
14. [Changelog](#changelog)

---

## Overview

LBFTT is a self-contained, USB-deployable bash script for Linux digital forensics and incident response. It performs structured, reproducible collection of forensic artifacts from a live Linux system, organizing everything into a timestamped, hash-verified case directory on a forensic USB drive.

The tool is designed for two distinct use cases:

- **DFIR Practitioners** (agents, investigators, examiners) responding to security incidents who need rapid, profile-driven collection of the right artifacts for their specific incident type — without having to remember what to collect under pressure.
- **System Administrators** who need to establish a verified system normalcy baseline for change detection, compliance documentation, or pre-incident preparation.

LBFTT produces a structured, court-admissible evidence package: every artifact is individually hashed (MD5, SHA-1, SHA-256), every command is timestamped, all output is organized into numbered log files, and the entire collection is bound together by a chain-of-custody manifest that self-hashes at finalization.

---

## Design Philosophy

### Volatility Order is Non-Negotiable

All incident response profiles collect volatile data first, in strict order of volatility. Memory is acquired before anything else. Processes and network connections are captured before any disk activity that might disturb them. This is not configurable — it is enforced by the module execution order within each profile function.

The rationale is straightforward: memory is lost the moment the system powers off or an attacker wipes it. Network connections disappear when sessions close. Running processes can be killed. On-disk artifacts are comparatively durable. The tool respects this hierarchy and never compromises it for convenience.

### Modular Architecture

Every collection activity is encapsulated in its own function (`collect_*`) that writes exclusively to its own numbered log file. No module touches another module's log. This means:

- Each log file is independently importable into Autopsy, Splunk, Elastic SIEM, or any other analysis platform.
- A failure in one module does not abort the entire collection — the tool continues to the next module.
- Individual logs can be hashed and verified independently without needing the entire collection.
- Adding new collection capability requires writing one new function and adding it to the relevant profile lists.

### Profile-Driven — Not Tool-Driven

Traditional triage tools give examiners a list of commands and expect them to know which ones matter. LBFTT inverts this: the examiner selects an incident type and the tool collects exactly what that incident type requires. This approach eliminates decision fatigue in high-stress situations, prevents collection gaps caused by human memory failure, and makes the tool usable by personnel who are not forensics specialists.

### Read-Only by Design

LBFTT never modifies the target system. It does not install software, does not write to local disk (all output goes to the forensic USB), does not kill processes, does not delete or quarantine files, and does not alter timestamps. The only system state change that occurs is the unavoidable act of running a bash script, which is documented in the manifest.

### Self-Documenting Evidence

Every log file contains the full command that was run, the time it started, the time it finished, the elapsed duration, and the complete output. If a command was not found on the system, that fact is logged explicitly. If a command timed out, that is logged. Examiners and courts can see exactly what ran, what it found, and how long it took — nothing is hidden or summarized away.

---

## Requirements

| Requirement | Detail |
|---|---|
| Operating System | Any modern Linux distribution |
| Privileges | Must run as root or via `sudo` |
| Bash version | 4.0 or later |
| Forensic USB | Mounted at `/mnt/FORENSICS` |
| Minimum USB free space | 5 GB (tool warns if less) |
| Optional — LiME | Pre-compiled kernel module for memory acquisition |
| Optional — AVML | Static binary for memory acquisition (fallback) |
| Optional — ClamAV | `clamscan` binary for AV scanning (MALWARE/APT and FULL IR) |

LBFTT uses only standard Linux utilities (`ps`, `ss`, `ip`, `find`, `stat`, `sha256sum`, etc.) that are present on virtually all distributions. Commands that are not available on a given system are gracefully skipped and the absence is logged — the collection continues without interruption.

---

## USB Drive Layout

The forensic USB drive should be organized as follows:

```
/mnt/FORENSICS/
├── LBFTT.sh                                        ← this script (executable)
├── avml                                            ← (optional) AVML binary
├── lime-<kernel-version>.ko                        ← (optional) LiME kernel module
│   e.g. lime-6.8.0-51-generic.ko
├── clamav-1.4.2-portable-x86_64-with-db.tar.gz    ← (optional) portable ClamAV bundle
├── clamav-1.4.2-portable-x86_64-with-db.tar.gz.sha256  ← bundle chain-of-custody hash
└── <case directories created here at runtime>
    └── hostname.YYYY-MM-DDTHHMMSSZ.PROFILE/
```

Multiple LiME modules for different kernel versions can coexist on the USB. The tool automatically selects the correct one by matching against `uname -r` at runtime.

---

## Output Structure

Every collection run creates a new timestamped case directory under `/mnt/FORENSICS/`. The directory name encodes the hostname, UTC timestamp, and collection profile, making every run uniquely identifiable at a glance.

```
/mnt/FORENSICS/
└── webserver01.2025-11-14T143022Z.MALWARE_APT/
    ├── 00_MANIFEST.log          ← chain-of-custody index, all hashes, summary
    ├── 01_SYSTEM.log            ← OS identity, kernel, uptime, GRUB, UEFI
    ├── 02_HARDWARE.log          ← CPU, memory, disks, PCI/USB, SMART health
    ├── 03_USERS_AUTH.log        ← accounts, groups, SSH keys, login history
    ├── 04_SCHEDULED_JOBS.log    ← cron, systemd timers, at jobs, anacron
    ├── 05_PROCESSES.log         ← running processes, open files, memory maps
    ├── 06_NETWORK.log           ← interfaces, connections, firewall, VPN, DNS
    ├── 07_SOFTWARE.log          ← installed packages, pip, snap, flatpak
    ├── 08_LOGS.log              ← auth, syslog, audit log, journal excerpts
    ├── 09_FILESYSTEM.log        ← SUID/SGID, hidden files, recent changes
    ├── 10_FILE_LISTING.log      ← full recursive directory listing
    ├── 11_MEMORY.log            ← acquisition method, hashes of memory image
    ├── 12_TRIAGE_ARCHIVE.log    ← tar manifest, stat metadata, archive hash
    ├── 13_CONTAINERS.log        ← Docker, Podman, LXC/LXD, namespaces
    ├── 14_CLOUD.log             ← cloud-init, IMDS queries, agent logs
    ├── 15_ANTI_FORENSICS.log    ← rootkit indicators, timestomping, evasion
    ├── 16_WEB_APP.log           ← web servers, databases, web shells
    ├── 17_PERSISTENCE.log       ← shell profiles, dotfiles, Python hooks
    ├── 18_SECRETS.log           ← credential files, private keys, keystores
    ├── 19_CLAMAV.log            ← ClamAV process + filesystem scan results
    ├── webserver01.MALWARE_APT.tar  ← archived key forensic files
    └── webserver01.2025-11-14T143022Z.lime  ← memory image (if acquired)
```

The numeric prefixes on log files are intentional. They ensure that `ls` and file explorers display files in investigative priority order — the manifest first, then artifacts ordered from most-volatile to least-volatile, with the memory image and archive at the end.

---

## Usage

### Interactive Mode

```bash
sudo ./LBFTT.sh
```

Launches the full interactive menu. The examiner is guided through case creation, pre-flight checks, and profile selection. This is the recommended mode for field use.

### Non-Interactive / CLI Mode

```bash
sudo ./LBFTT.sh <profile>
```

Runs a specific profile without any interactive prompts. Designed for scripted, automated, or remote deployment scenarios.

```bash
sudo ./LBFTT.sh baseline
sudo ./LBFTT.sh full_ir
sudo ./LBFTT.sh fast_ir
sudo ./LBFTT.sh network_ir
sudo ./LBFTT.sh web_intrusion
sudo ./LBFTT.sh cloud_ir
sudo ./LBFTT.sh malware_apt
sudo ./LBFTT.sh insider_threat
```

### Case Creation

Before running any collection, examiners are strongly encouraged to create a case using option **3** on the main menu. Case metadata — case number, case name, examiner name, and agency — is embedded in the manifest and every log file header, providing a documented chain of custody from the moment collection begins.

If collection is initiated without a case, the tool displays a prominent warning and requires explicit confirmation before proceeding. Case fields will display as `[not set]` in the manifest, which is flagged but not fatal.

---

## Collection Profiles

Profiles define which modules run and in what order. Volatile artifacts always come first within each profile. The examiner selects the profile that matches the incident type — the tool handles the rest.

### BASELINE — System Normalcy Snapshot

**Purpose:** Non-DFIR use. Establishes a documented, hashed record of a system's normal state. Intended for system administrators, compliance documentation, and pre-incident baselining to enable future change detection.

**Does not include:** Memory acquisition, incident-specific modules, or ClamAV scanning.

**Modules:** System → Hardware → Users → Scheduled Jobs → Processes → Network → Software → Filesystem → File Listing

---

### FULL IR — Complete Forensic Collection

**Purpose:** Comprehensive collection of all 19 modules including ClamAV scanning. Used when time permits a thorough investigation and the examiner wants to ensure no artifact category is missed. This is the slowest profile.

**Modules (in execution order):** Memory → Processes → Network → System → Hardware → Users → Scheduled Jobs → Logs → Software → Containers → Cloud → Anti-Forensics → Web App → Persistence → Secrets → Filesystem → File Listing → ClamAV → Triage Archive

---

### FAST IR — Volatile + Critical Artifacts

**Purpose:** Rapid collection of the most time-sensitive artifacts during an active incident. Prioritizes volatile data that will be lost if the system is powered off or the attacker takes further action.

**Modules:** Memory → Processes → Network → System → Users → Scheduled Jobs → Anti-Forensics → Logs → Triage Archive

---

### NETWORK IR — Network Intrusion Investigation

**Purpose:** Focused collection for network-based intrusions — unauthorized access, lateral movement, C2 communication, and data exfiltration scenarios.

**Modules:** Memory → Processes → Network → Logs → Containers → Cloud → Anti-Forensics → Triage Archive

**Rationale:** Network intrusions are primarily evidenced by active connections, process-to-socket mappings, firewall rule modifications, DNS queries, and VPN/proxy configurations. Container and cloud modules are included because modern network intrusions frequently pivot through containerized services or abuse cloud metadata endpoints.

---

### WEB INTRUSION — Web Server Compromise

**Purpose:** Focused collection for compromised web servers — web shell deployment, application exploitation, and web-based malware installation.

**Modules:** Memory → Processes → Network → Web App → Filesystem → Logs → Persistence → Anti-Forensics → Triage Archive

**Rationale:** Web intrusions leave evidence in web server access/error logs, recently modified files in web roots, suspicious PHP/JSP files containing execution functions, and persistence mechanisms in shell profiles and cron. The filesystem module is prioritized to capture file modification timestamps before they change.

---

### CLOUD IR — Cloud & Container Incident

**Purpose:** Incidents involving cloud infrastructure, container escapes, metadata API abuse, or compromised cloud agents.

**Modules:** Memory → Processes → Network → Cloud → Containers → Secrets → Logs → Anti-Forensics → Triage Archive

**Rationale:** Cloud incidents require specific evidence that general triage tools miss — cloud-init logs, instance metadata service (IMDS) query history, cloud agent logs (AWS SSM, GCP Guest Agent, Azure WaLinux), Kubernetes configurations, and credential files for cloud providers. The secrets module is included because cloud incidents frequently involve theft of IAM credentials, service account keys, and kubeconfig tokens.

---

### MALWARE / APT — Malware & Advanced Persistent Threat

**Purpose:** Deep investigation of malware infections and advanced persistent threat activity, including rootkits, fileless malware, persistence mechanisms, and long-dwell-time intrusions.

**Modules:** Memory → Processes → Anti-Forensics → ClamAV → Persistence → Scheduled Jobs → Filesystem → Logs → Secrets → Triage Archive

**Rationale:** APT investigations require hunting across multiple dimensions simultaneously. Memory acquisition captures malware running in RAM before it can clean up. Anti-forensics checks expose rootkit techniques (hidden processes, hidden ports, timestomping, preload hijacking). ClamAV scans identify known malware signatures in both running processes and staging directories. Persistence and scheduled jobs modules reveal how the attacker maintains access. Secrets collection documents what credentials may have been compromised.

---

### INSIDER THREAT — User Activity & Data Access

**Purpose:** Investigations involving malicious, negligent, or unauthorized activity by legitimate users — data theft, unauthorized access, policy violations, and account misuse.

**Modules:** Processes → Users → Logs → Persistence → Secrets → Filesystem → Scheduled Jobs → Network → Triage Archive

**Rationale:** Insider threat evidence is primarily behavioral — who logged in, when, from where, what commands they ran, what files they accessed, and whether they installed hidden persistence mechanisms or exfiltrated credentials. Note that memory acquisition is not included by default in this profile, as insider threat investigations often involve systems that cannot be immediately powered down and where the legal authority to acquire memory may be more complex.

---

## Collection Modules

### 01 — System Information

Captures the fundamental identity and state of the operating system. Includes `hostnamectl`, `uname -a`, `/etc/os-release`, `timedatectl`, system uptime, last reboot events, memory summary, `/proc/meminfo`, kernel error messages via `dmesg`, loaded kernel modules (`lsmod`), kernel runtime parameters (`sysctl -a`), current environment variables, and running/failed systemd units.

**Extended boot integrity collection:** GRUB configuration (`/boot/grub/grub.cfg`), `/boot` directory full listing with SHA-256 hashes of every file, initramfs contents via `lsinitramfs`, UEFI boot entries via `efibootmgr -v`, EFI variable listing, and Secure Boot state via `mokutil`. Any unexpected file in `/boot` or any UEFI boot entry added without authorization is a significant indicator of bootkit persistence.

### 02 — Hardware

Full hardware inventory via `lshw`, CPU details (`lscpu`), block device listing with filesystem types, UUIDs, models, and serial numbers (`lsblk`), partition tables (`fdisk -l`), filesystem UUIDs (`blkid`), disk usage (`df -h`), PCI devices (`lspci -vvv`), USB devices (`lsusb -v`), SCSI devices (`lsscsi`), BIOS/UEFI DMI data (`dmidecode`), current mount points, and SMART disk health for all block devices.

### 03 — Users & Authentication

Currently logged-on users, full login history (`last -F -w`), failed login attempts (`lastb -F -w`), all user accounts (`/etc/passwd`), shadow password file (`/etc/shadow`), all groups, sudoers configuration and `/etc/sudoers.d/` contents, accounts with UID 0 (root equivalents), accounts with empty passwords, per-user SSH authorized keys, per-user bash and zsh history files, PAM configuration, and per-user systemd units.

### 04 — Scheduled Jobs

System and per-user crontabs, `/etc/cron.d/` and all cron period directories, `at` and `batch` job queues, `anacron` configuration, all systemd timer units and their next trigger times, and `/etc/rc.local`. Scheduled jobs are one of the most common persistence mechanisms and require comprehensive collection — a single malicious cron entry or systemd timer can maintain attacker access indefinitely.

### 05 — Processes

Full process listing with all fields (`ps auxwwf`), process tree, open file handles for all processes (`lsof`), per-process memory maps for the first 20 PIDs (`/proc/*/maps`), active TTY and PTY devices, processes attached to terminal sessions, and recovery of `typescript` session log files. The process tree is particularly valuable for identifying unusual parent-child relationships that indicate process injection or masquerading.

### 06 — Network

Network interfaces with full configuration (`ip addr`, `ip link`), routing tables (`ip route`), ARP/neighbor cache (`ip neigh`), all active connections and listening ports (`ss -tulpan`), nftables and iptables firewall rules, network namespaces, SSH server and client configurations, DNS resolution cache and recent DNS queries via `systemd-resolved`, WireGuard interface state and configuration files, OpenVPN configuration files, proxy environment variables, traffic control rules (`tc`), and raw kernel network tables (`/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/arp`, `/proc/net/route`).

The raw `/proc/net` tables are collected independently of `ss` output specifically to support rootkit detection — a rootkit that hooks the `ss`/`netstat` system calls to hide connections cannot easily hide from the kernel's raw tables.

### 07 — Software

Installed packages via `dpkg` (Debian/Ubuntu) and `rpm` (RHEL/CentOS), package integrity verification via `dpkg --verify` and `rpm -Va` (flags modified system binaries), pip-installed Python packages for all users, snap packages, flatpak applications, and running Python/Ruby/Node.js interpreters with their loaded scripts.

### 08 — System Logs

Authentication logs (`/var/log/auth.log`, `/var/log/secure`), system logs (`/var/log/syslog`, `/var/log/messages`), kernel log (`/var/log/kern.log`), audit log (`/var/log/audit/audit.log`), failed login log (`/var/log/btmp` via `lastb`), package manager log, and systemd journal excerpts for authentication events, sudo usage, and service failures.

### 09 — Filesystem Anomalies

SUID and SGID binaries, world-writable files and directories, hidden files in sensitive locations, files modified within the last 24 hours across the entire filesystem, immutable files (`chattr +i`), LD_PRELOAD configuration, XDG autostart entries, and files with capabilities set (`getcap -r /`). This module uses `-xdev` on all `find` operations to stay within a single filesystem and avoid hanging on `/proc` or `/sys`.

### 10 — Full File Listing

Complete recursive listing of the entire filesystem with permissions, ownership, size, and timestamps (`ls -laR /`). Used primarily in BASELINE and FULL IR where comprehensive change detection is required. This is the slowest module and is excluded from time-sensitive profiles.

### 11 — Memory

See [Memory Acquisition](#memory-acquisition) section for full details.

### 12 — Triage Archive

Creates a tar archive of key forensic files for rapid analysis without requiring the examiner to navigate the full filesystem. Captures `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/`, all crontabs, hostname/hosts/resolv.conf, SSH server configuration, PAM configuration, OS release files, `/etc/ld.so.preload`, authentication and system logs, btmp/wtmp/lastlog, root's bash/zsh history, root's `.ssh` directory, `/tmp`, and `/var/tmp`. FULL mode additionally includes `/home`, `/var/spool/cron`, `/etc/init.d`, and `/etc/profile.d`. File timestamps are captured via `stat` before archiving to preserve access time metadata. The archive itself is SHA-256 hashed and the hash is recorded in the manifest.

### 13 — Containers & Virtualization

Docker container and image inventory including full `docker inspect` output for all containers (exposes mounted volumes, environment variables, network configuration, and restart policies), Docker daemon configuration, socket permissions, and `/var/lib/docker` directory listing. Podman equivalent collection. LXC/LXD container and storage pool listings. Kubernetes cluster info, pod listings across all namespaces, and kubeconfig file locations. Linux namespace inventory via `lsns` and `/proc/*/ns` links. Cgroups hierarchy. Virtualization detection via `systemd-detect-virt`, dmesg fingerprints, and DMI vendor strings.

Container inspect output is forensically valuable because it exposes what volumes were mounted (potential data access paths), what environment variables were set (potential credential exposure), and what network interfaces were configured (potential hidden communication channels).

### 14 — Cloud & Infrastructure Agents

Cloud-init status, configuration, and all log files. Instance Metadata Service (IMDS) queries for AWS, GCP, and Azure — these queries are performed to document what credential and configuration information an attacker could have accessed via the metadata API from a compromised instance. AWS SSM Agent and CloudWatch Agent status and logs. GCP Guest Agent status and logs. Azure WaLinux Agent logs. AWS CLI, gcloud, and Azure CLI configuration files. Infrastructure automation agent detection (Puppet, Chef, Ansible, Salt) and Terraform state file locations.

### 15 — Anti-Forensics & Rootkit Indicators

The `15_ANTI_FORENSICS.log` module is specifically designed to detect active evasion techniques and rootkit indicators.

#### PID Discrepancy Check

Compares the list of PIDs visible in `/proc` against the list returned by `ps`. Any PID present in `/proc` but absent from `ps` output is a strong indicator of a kernel-level rootkit that hooks the `readdir` system call to hide processes. The tool sorts and diffs both lists and flags any discrepancies explicitly.

#### Network Port Discrepancy Check

Compares listening ports in `/proc/net/tcp` (raw kernel table) against ports reported by `ss`. A rootkit that hooks socket-related system calls to hide network listeners cannot easily hide from the kernel's raw tables, creating a detectable discrepancy.

#### Kernel Symbol Anomalies

Reads `/proc/kallsyms` and reports symbols that fall outside standard kernel sections. Unexpected kernel symbols can indicate a rootkit that has hooked system calls or inserted malicious kernel code.

#### `/dev` Anomaly Detection

Scans `/dev` for files that are not device nodes, symlinks, directories, or pipes. Regular files in `/dev` are a classic rootkit hiding technique — the directory is rarely inspected and most monitoring tools ignore it.

#### Preload Hijacking

Checks `/etc/ld.so.preload` for existence and content. If present, the file is flagged with `[ALERT]` and every library it references is individually hashed. LD_PRELOAD injection is one of the most common userspace rootkit techniques on Linux. Additionally searches for `.so` files in non-standard paths (outside `/lib`, `/lib64`, `/usr/lib`) which may indicate injected shared libraries.

#### Rootkit Scanners

Executes `rkhunter` and `chkrootkit` if available on the system. Also checks for a `chkrootkit` binary placed on the USB drive alongside the script, enabling USB-based rootkit scanning without installing anything on the target system.

#### Timestomping Detection

Three layers of timestomping detection:

1. **ctime vs. mtime delta** — Files where the inode change time (`ctime`) is significantly newer than the modification time (`mtime`) may have had their `mtime` manually backdated. A large delta (more than 24 hours by default) is flagged. This check runs **outside the standard `run_cmd` wrapper** with a dedicated 600-second timeout and is scoped to the following high-value directories rather than the full filesystem:

   ```
   /bin  /sbin  /usr/bin  /usr/sbin  /usr/lib  /usr/local
   /etc  /home  /root  /tmp  /var/tmp  /opt  /srv
   ```

   **Why scoped and not full-filesystem:** A full `find / -xdev` walk combined with per-file `stat` calls routinely exceeds 120 seconds on systems with large home directories, Rust cargo registries, or Python virtual environments — timing out before producing any output. The scoped path list covers every location where timestomped malware would realistically be staged or installed. Paths excluded from this check include `/snap` (loop-mounted squashfs files inflate runtime with zero forensic value for timestomping), `/boot` (static after install), `/dev`, `/proc`, `/sys`, and `/run`.

   **If `[WARNING] Timestomping check timed out` appears in `15_ANTI_FORENSICS.log`:** The 600-second budget was exhausted before the scan completed. This is most likely caused by an exceptionally large directory tree under one of the scoped paths (e.g. a very large `/home` with many source trees or package caches). To investigate manually, run the check directly against a specific subdirectory:
   ```bash
   find /home -xdev -type f | while IFS= read -r f; do
       mtime=$(stat -c %Y "$f" 2>/dev/null)
       ctime=$(stat -c %Z "$f" 2>/dev/null)
       diff=$(( ctime - mtime ))
       [ "$diff" -gt 86400 ] && echo "DIFF=${diff}s  $(stat -c "%n  mtime=%y  ctime=%z" "$f")"
   done | sort -rn | head -100
   ```

2. **Binaries newer than OS install date** — System binaries in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` with `mtime` newer than the OS installation date (approximated by `/etc/os-release` timestamp) are flagged as potentially replaced or modified.

3. **`debugfs` inode creation time** — On ext4 filesystems, `debugfs` can retrieve the inode creation time (`crtime`), which is not exposed by `stat` and is significantly harder to modify than `mtime`. This provides a ground truth timestamp that is difficult for an attacker to falsify.

### 16 — Web Servers & Application Artifacts

Running web server process detection. Apache and Nginx version, configuration files, virtual host configurations, and last 500 lines of access and error logs. Web root directory listings for all standard web root paths. Recently modified files in web roots (last 7 days). Pattern-based web shell detection — scans PHP, PHTML, PHP5, JSP, JSPX, CGI, and Perl files for execution functions (`exec`, `system`, `passthru`, `shell_exec`, `eval`). PHP session files. MySQL/MariaDB, PostgreSQL, MongoDB, and Redis status, configuration, and error logs. Tomcat, Node.js, Gunicorn, and uWSGI process detection.

### 17 — Profile-Based Persistence

Global shell profiles (`/etc/profile`, `/etc/bash.bashrc`, `/etc/zshrc`, `/etc/environment`) and all `/etc/profile.d/` scripts. Per-user shell profiles (`.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.zprofile`, `.bash_logout`) for all users including root. Vim configuration (`.vimrc` can contain autocommands that execute shell code). Git configuration (`.gitconfig` can contain credential helpers and hooks). Git repository hook files across the filesystem. Per-user SSH client configuration files (`.ssh/config` can redirect connections through attacker infrastructure). Python `sitecustomize.py` and `usercustomize.py` files (executed automatically on every Python interpreter start). Python `.pth` files in site-packages (can inject arbitrary paths into Python's module search path). Per-user `~/.config/` directory listings. GNOME/KDE/XDG autostart entries (system and per-user). Display manager startup scripts. PAM module hashes and NSS configuration.

### 18 — Cryptographic Material & Secrets

Private key file detection by searching for PEM header strings. Metadata and hashes of all private key files (`.key`, `.pem`, `.p12`, `.pfx`, `id_rsa`, `id_ecdsa`, `id_ed25519`, `id_dsa`) — the tool records file existence, permissions, ownership, and hash without reading private key content. SSH private keys for all users. SSL/TLS certificate metadata (subject, issuer, validity dates). GPG keyring listings and GPG agent sockets. AWS credentials files (secret access keys are excluded from logging). GCP service account key file hashes. Kubernetes config files (tokens and certificate data excluded). `.netrc` files (plaintext FTP/HTTP credentials). `.pgpass` (PostgreSQL passwords). `.my.cnf` (MySQL credentials). `.env` files in web and application directories. KeePass database files (`.kdbx`) and Java keystores with hashes.

The sensitivity notice at the top of this log explicitly documents that the tool records existence and metadata rather than raw key material — providing a clear basis for handling the log as sensitive material under chain-of-custody controls.

### 19 — ClamAV Antivirus Scan

See [ClamAV Integration](#clamav-integration) section for full details.

---

## Memory Acquisition

Memory acquisition is always the first action in any IR profile, before any other module runs. This ordering is not configurable — it reflects the fundamental principle that memory is the most volatile artifact and must be captured before any further filesystem or process activity can alter it.

### Tool Selection — Priority Order

**1. [LiME (Linux Memory Extractor)](https://github.com/504ensicsLabs/LiME) — Preferred**

LiME is a loadable kernel module (LKM) that acquires physical memory from kernel space. Because acquisition happens inside the kernel, there is minimal userspace footprint — the acquisition process itself is not visible to userspace rootkits that hook `ps` or `/proc`. LiME outputs in the native `.lime` format, which is directly compatible with Volatility 3 and Rekall for offline memory analysis.

The LiME module must be pre-compiled against the exact kernel version running on the target system. The naming convention enforced by LBFTT is:

```
lime-<uname -r>.ko
e.g. lime-6.8.0-51-generic.ko
```

The tool automatically selects the correct module by matching `uname -r` at runtime. Multiple `.ko` files for different kernel versions can coexist on the USB drive.

**Building LiME for a target kernel:**
```bash
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make
cp lime.ko /mnt/FORENSICS/lime-$(uname -r).ko
```

**2. [AVML (Acquire Volatile Memory for Linux)](https://github.com/microsoft/avml) — Fallback**

AVML is a statically-linked userspace binary from Microsoft that acquires memory via `/dev/crash`, `/proc/kcore`, or `/dev/mem` depending on what the kernel exposes. It requires no compilation and works across kernel versions without preparation — simply placing the binary on the USB is sufficient. The tradeoff is that userspace acquisition is slightly more intrusive than LiME and may be blocked on hardened kernels.

> **Secure Boot / Kernel Lockdown:** On systems with Secure Boot enabled, the kernel lockdown mode is typically set to `[integrity]` or `[confidentiality]`. In these states, unsigned LiME kernel modules **will be blocked from loading** regardless of whether the `.ko` file is present on the USB. AVML is unaffected by lockdown because it operates entirely from userspace. On Secure Boot systems, **AVML is the correct tool** — do not waste time building a LiME module unless you can also sign it with a key enrolled in the MOK database. The `11_MEMORY.log` records both the kernel lockdown state and Secure Boot state to document this constraint for the case file.

**3. Skip — Neither Available**

If neither tool is present, memory acquisition is skipped and the log contains detailed instructions for obtaining and deploying both tools. Collection continues with all remaining modules.

### Pre-Acquisition Checks

Before loading LiME, the tool checks whether a LiME module is already loaded from a previous run and cleanly unloads it if so. If `insmod` fails, the log records the three most common causes: wrong kernel version, Secure Boot blocking unsigned module load, or kernel lockdown mode. The kernel lockdown mode state (`/sys/kernel/security/lockdown`) and Secure Boot state are recorded in the memory log regardless of which tool was used.

---

## ClamAV Integration

ClamAV scanning is included in the **MALWARE/APT** and **FULL IR** profiles. All scanning is performed in strict read-only mode — no files are removed, modified, or quarantined under any circumstances.

### ClamAV Portable Bundle

LBFTT is compatible with a self-contained portable ClamAV bundle that you build yourself by following the step-by-step instructions in the [Building the bundle](#building-the-bundle) section below. The bundle requires no installation on the target system — once built, place it on the forensic USB alongside `LBFTT.sh` and the script handles detection, extraction, scanning, and cleanup automatically.

#### What the bundle contains

The bundle is a single `.tar.gz` archive that extracts to a complete ClamAV environment:

```
bundle/
├── bin/
│   ├── clamscan.sh       ← wrapper script (use this, not the bare binary)
│   ├── freshclam.sh      ← wrapper script for signature updates
│   ├── clamdscan.sh      ← wrapper script for daemon-based scanning
│   ├── clamscan          ← musl-linked binary (do not call directly)
│   ├── freshclam         ← musl-linked binary (do not call directly)
│   ├── clamdscan         ← musl-linked binary (do not call directly)
│   └── sigtool           ← signature inspection utility
├── lib/
│   ├── ld-musl-x86_64.so.1   ← musl libc loader
│   ├── libclamav.so.*         ← ClamAV library
│   ├── ca-certificates.crt    ← CA bundle for freshclam HTTPS updates
│   └── [all required .so dependencies]
├── etc/
│   ├── freshclam.conf    ← freshclam configuration
│   └── clamd.conf        ← clamd configuration
└── db/
    ├── main.cvd          ← main virus database (~85 MB, ~3.2M signatures)
    ├── daily.cvd         ← daily updates (~23 MB, ~355K signatures)
    └── bytecode.cvd      ← bytecode rules (~276 KB)
```

The binaries are statically linked against **musl libc** (extracted from Alpine Linux packages) and carry all required shared libraries inside the bundle. They will run on any Linux x86_64 system regardless of what libc version or distribution is installed — including minimal or hardened environments. The wrapper scripts (`clamscan.sh`, `freshclam.sh`) invoke the musl loader explicitly and set required environment variables; always use the wrapper scripts, not the bare binaries.

#### Bundle detection priority

When `collect_clamav` runs, it searches for a ClamAV binary in the following order:

1. **Portable bundle tarball** — any file matching `clamav-*-portable-*.tar.gz` in `$SCRIPT_DIR`. If found, the bundle is extracted to a temporary directory, used for scanning, and cleaned up automatically at module exit.
2. **System-installed clamscan** — `command -v clamscan`
3. **Bare USB binary** — `$SCRIPT_DIR/clamscan` (legacy fallback)

If none are found, the module logs detailed instructions and skips gracefully without aborting the collection.

#### Building the bundle

The portable bundle is built from Alpine Linux APK packages using the following method. No compilation, no Docker, and no root access required on the build host.

**Prerequisites:** An Ubuntu/Debian x86_64 build host with `wget` and `tar`.

**Step 1 — Download Alpine package index**
```bash
wget -q https://dl-cdn.alpinelinux.org/alpine/v3.21/community/x86_64/APKINDEX.tar.gz     -O /tmp/APKINDEX-community.tar.gz
wget -q https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/APKINDEX.tar.gz     -O /tmp/APKINDEX-main.tar.gz
mkdir -p /tmp/apk-community /tmp/apk-main
tar xzf /tmp/APKINDEX-community.tar.gz -C /tmp/apk-community/
tar xzf /tmp/APKINDEX-main.tar.gz -C /tmp/apk-main/
```

**Step 2 — Download all required packages**

From the Alpine 3.21 community repository:
- `clamav-scanner-1.4.2-r0.apk`
- `clamav-clamdscan-1.4.2-r0.apk`
- `clamav-libs-1.4.2-r0.apk`
- `clamav-daemon-1.4.2-r0.apk`
- `freshclam-1.4.2-r0.apk`
- `libmspack-0.11_alpha-r1.apk`

From the Alpine 3.21 main repository:
- `musl-1.2.5-r9.apk`, `libgcc-14.2.0-r4.apk`
- `libcrypto3-3.3.6-r0.apk`, `libssl3-3.3.6-r0.apk`
- `libxml2-2.13.9-r0.apk`, `pcre2-10.43-r0.apk`, `json-c-0.18-r0.apk`
- `zlib-1.3.1-r2.apk`, `bzip2-1.0.8-r6.apk`, `libbz2-1.0.8-r6.apk`
- `xz-libs-5.6.3-r1.apk`, `libcurl-8.14.1-r2.apk`, `brotli-libs-1.1.0-r2.apk`
- `c-ares-1.34.6-r0.apk`, `libidn2-2.3.7-r0.apk`, `libpsl-0.21.5-r3.apk`
- `nghttp2-libs-1.64.0-r0.apk`, `zstd-libs-1.5.6-r2.apk`, `libunistring-1.2-r0.apk`

> **Important:** `freshclam` is a **separate top-level package** in the community repo — it is not bundled inside `clamav-scanner` or `clamav-daemon`. It must be downloaded explicitly.

**Step 3 — Extract packages and assemble bundle**
```bash
mkdir -p $HOME/clamav-portable
cd $HOME/clamav-portable
mkdir -p bundle/{bin,lib,etc,db}

# Extract each .apk (they are gzip-compressed tar archives)
for pkg in clamav-scanner clamav-clamdscan clamav-libs clamav-daemon freshclam            libmspack musl libgcc libcrypto3 libssl3 libxml2 pcre2            json-c zlib bzip2 libbz2 xz-libs libcurl brotli-libs c-ares            libidn2 libpsl nghttp2-libs zstd-libs libunistring; do
    mkdir -p extracted/$pkg
    tar xzf ${pkg}*.apk -C extracted/$pkg 2>/dev/null || true
done

# Copy binaries
cp extracted/clamav-scanner/usr/bin/clamscan     bundle/bin/
cp extracted/clamav-scanner/usr/bin/sigtool       bundle/bin/
cp extracted/clamav-clamdscan/usr/bin/clamdscan   bundle/bin/
cp extracted/freshclam/usr/bin/freshclam          bundle/bin/

# Copy musl loader
cp extracted/musl/lib/ld-musl-x86_64.so.1        bundle/lib/
cp extracted/musl/lib/libc.musl-x86_64.so.1      bundle/lib/

# Copy all shared libraries
for pkg in clamav-libs libgcc libcrypto3 libssl3 libxml2 pcre2 json-c            zlib libbz2 xz-libs libmspack libcurl brotli-libs c-ares            libidn2 libpsl nghttp2-libs zstd-libs libunistring; do
    cp extracted/$pkg/usr/lib/*.so* bundle/lib/ 2>/dev/null || true
done

# Copy configs and CA certificates (required for freshclam HTTPS)
cp extracted/freshclam/etc/clamav/freshclam.conf bundle/etc/
cp extracted/clamav-daemon/etc/clamav/clamd.conf bundle/etc/
cp /etc/ssl/certs/ca-certificates.crt bundle/lib/

# Point freshclam config at runtime DB directory
sed -i 's|^DatabaseDirectory.*|DatabaseDirectory /tmp/clamav-dfir/db|' bundle/etc/freshclam.conf
sed -i 's|^#DatabaseDirectory.*|DatabaseDirectory /tmp/clamav-dfir/db|' bundle/etc/freshclam.conf
```

**Step 4 — Create wrapper scripts**
```bash
cat > bundle/bin/clamscan.sh << 'WRAPPER'
#!/bin/bash
BUNDLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec "$BUNDLE_DIR/lib/ld-musl-x86_64.so.1"      --library-path "$BUNDLE_DIR/lib"      "$BUNDLE_DIR/bin/clamscan" "$@"
WRAPPER

cat > bundle/bin/freshclam.sh << 'WRAPPER'
#!/bin/bash
BUNDLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export SSL_CERT_FILE="$BUNDLE_DIR/lib/ca-certificates.crt"
export CURL_CA_BUNDLE="$BUNDLE_DIR/lib/ca-certificates.crt"
exec "$BUNDLE_DIR/lib/ld-musl-x86_64.so.1"      --library-path "$BUNDLE_DIR/lib"      "$BUNDLE_DIR/bin/freshclam" "$@"
WRAPPER

cat > bundle/bin/clamdscan.sh << 'WRAPPER'
#!/bin/bash
BUNDLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec "$BUNDLE_DIR/lib/ld-musl-x86_64.so.1"      --library-path "$BUNDLE_DIR/lib"      "$BUNDLE_DIR/bin/clamdscan" "$@"
WRAPPER

chmod +x bundle/bin/clamscan.sh bundle/bin/freshclam.sh bundle/bin/clamdscan.sh
```

> **SSL note:** The `SSL_CERT_FILE` and `CURL_CA_BUNDLE` environment variables in `freshclam.sh` are required. Without them, freshclam cannot verify HTTPS connections to the ClamAV signature update servers, causing update failures even when the network is available.

**Step 5 — Download virus databases and package**
```bash
# Use absolute path for --datadir — relative paths fail
bundle/bin/freshclam.sh     --config-file=bundle/etc/freshclam.conf     --datadir=$HOME/clamav-portable/bundle/db

# Package and record SHA-256
cd $HOME/clamav-portable
tar czf clamav-1.4.2-portable-x86_64-with-db.tar.gz bundle/
sha256sum clamav-1.4.2-portable-x86_64-with-db.tar.gz     > clamav-1.4.2-portable-x86_64-with-db.tar.gz.sha256
```

The final error from freshclam (`NotifyClamd: Can't find clamd.conf`) is harmless — it occurs because clamd is not running, which is expected in an offline bundle.

**Step 6 — Copy to USB**
```bash
cp clamav-1.4.2-portable-x86_64-with-db.tar.gz      /mnt/FORENSICS/
cp clamav-1.4.2-portable-x86_64-with-db.tar.gz.sha256 /mnt/FORENSICS/
```

#### Verified bundle hashes (build date: March 2026, Alpine 3.21, ClamAV 1.4.2)

| File | SHA-256 |
|---|---|
| Bundle without DB | `f72309b63b86bcaa31ab9071be023fbd0cc6c737d62c4ceb0edd5c9aa9ae0a25` |
| Bundle with DB | `d621f48180f27ffcbbbfe28ac48f70c1316041628c4635f7c8e98ebb30b9cdc5` |

These hashes are recorded for chain-of-custody purposes. If you rebuild the bundle from fresh packages the hashes will differ — record the new hashes in your case documentation.

### Three-Pass Scan Architecture

**Pass 1 — Process Executables (`/proc/*/exe`)**

Scans the executable image backing every running process. The tool resolves and deduplicates exe links to avoid redundant scans of shared binaries (e.g. scanning `bash` once rather than once per shell session). Critically, the scan targets the `/proc/<pid>/exe` symlink rather than just the resolved path — this ensures that binaries which are currently running but have already been deleted from disk are still scanned. Deleted-but-running malware appears as `/proc/<pid>/exe (deleted)` in results.

**Pass 2 — Open File Descriptors (`/proc/*/fd`)**

Scans all file descriptors held open by running processes. This catches malicious shared libraries injected into process memory space, malicious scripts currently being interpreted, and data files open by C2 tools — including files that have been deleted from disk but remain accessible via their open file descriptor handle.

**Pass 3 — High-Probability Filesystem Directories**

Targeted scan of 20 directories ordered by likelihood of containing malware:

```
/tmp            /var/tmp        /dev/shm        /run
/root           /home           /var/www        /srv
/opt            /usr/local/bin  /usr/local/sbin /usr/local/lib
/etc/cron.d     /etc/cron.daily /etc/cron.hourly
/etc/cron.weekly /etc/cron.monthly
/etc/init.d     /etc/profile.d  /var/spool/cron
```

The tool checks which directories exist before scanning and logs `[EXISTS]` or `[SKIP]` for each, making the log self-documenting on systems with non-standard layouts.

### Signature Updates

If `freshclam` is available, the tool prompts the examiner before scanning whether to update virus signatures. The prompt includes an explicit warning that network activity may not be appropriate during an active investigation — giving the examiner the information they need to make the right call for their situation. Signature update choice and outcome are recorded in the log.

### Forensic Safety Flags

The following flags are explicitly **NOT** used: `--remove`, `--quarantine`, `--move`. The log opens with a `FORENSIC NOTICE` block documenting this. Flags that are used:

| Flag | Purpose |
|---|---|
| `--infected` | Report only infected files — keeps log readable |
| `--recursive` | Scan subdirectories |
| `--no-summary` | Suppress per-scan footer — cleaner log |
| `--follow-dir-symlinks=0` | Prevent directory symlink traversal |
| `--follow-file-symlinks=0` | Prevent file symlink traversal |
| `--max-filesize=100M` | Skip files larger than 100 MB |
| `--max-scansize=100M` | Cap scan data per file |
| `--suppress-ok-results` | Log detections only, not clean results |

### Detection Summary

The log closes with a summary section that counts all `FOUND` entries across all three passes and reprints them in one consolidated block, so examiners can see all detections without scrolling through the full scan output.

---

## Chain of Custody & Manifest

The manifest (`00_MANIFEST.log`) is the authoritative chain-of-custody document for a collection run. It is created at the start of collection and finalized at the end.

**Manifest contents:**

- Case metadata (case number, name, examiner, agency, notes, creation date)
- System identification at time of collection (hostname, kernel, UTC timestamp)
- Collection profile and case directory path
- For each log file: file path, MD5, SHA-1, SHA-256, and file size
- For the memory image: all three hashes and image size
- Collection summary: total files, total size, end time, elapsed time
- Manifest self-hash: the manifest hashes itself at finalization, so any post-collection tampering with the manifest is detectable

**Per-artifact hashing:**

Every log file is hashed with MD5, SHA-1, and SHA-256 after it is written and before the next module runs. The hashes are written into the artifact's own log and into the manifest simultaneously. This means that if an individual log is tampered with after collection, both its internal hash record and the manifest entry will no longer match.

**File timestamps:**

`stat` output is captured for every file in the triage archive before archiving. This preserves access time, modification time, and change time metadata that would otherwise be lost or altered by the archiving process.

---

## Forensic Safety Principles

LBFTT is designed to be used as evidence-collection software. The following principles govern its behavior:

- **No writes to target filesystem** — all output is written to the forensic USB (`/mnt/FORENSICS`). The only exception is temporary files in `/tmp` used during anti-forensics checks, which are explicitly cleaned up before the module exits.
- **No process termination** — LBFTT never kills, pauses, or signals any process on the target system.
- **No file deletion or modification** — no file on the target system is ever deleted, moved, renamed, or modified.
- **No software installation** — LBFTT never installs packages, kernel modules (other than LiME for memory acquisition), or other software on the target system. LiME is unloaded immediately after acquisition completes.
- **No quarantine** — ClamAV is invoked without `--remove`, `--quarantine`, or `--move` flags. This is documented in code comments and in the ClamAV log's forensic notice block.
- **Timeout protection** — long-running commands are wrapped with `timeout` to prevent the tool from hanging indefinitely on a single command. Memory acquisition allows 3600 seconds (1 hour); most other commands allow 120 seconds. The timestomping ctime/mtime delta check is an explicit exception — it runs outside `run_cmd` with a dedicated 600-second timeout and a scoped path list to avoid exhausting the standard budget.
- **Error isolation** — a failure or error in any individual command is logged and the tool continues. `set -euo pipefail` is active at the script level but collection functions use `|| true` patterns to prevent individual command failures from aborting the collection.

---

## Adding New Profiles

To add a new collection profile:

**1.** Write a new profile function using the existing pattern:

```bash
run_my_new_profile() {
    run_profile "MY_PROFILE_NAME" \
        collect_memory \
        collect_process_info \
        collect_network_info \
        collect_log_files \
        collect_triage_files_profile
}
```

**2.** Add it to the interactive menu in `show_profile_menu()`:

```bash
echo -e "  ${CYAN}12)${RESET}  ${YELLOW}MY PROFILE${RESET}"
echo -e "      One-line description of what this profile collects"
```

And add the corresponding case in the `case` statement:

```bash
12) clear; run_my_new_profile
    echo ""; read -rp "  Press ENTER to return to menu..." ;;
```

**3.** Add it to the CLI entry point:

```bash
my_profile) run_my_new_profile ;;
```

And add it to the CLI help text:

```bash
echo "    my_profile      Description for CLI help"
```

All chain-of-custody, hashing, manifest generation, and finalization behavior is handled automatically by `run_profile()` — no additional wiring is required.

---

## Changelog

| Version | Changes |
|---|---|
| 1.5.1 | **Bug fixes and improvements:** Fixed `awk strtonum()` portability error in `/proc/net` port discrepancy check (gawk-only function replaced with portable `printf` hex conversion); fixed ClamAV double-logging bug where concurrent `--log=` flag and pipe redirect caused `FOUND` detection lines to be lost or overwritten; fixed ClamAV detection summary `grep "FOUND"` self-matching its own output text (changed to `grep ": FOUND"`); fixed `systemd-detect-virt` false "not available" message on physical machines (exit code 1 means not a VM, not a missing tool); suppressed `lsattr` `Operation not supported` noise from `/proc/*/map_files/` virtual filesystem entries; added portable ClamAV 1.4.2 bundle support (musl-linked, Alpine APK extraction, compatible with user-built bundles including signature databases) with auto-detection and extraction in `collect_clamav`; added `--config-file` and absolute `--datadir` to freshclam invocation required for portable bundle; moved timestomping ctime/mtime delta check outside `run_cmd` wrapper with dedicated 600-second timeout; scoped timestomping check to high-value paths (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/local`, `/etc`, `/home`, `/root`, `/tmp`, `/var/tmp`, `/opt`, `/srv`) instead of full filesystem to avoid timeout on large home directories; added Secure Boot / kernel lockdown documentation to memory acquisition section |
| 1.5 | Added `collect_clamav` (three-pass ClamAV scan) to MALWARE/APT and FULL IR profiles |
| 1.4 | Replaced monolithic mode functions with profile-based architecture; added NETWORK IR, WEB INTRUSION, CLOUD IR, MALWARE/APT, INSIDER THREAT profiles; added `require_case_or_confirm()` central case warning; updated CLI to accept all profile names |
| 1.3 | Added 6 new collection modules: Containers (13), Cloud (14), Anti-Forensics (15), Web App (16), Persistence (17), Secrets (18); augmented Network module with VPN, DNS cache, raw /proc/net tables; augmented System module with GRUB, UEFI, boot integrity; augmented Processes module with TTY artifacts |
| 1.2 | Added LiME kernel module support with AVML fallback; dual-tool memory acquisition with automatic kernel version matching; kernel lockdown and Secure Boot detection |
| 1.1 | Restructured output from single monolithic log to per-artifact numbered log files; added chain-of-custody manifest with self-hashing; added per-command elapsed time recording |
| 1.0 | Complete rewrite from v0.2 Beta; modular architecture; `run_cmd` wrapper with timeout and graceful skip; replaced deprecated `netstat`/`ifconfig` with `ss`/`ip`; added nftables, systemd journal, authorized_keys, PAM, sudoers.d, SMART health, dpkg/rpm verification |

---

*Linux Baseline & Forensic Triage Tool (LBFTT) — Copyright © EGA Technology Specialists, LLC. — GNU GPL v3.0*
