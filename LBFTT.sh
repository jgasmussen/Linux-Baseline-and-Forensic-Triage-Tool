#!/usr/bin/env bash
# ==============================================================================
#         Linux Baseline & Forensic Triage Tool (LBFTT)
#                        Version 1.5.1
# ------------------------------------------------------------------------------
#                 Written by: John G. Asmussen
#               EGA Technology Specialists, LLC.
#                       GNU GPL v3.0
# ==============================================================================
# USAGE:
#   Interactive : sudo ./LBFTT.sh
#   CLI mode    : sudo ./LBFTT.sh [baseline|fast|full]
#
# REQUIREMENTS:
#   - Run as root / sudo
#   - Forensic USB mounted at /mnt/FORENSICS
#
# OUTPUT LAYOUT (one case directory per run):
#   /mnt/FORENSICS/
#   └── hostname.YYYY-MM-DDTHHMMSSZ.MODE/
#       ├── 00_MANIFEST.log          ← chain-of-custody index + all hashes
#       ├── 01_SYSTEM.log            ← OS identity, kernel, uptime, environment
#       ├── 02_HARDWARE.log          ← CPU, disks, PCI/USB, SMART health
#       ├── 03_USERS_AUTH.log        ← accounts, groups, SSH keys, history
#       ├── 04_SCHEDULED_JOBS.log    ← cron, systemd timers, persistence hooks
#       ├── 05_PROCESSES.log         ← running processes, open files, maps
#       ├── 06_NETWORK.log           ← interfaces, connections, firewall, VPN
#       ├── 07_SOFTWARE.log          ← installed packages, pip, snap, flatpak
#       ├── 08_LOGS.log              ← auth, syslog, audit, journal excerpts
#       ├── 09_FILESYSTEM.log        ← SUID, hidden, recent changes, hashes
#       ├── 10_FILE_LISTING.log      ← full recursive directory listing
#       ├── 11_MEMORY.log            ← LiME / AVML acquisition + hashes
#       ├── 12_TRIAGE_ARCHIVE.log    ← tar manifest, stat metadata, hashes
#       ├── 13_CONTAINERS.log        ← Docker, Podman, LXC/LXD, namespaces
#       ├── 14_CLOUD.log             ← cloud-init, metadata API, agents
#       ├── 15_ANTI_FORENSICS.log    ← rootkit indicators, timestomping, evasion
#       ├── 16_WEB_APP.log           ← web servers, DBs, app configs, web shells
#       ├── 17_PERSISTENCE.log       ← profile hooks, dotfiles, Python paths
#       ├── 18_SECRETS.log           ← credential files, keys, cloud configs
#       ├── 19_CLAMAV.log            ← ClamAV process memory + filesystem scan
#       └── hostname.MODE.tar        ← archived forensic files
#
# MEMORY ACQUISITION TOOL PRIORITY ORDER:
#   1. LiME  (lime-<kernel>.ko on USB) — kernel-space, least intrusive, preferred
#   2. AVML  (avml binary on USB)      — userspace fallback, single static binary
#   3. Skip  — logged with instructions if neither tool is present
# ------------------------------------------------------------------------------
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# GLOBAL CONSTANTS & COLORS
# ==============================================================================
readonly DEST="/mnt/FORENSICS"
readonly TOOL_VERSION="1.5.1"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Terminal colors
readonly RED='\e[31m'
readonly GREEN='\e[32m'
readonly YELLOW='\e[33m'
readonly BLUE='\e[34m'
readonly CYAN='\e[36m'
readonly BOLD='\e[1m'
readonly RESET='\e[0m'

# Case directory — set by setup_collection()
CASE_DIR=""
COLLECTION_START_EPOCH=0

# ==============================================================================
# CASE METADATA — populated by create_case(); used in every log header
# ==============================================================================
CASE_NUMBER=""
CASE_NAME=""
CASE_EXAMINER=""
CASE_AGENCY=""
CASE_NOTES=""
CASE_CREATED=""

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

msg()      { echo -e "${BLUE}[*]${RESET} $*"; }
msg_ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
msg_warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
msg_err()  { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# Write a visual section divider + title into a log file
section() {
    local log="$1"; local title="$2"
    {
        printf '\n%s\n' "$(printf '=%.0s' {1..80})"
        printf '  %s\n' "$title"
        printf '%s\n\n' "$(printf '=%.0s' {1..80})"
    } >> "$log"
}

# Run a command and append its output to a log file.
# Gracefully skips commands that are not installed.
# Usage: run_cmd <logfile> <description> <cmd> [args...]
run_cmd() {
    local log="$1"; local desc="$2"; shift 2
    local cmd="$1"
    local start end elapsed

    section "$log" "$desc"
    echo "  Command : $*" >> "$log"
    start=$(date +%s)

    if ! command -v "$cmd" &>/dev/null; then
        echo "  [SKIPPED] '$cmd' not found on this system." >> "$log"
        msg_warn "'$cmd' not found — skipping: $desc"
        return 0
    fi

    if ! timeout 120 "$@" >> "$log" 2>&1; then
        echo "  [WARNING] Command exited with non-zero status." >> "$log"
    fi

    end=$(date +%s)
    elapsed=$(( end - start ))
    echo "" >> "$log"
    echo "  Elapsed : ${elapsed}s" >> "$log"
}

# Write standard artifact log file header (includes case metadata when set)
write_header() {
    local log="$1"; local title="$2"
    cat >> "$log" <<EOF
================================================================================
      Linux Baseline & Forensic Triage Tool (LBFTT) v${TOOL_VERSION}
      ${title}
================================================================================
  CASE INFORMATION
  ----------------
  Case Number : ${CASE_NUMBER:-[not set -- use menu option 3 to create a case]}
  Case Name   : ${CASE_NAME:-[not set]}
  Examiner    : ${CASE_EXAMINER:-${SUDO_USER:-unknown}}
  Agency/Org  : ${CASE_AGENCY:-[not set]}
  Notes       : ${CASE_NOTES:-[none]}
  Case Created: ${CASE_CREATED:-[not set]}

  SYSTEM INFORMATION
  ------------------
  Hostname    : $(hostname -f 2>/dev/null || hostname)
  Collection  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
  Kernel      : $(uname -r)
  Case Dir    : ${CASE_DIR}
================================================================================

EOF
}

# Hash a single file and write results to both the artifact log and the manifest
hash_file() {
    local log="$1"; local filepath="$2"
    if [[ ! -f "$filepath" ]]; then
        echo "  [HASH ERROR] File not found: $filepath" >> "$log"
        return 1
    fi
    local md5 sha1 sha256 size
    md5=$(md5sum       "$filepath" | awk '{print $1}')
    sha1=$(sha1sum     "$filepath" | awk '{print $1}')
    sha256=$(sha256sum "$filepath" | awk '{print $1}')
    size=$(du -sh      "$filepath" 2>/dev/null | cut -f1)

    {
        echo "  File   : $filepath"
        echo "  Size   : $size"
        echo "  MD5    : $md5"
        echo "  SHA1   : $sha1"
        echo "  SHA256 : $sha256"
    } >> "$log"

    # Also append a single-line entry to the manifest for easy parsing
    local manifest="${CASE_DIR}/00_MANIFEST.log"
    if [[ -f "$manifest" ]]; then
        printf '  %-52s  MD5:%-34s  SHA256:%s\n' \
            "$(basename "$filepath")" "$md5" "$sha256" >> "$manifest"
    fi
}

# Hash an artifact log and register it in the manifest
register_log() {
    local filepath="$1"
    local manifest="${CASE_DIR}/00_MANIFEST.log"
    [[ -f "$manifest" ]] && hash_file "$manifest" "$filepath"
}

# ==============================================================================
# CASE CREATION — collects examiner & case metadata before any collection runs
# ==============================================================================

create_case() {
    clear
    print_banner
    echo -e "  ${BOLD}${CYAN}── CREATE NEW CASE ────────────────────────────────────────${RESET}"
    echo ""
    echo -e "  Enter the case details below."
    echo -e "  ${YELLOW}Fields marked * are required. Press ENTER to skip optional fields.${RESET}"
    echo ""

    # ── Required fields ───────────────────────────────────────────────────────
    while true; do
        echo -ne "  ${BOLD}* Case Number   : ${RESET}"
        read -r input
        input="$(echo "$input" | xargs)"   # trim whitespace
        if [[ -n "$input" ]]; then
            CASE_NUMBER="$input"; break
        else
            msg_err "Case number is required."
        fi
    done

    while true; do
        echo -ne "  ${BOLD}* Examiner Name : ${RESET}"
        read -r input
        input="$(echo "$input" | xargs)"
        if [[ -n "$input" ]]; then
            CASE_EXAMINER="$input"; break
        else
            msg_err "Examiner name is required."
        fi
    done

    # ── Optional fields ───────────────────────────────────────────────────────
    echo -ne "  ${BOLD}  Case Name/Title: ${RESET}"
    read -r input
    CASE_NAME="$(echo "$input" | xargs)"

    echo -ne "  ${BOLD}  Agency / Org   : ${RESET}"
    read -r input
    CASE_AGENCY="$(echo "$input" | xargs)"

    echo -ne "  ${BOLD}  Notes          : ${RESET}"
    read -r input
    CASE_NOTES="$(echo "$input" | xargs)"

    CASE_CREATED="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

    # ── Confirmation screen ───────────────────────────────────────────────────
    echo ""
    echo -e "  ${CYAN}$(printf '─%.0s' {1..54})${RESET}"
    echo -e "  ${BOLD}  CASE SUMMARY — Please verify${RESET}"
    echo -e "  ${CYAN}$(printf '─%.0s' {1..54})${RESET}"
    echo ""
    echo -e "  ${BOLD}Case Number :${RESET} ${CASE_NUMBER}"
    echo -e "  ${BOLD}Case Name   :${RESET} ${CASE_NAME:-[not set]}"
    echo -e "  ${BOLD}Examiner    :${RESET} ${CASE_EXAMINER}"
    echo -e "  ${BOLD}Agency/Org  :${RESET} ${CASE_AGENCY:-[not set]}"
    echo -e "  ${BOLD}Notes       :${RESET} ${CASE_NOTES:-[none]}"
    echo -e "  ${BOLD}Created     :${RESET} ${CASE_CREATED}"
    echo ""
    echo -ne "  ${BOLD}Confirm and save? [Y/n]: ${RESET}"
    read -r confirm

    if [[ "${confirm,,}" == "n" ]]; then
        msg_warn "Case creation cancelled — fields cleared."
        CASE_NUMBER=""; CASE_NAME=""; CASE_EXAMINER=""
        CASE_AGENCY=""; CASE_NOTES=""; CASE_CREATED=""
        return 0
    fi

    msg_ok "Case created: ${CASE_NUMBER} — ${CASE_EXAMINER} — ${CASE_CREATED}"
}

# ==============================================================================
# PRE-FLIGHT CHECKS
# ==============================================================================

check_root() {
    echo ""
    msg "Checking for root/sudo privileges..."
    if [[ $EUID -ne 0 ]]; then
        msg_err "This script must be run as root or with sudo."
        exit 1
    fi
    msg_ok "Running as root — OK"
}

check_mount() {
    echo ""
    msg "Verifying forensic USB mount at ${DEST}..."
    if ! grep -qs "$DEST" /proc/mounts; then
        msg_err "Destination drive is NOT mounted at '${DEST}'."
        msg_err "Mount your forensic USB and retry."
        exit 1
    fi
    local avail_kb avail_gb
    avail_kb=$(df --output=avail "$DEST" 2>/dev/null | tail -1)
    avail_gb=$(( avail_kb / 1024 / 1024 ))
    if (( avail_gb < 5 )); then
        msg_warn "Less than 5 GB free on ${DEST} (${avail_gb} GB). Large collections may fail."
    fi
    msg_ok "Destination mounted at ${DEST} — OK (${avail_gb} GB free)"
}

# ==============================================================================
# COLLECTION SETUP — creates the case directory and manifest
# ==============================================================================

setup_collection() {
    local mode="$1"    # BASELINE | FAST | FULL
    local hn
    hn=$(hostname -s)
    local datestamp
    datestamp=$(date -u '+%Y-%m-%dT%H%M%SZ')

    # Case directory: /mnt/FORENSICS/hostname.timestamp.MODE/
    CASE_DIR="${DEST}/${hn}.${datestamp}.${mode}"
    mkdir -p "$CASE_DIR"

    # Artifact log paths — numbered for sorted display and investigative priority
    MANIFEST="${CASE_DIR}/00_MANIFEST.log"
    LOG_SYSTEM="${CASE_DIR}/01_SYSTEM.log"
    LOG_HARDWARE="${CASE_DIR}/02_HARDWARE.log"
    LOG_USERS="${CASE_DIR}/03_USERS_AUTH.log"
    LOG_JOBS="${CASE_DIR}/04_SCHEDULED_JOBS.log"
    LOG_PROCESSES="${CASE_DIR}/05_PROCESSES.log"
    LOG_NETWORK="${CASE_DIR}/06_NETWORK.log"
    LOG_SOFTWARE="${CASE_DIR}/07_SOFTWARE.log"
    LOG_SYSLOGS="${CASE_DIR}/08_LOGS.log"
    LOG_FILESYSTEM="${CASE_DIR}/09_FILESYSTEM.log"
    LOG_FILE_LISTING="${CASE_DIR}/10_FILE_LISTING.log"
    LOG_MEMORY="${CASE_DIR}/11_MEMORY.log"
    LOG_TRIAGE="${CASE_DIR}/12_TRIAGE_ARCHIVE.log"
    LOG_CONTAINERS="${CASE_DIR}/13_CONTAINERS.log"
    LOG_CLOUD="${CASE_DIR}/14_CLOUD.log"
    LOG_ANTI_FORENSICS="${CASE_DIR}/15_ANTI_FORENSICS.log"
    LOG_WEB_APP="${CASE_DIR}/16_WEB_APP.log"
    LOG_PERSISTENCE="${CASE_DIR}/17_PERSISTENCE.log"
    LOG_SECRETS="${CASE_DIR}/18_SECRETS.log"
    LOG_CLAMAV="${CASE_DIR}/19_CLAMAV.log"
    COLLECTION_TAR="${CASE_DIR}/${hn}.${mode}.tar"
    MEMORY_IMAGE="${CASE_DIR}/${hn}.${datestamp}.mem"

    # Build manifest / chain-of-custody header
    # Record start epoch for elapsed time calculation at finalization
    COLLECTION_START_EPOCH=$(date +%s)

    cat > "$MANIFEST" <<EOF
================================================================================
      Linux Baseline & Forensic Triage Tool (LBFTT) v${TOOL_VERSION}
      CHAIN OF CUSTODY MANIFEST -- ${mode} COLLECTION
================================================================================
  CASE INFORMATION
  ----------------
  Case Number : ${CASE_NUMBER:-[not set]}
  Case Name   : ${CASE_NAME:-[not set]}
  Examiner    : ${CASE_EXAMINER:-${SUDO_USER:-unknown}}
  Agency/Org  : ${CASE_AGENCY:-[not set]}
  Notes       : ${CASE_NOTES:-[none]}
  Case Created: ${CASE_CREATED:-[not set]}

  SYSTEM INFORMATION
  ------------------
  Hostname    : $(hostname -f 2>/dev/null || hostname)
  Start Time  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
  Kernel      : $(uname -r)
  Mode        : ${mode}
  Case Dir    : ${CASE_DIR}
================================================================================

  ARTIFACT LOG FILES
  ------------------
EOF

    msg_ok "Case directory created: ${CASE_DIR}"
    msg    "Manifest: ${MANIFEST}"
}

# Append summary footer and self-hash to the manifest
finalize_manifest() {
    local mode="$1"
    local end_epoch end_time elapsed_secs elapsed_fmt
    end_epoch=$(date +%s)
    end_time=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    elapsed_secs=$(( end_epoch - COLLECTION_START_EPOCH ))

    # Format elapsed time as Xh Xm Xs
    local hours minutes seconds
    hours=$(( elapsed_secs / 3600 ))
    minutes=$(( (elapsed_secs % 3600) / 60 ))
    seconds=$(( elapsed_secs % 60 ))
    elapsed_fmt="${hours}h ${minutes}m ${seconds}s"

    {
        echo ""
        printf '%s\n' "$(printf '=%.0s' {1..80})"
        echo "  COLLECTION SUMMARY"
        printf '%s\n' "$(printf -- '-%.0s' {1..80})"
        echo "  Mode        : ${mode}"
        echo "  End Time    : ${end_time}"
        echo "  Elapsed     : ${elapsed_fmt}  (${elapsed_secs}s)"
        echo "  Files saved : $(find "$CASE_DIR" -maxdepth 1 -type f | wc -l)"
        echo "  Total size  : $(du -sh "$CASE_DIR" 2>/dev/null | cut -f1)"
        printf '%s\n' "$(printf '=%.0s' {1..80})"
        echo ""
        echo "  MANIFEST SELF-HASH  (hash this file to verify collection integrity)"
        printf '%s\n' "$(printf -- '-%.0s' {1..80})"
    } >> "$MANIFEST"

    local md5 sha256
    md5=$(md5sum       "$MANIFEST" | awk '{print $1}')
    sha256=$(sha256sum "$MANIFEST" | awk '{print $1}')
    {
        echo "  MD5    : $md5"
        echo "  SHA256 : $sha256"
        printf '%s\n' "$(printf '=%.0s' {1..80})"
    } >> "$MANIFEST"

    msg_ok "Manifest finalized: ${MANIFEST}"
}

# ==============================================================================
# COLLECTION MODULES
# Each function writes exclusively to its own numbered log file.
# ==============================================================================

# ── 11: Memory ────────────────────────────────────────────────────────────────
#
# Tool selection priority:
#   1. LiME  — kernel module (lime-<uname -r>.ko) on the USB beside this script.
#              Acquires from kernel space; smallest system footprint; produces a
#              raw .lime image directly compatible with Volatility 3.
#              Requires the .ko pre-compiled for the EXACT running kernel.
#
#   2. AVML  — statically-linked userspace binary (avml) on the USB.
#              Universal fallback; no kernel headers required; slightly more
#              intrusive than LiME but reliable across all modern kernels.
#
#   3. Skip  — both tools absent; logs instructions and continues collection.
#
# LiME naming convention (place on USB alongside this script):
#   lime-<kernel release>.ko   e.g.  lime-6.8.0-51-generic.ko
#
# Build LiME on a matching kernel:
#   git clone https://github.com/504ensicsLabs/LiME
#   cd LiME/src && make
#   cp lime.ko /path/to/usb/lime-$(uname -r).ko
#
collect_memory() {
    local log="$LOG_MEMORY"
    write_header "$log" "11 — VOLATILE MEMORY ACQUISITION"

    local kernel_ver
    kernel_ver=$(uname -r)
    local lime_path="${SCRIPT_DIR}/lime-${kernel_ver}.ko"
    local avml_path="${SCRIPT_DIR}/avml"
    local lime_image="${MEMORY_IMAGE%.mem}.lime"   # .lime extension for LiME format
    local acquired=false

    # ── Tool inventory ──────────────────────────────────────────────────────
    section "$log" "Memory Acquisition Tool Inventory"
    {
        echo "  Running kernel        : ${kernel_ver}"
        echo "  LiME module expected  : ${lime_path}"
        echo "  LiME module present   : $( [[ -f "$lime_path" ]] && echo YES || echo NO )"
        echo "  AVML binary expected  : ${avml_path}"
        echo "  AVML binary present   : $( [[ -x "$avml_path" ]] && echo YES || echo NO )"
        echo ""
    } >> "$log"

    # ── Check for conflicting LiME load ─────────────────────────────────────
    if lsmod 2>/dev/null | grep -q "^lime "; then
        msg_warn "LiME module is already loaded — unloading before acquisition..."
        {
            echo "  [WARN] LiME module already loaded. Attempting rmmod lime..."
        } >> "$log"
        if ! rmmod lime >> "$log" 2>&1; then
            msg_err "Could not unload existing LiME module — falling through to AVML."
            echo "  [ERROR] rmmod lime failed. Will attempt AVML instead." >> "$log"
            # Force skip of LiME path by clearing lime_path
            lime_path=""
        fi
    fi

    # ════════════════════════════════════════════════════════════════════════
    # PATH 1 — LiME
    # ════════════════════════════════════════════════════════════════════════
    if [[ -n "$lime_path" && -f "$lime_path" ]]; then
        msg "Memory acquisition tool: ${GREEN}LiME${RESET} (kernel module — preferred)"
        section "$log" "LiME — Linux Memory Extractor (Kernel Module)"
        {
            echo "  Method  : LiME kernel module (kernel-space acquisition)"
            echo "  Module  : ${lime_path}"
            echo "  Output  : ${lime_image}"
            echo "  Format  : lime  (compatible with Volatility 3 / rekall)"
            echo ""
            echo "  NOTE: LiME writes directly from kernel space. This is the"
            echo "  most forensically sound acquisition method — minimal userspace"
            echo "  footprint and no reliance on /proc or /dev interfaces."
            echo ""
        } >> "$log"

        msg "  Loading LiME module and acquiring memory — please wait..."

        # insmod writes the image synchronously; it blocks until complete.
        # path= must be absolute. format=lime produces a Volatility-compatible image.
        local lime_start lime_end lime_elapsed
        lime_start=$(date +%s)

        if insmod "$lime_path" "path=${lime_image} format=lime" >> "$log" 2>&1; then
            lime_end=$(date +%s)
            lime_elapsed=$(( lime_end - lime_start ))

            # Unload the module immediately after acquisition
            if rmmod lime >> "$log" 2>&1; then
                echo "  LiME module unloaded cleanly." >> "$log"
            else
                msg_warn "rmmod lime returned non-zero — module may still be loaded"
                echo "  [WARN] rmmod lime returned non-zero after acquisition." >> "$log"
            fi

            if [[ -f "$lime_image" ]]; then
                MEMORY_IMAGE="$lime_image"   # update global so manifest picks it up
                msg_ok "  LiME acquisition complete (${lime_elapsed}s)"
                {
                    echo "  Acquisition time : ${lime_elapsed}s"
                    echo "  Image file       : ${lime_image}"
                    echo "  Image size       : $(du -sh "$lime_image" | cut -f1)"
                } >> "$log"
                section "$log" "LiME Memory Image — Cryptographic Hashes"
                hash_file "$log" "$lime_image"
                acquired=true
            else
                msg_err "LiME ran but output file not found: ${lime_image}"
                {
                    echo "  [ERROR] insmod returned 0 but output file is missing."
                    echo "  Expected: ${lime_image}"
                    echo "  Falling through to AVML..."
                } >> "$log"
            fi
        else
            msg_err "LiME insmod failed — falling through to AVML"
            {
                echo "  [ERROR] insmod ${lime_path} returned non-zero."
                echo "  Possible causes:"
                echo "    - Module compiled for a different kernel version"
                echo "    - Secure Boot blocking unsigned module load"
                echo "    - Kernel lockdown mode active (check: cat /sys/kernel/security/lockdown)"
                echo "  Falling through to AVML..."
            } >> "$log"
            # Ensure module is not partially loaded
            rmmod lime >> "$log" 2>&1 || true
        fi
    else
        {
            section "$log" "LiME — Skipped"
            echo "  No LiME module found for kernel: ${kernel_ver}"
            echo "  Expected path: ${lime_path}"
            echo ""
            echo "  To use LiME, build and place the module on the USB:"
            echo "    git clone https://github.com/504ensicsLabs/LiME"
            echo "    cd LiME/src && make"
            echo "    cp lime.ko /mnt/FORENSICS/lime-\$(uname -r).ko"
            echo ""
        } >> "$log"
        msg_warn "No LiME module for kernel ${kernel_ver} — trying AVML..."
    fi

    # ════════════════════════════════════════════════════════════════════════
    # PATH 2 — AVML (fallback)
    # ════════════════════════════════════════════════════════════════════════
    if [[ "$acquired" == false ]]; then
        if [[ -x "$avml_path" ]]; then
            msg "Memory acquisition tool: ${YELLOW}AVML${RESET} (userspace fallback)"
            section "$log" "AVML — Acquire Volatile Memory for Linux (Userspace)"
            {
                echo "  Method  : AVML userspace acquisition"
                echo "  Binary  : ${avml_path}"
                echo "  Output  : ${MEMORY_IMAGE}"
                echo "  Format  : raw ELF core  (compatible with Volatility 3)"
                echo ""
                echo "  NOTE: AVML operates from userspace via /dev/crash, /proc/kcore,"
                echo "  or /dev/mem depending on kernel configuration. Slightly more"
                echo "  intrusive than LiME but works without pre-compiled kernel modules."
                echo ""
            } >> "$log"

            msg "  Acquiring memory image with AVML — please wait..."
            local avml_start avml_end avml_elapsed
            avml_start=$(date +%s)

            if timeout 3600 "$avml_path" "$MEMORY_IMAGE" >> "$log" 2>&1; then
                avml_end=$(date +%s)
                avml_elapsed=$(( avml_end - avml_start ))
                msg_ok "  AVML acquisition complete (${avml_elapsed}s)"
                {
                    echo "  Acquisition time : ${avml_elapsed}s"
                    echo "  Image file       : ${MEMORY_IMAGE}"
                    echo "  Image size       : $(du -sh "$MEMORY_IMAGE" | cut -f1)"
                } >> "$log"
                section "$log" "AVML Memory Image — Cryptographic Hashes"
                hash_file "$log" "$MEMORY_IMAGE"
                acquired=true
            else
                msg_err "AVML returned a non-zero exit code — see ${log}"
                {
                    echo "  [ERROR] AVML exited with non-zero status."
                    echo "  Possible causes:"
                    echo "    - Insufficient permissions (ensure running as root)"
                    echo "    - /proc/kcore and /dev/crash both inaccessible"
                    echo "    - Kernel hardening restricting memory access"
                } >> "$log"
            fi
        else
            {
                section "$log" "AVML — Skipped"
                echo "  AVML binary not found at: ${avml_path}"
                echo "  Download from: https://github.com/microsoft/avml/releases"
                echo ""
            } >> "$log"
            msg_warn "AVML binary not found at ${avml_path}"
        fi
    fi

    # ════════════════════════════════════════════════════════════════════════
    # PATH 3 — Neither tool available
    # ════════════════════════════════════════════════════════════════════════
    if [[ "$acquired" == false ]]; then
        section "$log" "Memory Acquisition — SKIPPED"
        {
            echo "  [SKIPPED] No memory acquisition tool was available or succeeded."
            echo ""
            echo "  To enable memory acquisition, place one of the following on the USB"
            echo "  drive alongside this script (${SCRIPT_DIR}):"
            echo ""
            echo "  Option 1 — LiME (preferred, kernel-space):"
            echo "    git clone https://github.com/504ensicsLabs/LiME"
            echo "    cd LiME/src && make"
            echo "    cp lime.ko <USB>/lime-\$(uname -r).ko"
            echo ""
            echo "  Option 2 — AVML (fallback, userspace):"
            echo "    Download from https://github.com/microsoft/avml/releases"
            echo "    cp avml <USB>/avml && chmod +x <USB>/avml"
            echo ""
        } >> "$log"
        msg_warn "Memory acquisition skipped — no tool available. Collection continues."
    fi

    # ── Post-acquisition: kernel lockdown check ──────────────────────────────
    section "$log" "Kernel Lockdown & Security Notes"
    {
        local lockdown
        lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "not available")
        echo "  Kernel lockdown mode  : ${lockdown}"
        echo "  Secure Boot state     : $(mokutil --sb-state 2>/dev/null || echo 'mokutil not available')"
        echo ""
        echo "  NOTE: If lockdown is [integrity] or [confidentiality], LiME unsigned"
        echo "  module loads will be blocked. You must either disable Secure Boot,"
        echo "  sign the LiME module, or rely on AVML."
    } >> "$log"

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 01: System ────────────────────────────────────────────────────────────────
collect_system_info() {
    local log="$LOG_SYSTEM"
    write_header "$log" "01 — SYSTEM INFORMATION"
    msg "Collecting: System Information..."

    run_cmd "$log" "Hostname & OS Identity (hostnamectl)"       hostnamectl
    run_cmd "$log" "Kernel & Architecture (uname -a)"           uname -a
    run_cmd "$log" "OS Release (/etc/os-release)"               cat /etc/os-release
    run_cmd "$log" "Date / Time / Timezone (timedatectl)"       timedatectl
    run_cmd "$log" "System Uptime"                              uptime -p
    run_cmd "$log" "Last Reboot Events"                         last reboot -F
    run_cmd "$log" "Boot Journal — Warnings & Errors"           journalctl -b -p warning --no-pager -q
    run_cmd "$log" "Memory Summary (free -h)"                   free -h
    run_cmd "$log" "Detailed Memory Info (/proc/meminfo)"       cat /proc/meminfo
    run_cmd "$log" "Kernel Error/Warning Messages (dmesg)"      dmesg --level=err,warn,crit,alert,emerg
    run_cmd "$log" "Loaded Kernel Modules (lsmod)"              lsmod
    run_cmd "$log" "Kernel Runtime Parameters (sysctl -a)"      sysctl -a
    run_cmd "$log" "Current Environment Variables"              env
    run_cmd "$log" "Active Systemd Units (running)"             systemctl list-units --state=running --no-pager
    run_cmd "$log" "Failed Systemd Units"                       systemctl list-units --state=failed --no-pager

    # ── Boot & kernel integrity ───────────────────────────────────────────
    run_cmd "$log" "GRUB Configuration (/boot/grub/grub.cfg)" \
        bash -c 'cat /boot/grub/grub.cfg 2>/dev/null || cat /boot/grub2/grub.cfg 2>/dev/null || echo "GRUB config not found"'
    run_cmd "$log" "GRUB Default Settings (/etc/default/grub)" \
        bash -c 'cat /etc/default/grub 2>/dev/null || echo "Not found"'
    run_cmd "$log" "/boot Directory — Full Listing with Hashes" \
        bash -c 'ls -lahZ /boot/ && find /boot -type f -exec sha256sum {} \; 2>/dev/null'
    run_cmd "$log" "Initramfs Contents (lsinitramfs)" \
        bash -c 'img=$(ls /boot/initrd.img* 2>/dev/null | head -1); [ -n "$img" ] && lsinitramfs "$img" 2>/dev/null || echo "No initrd found or lsinitramfs not available"'
    run_cmd "$log" "UEFI Boot Entries (efibootmgr -v)" \
        bash -c 'efibootmgr -v 2>/dev/null || echo "efibootmgr not available (non-UEFI or not installed)"'
    run_cmd "$log" "EFI Variables Listing (/sys/firmware/efi/efivars)" \
        bash -c 'ls -la /sys/firmware/efi/efivars/ 2>/dev/null || echo "EFI vars not accessible"'
    run_cmd "$log" "Secure Boot State (mokutil)" \
        bash -c 'mokutil --sb-state 2>/dev/null || echo "mokutil not available"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 02: Hardware ──────────────────────────────────────────────────────────────
collect_hardware_info() {
    local log="$LOG_HARDWARE"
    write_header "$log" "02 — HARDWARE"
    msg "Collecting: Hardware Information..."

    run_cmd "$log" "Hardware Summary (lshw -short)"             lshw -short
    run_cmd "$log" "CPU Information (lscpu)"                    lscpu
    run_cmd "$log" "Block Devices (lsblk)"                      lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,UUID,LABEL,MODEL,SERIAL
    run_cmd "$log" "Disk Partitions (fdisk -l)"                 fdisk -l
    run_cmd "$log" "Disk UUIDs and Labels (blkid)"              blkid
    run_cmd "$log" "Filesystem Disk Usage (df -h)"              df -h
    run_cmd "$log" "PCI Devices (lspci -vvv)"                   lspci -vvv
    run_cmd "$log" "USB Devices (lsusb -v)"                     lsusb -v
    run_cmd "$log" "SCSI Devices (lsscsi -s)"                   lsscsi -s
    run_cmd "$log" "DMI / BIOS / UEFI Info (dmidecode)"         dmidecode
    run_cmd "$log" "Current Mount Points (/proc/mounts)"        cat /proc/mounts
    run_cmd "$log" "SMART Disk Health" \
        bash -c 'for d in $(lsblk -dno NAME | grep -v loop); do
                     echo "=== /dev/$d ==="
                     smartctl -a /dev/$d 2>/dev/null || true
                 done'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 03: Users & Authentication ────────────────────────────────────────────────
collect_user_info() {
    local log="$LOG_USERS"
    write_header "$log" "03 — USERS, GROUPS & AUTHENTICATION"
    msg "Collecting: Users & Authentication..."

    run_cmd "$log" "Currently Logged-On Users (who -aH)"        who -aH
    run_cmd "$log" "Recent Login History (last -F -w)"           last -F -w
    run_cmd "$log" "Failed Login Attempts (lastb -F -w)"         lastb -F -w
    run_cmd "$log" "All User Accounts (/etc/passwd)"             cat /etc/passwd
    run_cmd "$log" "Password Shadow File (/etc/shadow)"          cat /etc/shadow
    run_cmd "$log" "All Groups (/etc/group)"                     cat /etc/group
    run_cmd "$log" "Sudoers Configuration (/etc/sudoers)"        cat /etc/sudoers
    run_cmd "$log" "Sudoers.d Directory Contents" \
        bash -c 'ls -la /etc/sudoers.d/ 2>/dev/null
                 cat /etc/sudoers.d/* 2>/dev/null || true'
    run_cmd "$log" "Users with UID 0 (root equivalents)" \
        bash -c 'awk -F: "(\$3==0){print \$1,\$3,\$6}" /etc/passwd'
    run_cmd "$log" "Accounts with Empty Passwords" \
        bash -c 'awk -F: "(\$2==\"\"){print \$1}" /etc/shadow 2>/dev/null || true'
    run_cmd "$log" "Accounts with No Password Expiry" \
        bash -c 'awk -F: "(\$5==\"99999\"||$5==\"\"){print \$1}" /etc/shadow 2>/dev/null || true'
    run_cmd "$log" "SSH Authorized Keys — All Users" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.ssh/authorized_keys"
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || true'
    run_cmd "$log" "SSH Known Hosts — All Users" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.ssh/known_hosts"
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || true'
    run_cmd "$log" "PAM Configuration Files" \
        bash -c 'ls -la /etc/pam.d/ && cat /etc/pam.d/* 2>/dev/null || true'
    run_cmd "$log" "Login Definitions (/etc/login.defs)"         cat /etc/login.defs
    run_cmd "$log" "Shell History — All Users" \
        bash -c 'for h in /root /home/*; do
                     for f in "$h/.bash_history" "$h/.zsh_history" "$h/.sh_history"; do
                         [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                     done
                 done 2>/dev/null || true'
    run_cmd "$log" "Active Sessions Detail (w)"                   w

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 04: Scheduled Jobs & Persistence ──────────────────────────────────────────
collect_scheduled_jobs() {
    local log="$LOG_JOBS"
    write_header "$log" "04 — SCHEDULED JOBS & PERSISTENCE MECHANISMS"
    msg "Collecting: Scheduled Jobs & Persistence..."

    run_cmd "$log" "System Crontab (/etc/crontab)"               cat /etc/crontab
    run_cmd "$log" "All Cron Directories" \
        bash -c 'for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
                     echo "=== $d ==="
                     ls -la "$d" 2>/dev/null && cat "$d"/* 2>/dev/null || true
                 done'
    run_cmd "$log" "Per-User Crontabs" \
        bash -c 'for u in $(cut -d: -f1 /etc/passwd); do
                     tab=$(crontab -l -u "$u" 2>/dev/null)
                     [ -n "$tab" ] && echo "=== $u ===" && echo "$tab"
                 done'
    run_cmd "$log" "Systemd Timers — All"                        systemctl list-timers --all --no-pager
    run_cmd "$log" "Systemd Service Units — All"                 systemctl list-unit-files --type=service --no-pager
    run_cmd "$log" "At Jobs (atq)" \
        bash -c 'atq 2>/dev/null || echo "at not available or no jobs"'
    run_cmd "$log" "RC Local (/etc/rc.local)" \
        bash -c 'cat /etc/rc.local 2>/dev/null || echo "Not present"'
    run_cmd "$log" "Init.d Scripts" \
        bash -c 'ls -la /etc/init.d/ 2>/dev/null || true'
    run_cmd "$log" "Systemd User Units — All Users" \
        bash -c 'for h in /root /home/*; do
                     d="$h/.config/systemd/user"
                     [ -d "$d" ] && echo "=== $d ===" && ls -laR "$d"
                 done 2>/dev/null || true'
    run_cmd "$log" "XDG Autostart Entries" \
        bash -c 'for d in /etc/xdg/autostart /root/.config/autostart /home/*/.config/autostart; do
                     [ -d "$d" ] && echo "=== $d ===" && ls -la "$d" && cat "$d"/*.desktop 2>/dev/null
                 done 2>/dev/null || true'
    run_cmd "$log" "LD Preload — Potential Injection (/etc/ld.so.preload)" \
        bash -c 'cat /etc/ld.so.preload 2>/dev/null || echo "Not present or empty"'
    run_cmd "$log" "LD_PRELOAD in Environment" \
        bash -c 'env | grep -i ld_preload || echo "LD_PRELOAD not set"'
    run_cmd "$log" "Dynamic Linker Cache (ldconfig -p)"           ldconfig -p

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 05: Processes ─────────────────────────────────────────────────────────────
collect_process_info() {
    local log="$LOG_PROCESSES"
    write_header "$log" "05 — RUNNING PROCESSES"
    msg "Collecting: Process Information..."

    run_cmd "$log" "Full Process List (ps auxwwf)"               ps auxwwf
    run_cmd "$log" "Process Tree with PIDs (pstree)" \
        bash -c 'pstree -aplnZ 2>/dev/null || pstree -apln'
    run_cmd "$log" "Per-Process Details via /proc" \
        bash -c '
            printf "%-8s %-8s %-16s %-12s %-60s %s\n" PID PPID COMM USER CMDLINE EXE
            printf "%s\n" "$(printf -- "-%.0s" {1..130})"
            for pid_dir in /proc/[0-9]*/; do
                pid=$(basename "$pid_dir")
                comm=$(cat "$pid_dir/comm" 2>/dev/null || echo "?")
                cmdline=$(tr "\0" " " < "$pid_dir/cmdline" 2>/dev/null | head -c 256 || echo "?")
                exe=$(readlink "$pid_dir/exe" 2>/dev/null || echo "?")
                ppid=$(awk "/^PPid:/{print \$2}" "$pid_dir/status" 2>/dev/null || echo "?")
                uid=$(awk  "/^Uid:/{print  \$2}" "$pid_dir/status" 2>/dev/null || echo "?")
                user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "uid:$uid")
                printf "%-8s %-8s %-16s %-12s %-60s %s\n" \
                    "$pid" "$ppid" "$comm" "$user" "$cmdline" "$exe"
            done'
    run_cmd "$log" "Processes Running from /tmp or /dev (suspicious)" \
        bash -c 'ls -alR /proc/*/cwd 2>/dev/null | grep -E "(tmp|dev)" || echo "None found"'
    run_cmd "$log" "Deleted Binaries Still Running" \
        bash -c 'ls -al /proc/*/exe 2>/dev/null | grep -i deleted || echo "None found"'
    run_cmd "$log" "All Open Files by Process (lsof -nP)"        lsof -nP
    run_cmd "$log" "Open Network Files / Sockets (lsof -nP -i)"  lsof -nP -i
    run_cmd "$log" "Process Memory Maps — First 20 PIDs" \
        bash -c 'for pid in $(ls /proc | grep "^[0-9]" | head -20); do
                     [ -f "/proc/$pid/maps" ] && echo "=== PID $pid ===" && cat "/proc/$pid/maps"
                 done 2>/dev/null || true'

    # ── TTY & terminal session artifacts ─────────────────────────────────
    run_cmd "$log" "Active PTY/TTY Devices" \
        bash -c 'ls -la /dev/pts/ 2>/dev/null; ls -la /dev/tty* 2>/dev/null || true'
    run_cmd "$log" "Processes Attached to Terminal Sessions" \
        bash -c 'for pid in /proc/[0-9]*/fd; do
                     p=$(dirname "$pid")
                     tty=$(ls -la "$pid" 2>/dev/null | grep -E "pts|tty" | head -1)
                     [ -n "$tty" ] && echo "PID $(basename $p): $tty"
                 done 2>/dev/null || true'
    run_cmd "$log" "Script Session Logs (typescript files)" \
        bash -c 'find /root /home /tmp -name "typescript" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null || echo "None found"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 06: Network ───────────────────────────────────────────────────────────────
collect_network_info() {
    local log="$LOG_NETWORK"
    write_header "$log" "06 — NETWORK CONFIGURATION & CONNECTIONS"
    msg "Collecting: Network Information..."

    run_cmd "$log" "Network Interfaces — Addresses (ip addr)"   ip addr show
    run_cmd "$log" "Network Interfaces — Link Layer (ip link)"  ip link show
    run_cmd "$log" "Routing Table — All Tables (ip route)"      ip route show table all
    run_cmd "$log" "ARP / Neighbor Table (ip neigh)"            ip neigh show
    run_cmd "$log" "Socket Statistics — All (ss -anpetu)"       ss -anpetu
    run_cmd "$log" "Listening Ports (ss -tlnp)"                 ss -tlnp
    run_cmd "$log" "All TCP Connections (ss -antp)"             ss -antp
    run_cmd "$log" "All UDP Connections (ss -anup)"             ss -anup
    run_cmd "$log" "DNS Configuration (/etc/resolv.conf)"       cat /etc/resolv.conf
    run_cmd "$log" "Hosts File (/etc/hosts)"                    cat /etc/hosts
    run_cmd "$log" "Hosts Allow / Deny" \
        bash -c 'echo "=== /etc/hosts.allow ===" && cat /etc/hosts.allow 2>/dev/null
                 echo "=== /etc/hosts.deny ===" && cat /etc/hosts.deny 2>/dev/null || true'
    run_cmd "$log" "NSSwitch Configuration"                     cat /etc/nsswitch.conf
    run_cmd "$log" "iptables Rules — IPv4 (iptables-save)"      iptables-save
    run_cmd "$log" "ip6tables Rules — IPv6 (ip6tables-save)"    ip6tables-save
    run_cmd "$log" "nftables Ruleset" \
        bash -c 'nft list ruleset 2>/dev/null || echo "nft not available"'
    run_cmd "$log" "UFW Firewall Status" \
        bash -c 'ufw status verbose 2>/dev/null || echo "ufw not available"'
    run_cmd "$log" "Network Interface Statistics (/proc/net/dev)" cat /proc/net/dev
    run_cmd "$log" "Wireless Interfaces (iwconfig)" \
        bash -c 'iwconfig 2>/dev/null || echo "iwconfig not available"'
    run_cmd "$log" "NetworkManager Connections (nmcli)" \
        bash -c 'nmcli connection show 2>/dev/null || echo "nmcli not available"'
    run_cmd "$log" "SSH Server Configuration (/etc/ssh/sshd_config)" \
        bash -c 'cat /etc/ssh/sshd_config 2>/dev/null || echo "Not found"'
    run_cmd "$log" "SSH Client Configuration (/etc/ssh/ssh_config)" \
        bash -c 'cat /etc/ssh/ssh_config 2>/dev/null || echo "Not found"'

    # ── Extended network artifacts ────────────────────────────────────────
    run_cmd "$log" "DNS Resolution Cache (systemd-resolve --statistics)" \
        bash -c 'systemd-resolve --statistics 2>/dev/null || echo "systemd-resolved not available"'
    run_cmd "$log" "Recent DNS Queries (journalctl systemd-resolved)" \
        bash -c 'journalctl -u systemd-resolved --no-pager -n 300 2>/dev/null || echo "Not available"'
    run_cmd "$log" "WireGuard Interfaces (wg show)" \
        bash -c 'wg show 2>/dev/null || echo "WireGuard not active or not installed"'
    run_cmd "$log" "WireGuard Configurations (/etc/wireguard/)" \
        bash -c 'ls -la /etc/wireguard/ 2>/dev/null && cat /etc/wireguard/*.conf 2>/dev/null || echo "No WireGuard configs found"'
    run_cmd "$log" "OpenVPN Configurations" \
        bash -c 'find /etc/openvpn /etc/vpn 2>/dev/null -name "*.conf" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null || echo "No OpenVPN configs found"'
    run_cmd "$log" "Proxy Settings (environment)" \
        bash -c 'env | grep -iE "(proxy|http_proxy|https_proxy|no_proxy)" || echo "No proxy vars set"'
    run_cmd "$log" "Traffic Control Rules (tc qdisc/filter)" \
        bash -c 'tc qdisc show 2>/dev/null; tc filter show 2>/dev/null || echo "tc not available"'
    run_cmd "$log" "Raw Kernel TCP Table (/proc/net/tcp)" \
        cat /proc/net/tcp
    run_cmd "$log" "Raw Kernel TCP6 Table (/proc/net/tcp6)" \
        bash -c 'cat /proc/net/tcp6 2>/dev/null || echo "Not available"'
    run_cmd "$log" "Raw Kernel UDP Table (/proc/net/udp)" \
        cat /proc/net/udp
    run_cmd "$log" "Raw Kernel ARP Table (/proc/net/arp)" \
        cat /proc/net/arp
    run_cmd "$log" "Raw Kernel Route Table (/proc/net/route)" \
        cat /proc/net/route
    run_cmd "$log" "Raw Kernel Socket Stats (/proc/net/sockstat)" \
        cat /proc/net/sockstat

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 07: Software ──────────────────────────────────────────────────────────────
collect_software_info() {
    local log="$LOG_SOFTWARE"
    write_header "$log" "07 — INSTALLED SOFTWARE & PACKAGES"
    msg "Collecting: Software & Package Information..."

    run_cmd "$log" "Installed Packages (dpkg -l)" \
        bash -c 'dpkg -l 2>/dev/null || echo "dpkg not available"'
    run_cmd "$log" "Installed Packages (rpm -qa)" \
        bash -c 'rpm -qa --queryformat "%{NAME} %{VERSION} %{INSTALLTIME:date}\n" 2>/dev/null | sort || echo "rpm not available"'
    run_cmd "$log" "Recently Installed Packages (dpkg log)" \
        bash -c 'grep " install " /var/log/dpkg.log* 2>/dev/null | tail -200 || echo "Not found"'
    run_cmd "$log" "Python Packages (pip list)" \
        bash -c 'pip list 2>/dev/null || pip3 list 2>/dev/null || echo "pip not available"'
    run_cmd "$log" "Snap Packages" \
        bash -c 'snap list 2>/dev/null || echo "snap not available"'
    run_cmd "$log" "Flatpak Packages" \
        bash -c 'flatpak list 2>/dev/null || echo "flatpak not available"'
    run_cmd "$log" "Shared Libraries (ldconfig -p)"             ldconfig -p
    run_cmd "$log" "Package Integrity — Modified Files (dpkg --verify)" \
        bash -c 'dpkg --verify 2>/dev/null || echo "dpkg not available"'
    run_cmd "$log" "Package Integrity — Modified Files (rpm -Va)" \
        bash -c 'rpm -Va 2>/dev/null || echo "rpm not available"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 08: System Logs ───────────────────────────────────────────────────────────
collect_log_files() {
    local log="$LOG_SYSLOGS"
    write_header "$log" "08 — SYSTEM LOG EXCERPTS"
    msg "Collecting: System Log Files..."

    run_cmd "$log" "Systemd Journal — SSH / Auth (last 500 lines)" \
        journalctl -u ssh -u sshd -u sudo --no-pager -n 500
    run_cmd "$log" "Systemd Journal — Errors Last 24h" \
        journalctl -p err --since "24 hours ago" --no-pager
    run_cmd "$log" "Auth Log (/var/log/auth.log or /var/log/secure)" \
        bash -c 'cat /var/log/auth.log 2>/dev/null || cat /var/log/secure 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Syslog (/var/log/syslog or /var/log/messages)" \
        bash -c 'cat /var/log/syslog 2>/dev/null || cat /var/log/messages 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Kernel Log (/var/log/kern.log)" \
        bash -c 'cat /var/log/kern.log 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Audit Log (/var/log/audit/audit.log)" \
        bash -c 'cat /var/log/audit/audit.log 2>/dev/null || echo "Not found or audit not configured"'
    run_cmd "$log" "Active Audit Rules (auditctl -l)" \
        bash -c 'auditctl -l 2>/dev/null || echo "auditd not available"'
    run_cmd "$log" "Cron Log" \
        bash -c 'cat /var/log/cron.log 2>/dev/null || journalctl -u cron --no-pager -n 200 2>/dev/null || echo "Not found"'
    run_cmd "$log" "All Login Records (last -F -w -a)"           last -F -w -a
    run_cmd "$log" "All Failed Login Records (lastb -F -w -a)"   lastb -F -w -a

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 09: Filesystem Anomalies ──────────────────────────────────────────────────
collect_filesystem_info() {
    local log="$LOG_FILESYSTEM"
    write_header "$log" "09 — FILESYSTEM ANOMALIES & INTEGRITY"
    msg "Collecting: Filesystem Anomalies..."

    run_cmd "$log" "Hidden Directories" \
        find / -xdev -type d -name ".*" 2>/dev/null
    run_cmd "$log" "World-Writable Directories" \
        find / -xdev -type d -perm -0002 -not -path "*/proc/*" 2>/dev/null
    run_cmd "$log" "SUID Files" \
        find / -xdev -type f -perm -4000 -exec ls -la {} \; 2>/dev/null
    run_cmd "$log" "SGID Files" \
        find / -xdev -type f -perm -2000 -exec ls -la {} \; 2>/dev/null
    run_cmd "$log" "Files with No Valid Owner or Group" \
        find / -xdev \( -nouser -o -nogroup \) -exec ls -la {} \; 2>/dev/null
    run_cmd "$log" "Immutable Files (lsattr -R /)" \
        bash -c 'lsattr -R / 2>&1 | grep -v "^lsattr: Operation not supported\|^lsattr: Inappropriate ioctl"'
    run_cmd "$log" "Files Modified in Last 24 Hours" \
        find / -xdev -type f -mtime -1 \
            -not -path "*/proc/*" -not -path "*/sys/*" \
            -exec ls -la {} \; 2>/dev/null
    run_cmd "$log" "Files Modified in Last 7 Days (paths only)" \
        find / -xdev -type f -mtime -7 \
            -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null
    run_cmd "$log" "Executable Files in /tmp, /var/tmp, /dev/shm" \
        bash -c 'find /tmp /var/tmp /dev/shm -type f -executable \
                     -exec ls -la {} \; 2>/dev/null || echo "None found"'
    run_cmd "$log" "SHA-256 Hashes — System Binaries" \
        bash -c 'find /usr/bin /usr/sbin /bin /sbin -type f \
                     -exec sha256sum {} \; 2>/dev/null'
    run_cmd "$log" "Binary Content Detected in Log Files" \
        bash -c 'grep -rl $'"'"'[\x01-\x08\x0e-\x1f]'"'"' /var/log/ 2>/dev/null \
                     | head -50 || echo "None found"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 10: Full File Listing ─────────────────────────────────────────────────────
collect_file_listing() {
    local log="$LOG_FILE_LISTING"
    write_header "$log" "10 — COMPLETE FILE SYSTEM LISTING"
    msg "Collecting: Full File Listing (this may take a while)..."

    section "$log" "All Files — Full Metadata Listing"
    {
        echo "  NOTE: Excludes /proc and /sys to prevent hangs."
        echo "  Command: find / -xdev | xargs ls -ladZ --time-style=full-iso"
        echo "  Start   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } >> "$log"

    local start end elapsed
    start=$(date +%s)

    find / -xdev \( -path /proc -o -path /sys \) -prune -o \
        -print0 2>/dev/null | \
        xargs -0 ls -ladZ --time-style=full-iso 2>/dev/null >> "$log"

    end=$(date +%s)
    elapsed=$(( end - start ))
    {
        echo ""
        echo "  End     : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "  Elapsed : ${elapsed}s"
    } >> "$log"

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 12: Triage File Archive ───────────────────────────────────────────────────
collect_triage_files() {
    local log="$LOG_TRIAGE"
    local mode="$1"
    write_header "$log" "12 — FORENSIC TRIAGE FILE ARCHIVE"
    msg "Collecting: Triage File Archive..."

    # Core artifact paths — always collected
    local FILES=(
        /etc/passwd /etc/shadow /etc/group
        /etc/sudoers /etc/sudoers.d
        /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly
        /etc/cron.weekly /etc/cron.monthly
        /etc/hostname /etc/hosts /etc/resolv.conf /etc/nsswitch.conf
        /etc/ssh /etc/pam.d
        /etc/os-release /etc/issue /etc/issue.net
        /etc/ld.so.preload
        /var/log/auth.log /var/log/secure
        /var/log/syslog /var/log/messages
        /var/log/kern.log /var/log/dpkg.log
        /var/log/audit /var/log/btmp /var/log/wtmp /var/log/lastlog
        /root/.bash_history /root/.zsh_history /root/.ssh
        /tmp /var/tmp
    )

    # FULL mode adds home directories and additional persistence paths
    if [[ "$mode" == "FULL" ]]; then
        FILES+=(
            /home
            /var/spool/cron
            /etc/init.d
            /etc/rc.local
            /etc/profile.d
            /etc/environment
        )
    fi

    section "$log" "Files Targeted for Collection"
    printf '  %s\n' "${FILES[@]}" >> "$log"

    # Capture stat metadata BEFORE creating the archive to preserve atime accuracy
    section "$log" "File Timestamp Metadata (stat) — Pre-Archive"
    echo "  Captured before tar to preserve original atime values." >> "$log"
    echo "" >> "$log"
    for f in "${FILES[@]}"; do
        [[ -e "$f" ]] && find "$f" -type f \
            -exec stat --printf='%n\tSize:%s\tAtime:%x\tMtime:%y\tCtime:%z\tPerm:%A\n' {} \; \
            2>/dev/null
    done >> "$log" 2>&1

    # Build tar archive — no compression to maximize speed on USB
    section "$log" "Tar Archive Creation"
    {
        echo "  Archive : ${COLLECTION_TAR}"
        echo "  Command : tar -cpf [archive] --acls --xattrs --atime-preserve=system [files]"
        echo ""
    } >> "$log"

    local existing_files=()
    for f in "${FILES[@]}"; do
        [[ -e "$f" ]] && existing_files+=("$f")
    done

    if tar -cpf "$COLLECTION_TAR" \
            --ignore-failed-read \
            --preserve-permissions \
            --acls \
            --xattrs \
            --atime-preserve=system \
            "${existing_files[@]}" >> "$log" 2>&1; then
        msg_ok "  Triage archive created: ${COLLECTION_TAR}"
    else
        msg_err "tar reported errors — archive may be incomplete"
        echo "  [WARNING] tar exited non-zero. Archive may be incomplete." >> "$log"
    fi

    section "$log" "Triage Archive — Cryptographic Hashes"
    hash_file "$log" "$COLLECTION_TAR"

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 13: Containers & Virtualization ──────────────────────────────────────────
collect_containers() {
    local log="$LOG_CONTAINERS"
    write_header "$log" "13 — CONTAINERS, NAMESPACES & VIRTUALIZATION"
    msg "Collecting: Container & Virtualization Artifacts..."

    # ── Docker ────────────────────────────────────────────────────────────
    section "$log" "Docker"
    run_cmd "$log" "Docker — Running & All Containers (docker ps -a)" \
        bash -c 'docker ps -a --no-trunc 2>/dev/null || echo "Docker not available or not running"'
    run_cmd "$log" "Docker — All Images" \
        bash -c 'docker images --no-trunc 2>/dev/null || echo "Docker not available"'
    run_cmd "$log" "Docker — Container Inspect (all containers)" \
        bash -c 'docker ps -aq 2>/dev/null | xargs -r docker inspect 2>/dev/null || echo "No containers or Docker not available"'
    run_cmd "$log" "Docker — Network List" \
        bash -c 'docker network ls 2>/dev/null && docker network inspect $(docker network ls -q) 2>/dev/null || echo "Docker not available"'
    run_cmd "$log" "Docker — Volume List" \
        bash -c 'docker volume ls 2>/dev/null || echo "Docker not available"'
    run_cmd "$log" "Docker — Daemon Configuration (/etc/docker/daemon.json)" \
        bash -c 'cat /etc/docker/daemon.json 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Docker — Service Unit" \
        bash -c 'systemctl cat docker.service 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Docker — /var/lib/docker Directory Listing" \
        bash -c 'ls -laR /var/lib/docker/ 2>/dev/null | head -500 || echo "Not found"'
    run_cmd "$log" "Docker — Socket Permissions" \
        bash -c 'ls -la /var/run/docker.sock 2>/dev/null || echo "Docker socket not found"'

    # ── Podman ────────────────────────────────────────────────────────────
    section "$log" "Podman"
    run_cmd "$log" "Podman — All Containers (podman ps -a)" \
        bash -c 'podman ps -a --no-trunc 2>/dev/null || echo "Podman not available"'
    run_cmd "$log" "Podman — All Images" \
        bash -c 'podman images --no-trunc 2>/dev/null || echo "Podman not available"'
    run_cmd "$log" "Podman — Container Inspect (all)" \
        bash -c 'podman ps -aq 2>/dev/null | xargs -r podman inspect 2>/dev/null || echo "No containers or Podman not available"'
    run_cmd "$log" "Podman — Pod List" \
        bash -c 'podman pod list 2>/dev/null || echo "Podman not available"'

    # ── LXC / LXD ─────────────────────────────────────────────────────────
    section "$log" "LXC / LXD"
    run_cmd "$log" "LXC — Container List (lxc-ls)" \
        bash -c 'lxc-ls --fancy 2>/dev/null || echo "LXC not available"'
    run_cmd "$log" "LXD — Instance List (lxc list)" \
        bash -c 'lxc list 2>/dev/null || echo "LXD not available"'
    run_cmd "$log" "LXD — Storage Pools" \
        bash -c 'lxc storage list 2>/dev/null || echo "LXD not available"'
    run_cmd "$log" "LXD — Network List" \
        bash -c 'lxc network list 2>/dev/null || echo "LXD not available"'

    # ── Kubernetes ────────────────────────────────────────────────────────
    section "$log" "Kubernetes / kubectl"
    run_cmd "$log" "kubectl — Cluster Info" \
        bash -c 'kubectl cluster-info 2>/dev/null || echo "kubectl not available or no cluster"'
    run_cmd "$log" "kubectl — All Pods (all namespaces)" \
        bash -c 'kubectl get pods --all-namespaces 2>/dev/null || echo "kubectl not available"'
    run_cmd "$log" "Kubeconfig Locations" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.kube/config"
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || echo "No kubeconfigs found"'
    run_cmd "$log" "kubelet Service Status" \
        bash -c 'systemctl status kubelet 2>/dev/null || echo "kubelet not running"'

    # ── Linux Namespaces ──────────────────────────────────────────────────
    section "$log" "Linux Namespaces"
    run_cmd "$log" "Namespace Inventory (lsns)" \
        bash -c 'lsns 2>/dev/null || echo "lsns not available"'
    run_cmd "$log" "Per-Process Namespace Links (/proc/*/ns)" \
        bash -c 'for pid in $(ls /proc | grep "^[0-9]" | head -50); do
                     [ -d "/proc/$pid/ns" ] || continue
                     comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "?")
                     ns=$(ls -la "/proc/$pid/ns/" 2>/dev/null)
                     echo "=== PID $pid ($comm) ===" && echo "$ns"
                 done 2>/dev/null || true'
    run_cmd "$log" "Cgroups Hierarchy (/proc/1/cgroup)" \
        bash -c 'cat /proc/1/cgroup 2>/dev/null && cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true'
    run_cmd "$log" "Cgroup Mounts (/sys/fs/cgroup)" \
        bash -c 'ls -la /sys/fs/cgroup/ 2>/dev/null || echo "Not accessible"'

    # ── Virtualization Detection ──────────────────────────────────────────
    section "$log" "Virtualization Detection"
    run_cmd "$log" "Virtualization Type (systemd-detect-virt)" \
        bash -c 'systemd-detect-virt -v 2>/dev/null || echo "systemd-detect-virt not available"'
    run_cmd "$log" "Hypervisor Indicators (dmesg)" \
        bash -c 'dmesg 2>/dev/null | grep -iE "(vmware|virtualbox|kvm|qemu|xen|hyperv|hyper-v)" || echo "None found"'
    run_cmd "$log" "VM Guest Agent Processes" \
        bash -c 'ps auxww | grep -iE "(vmtoolsd|vboxservice|qemu-guest|xe-daemon|hv_vss)" | grep -v grep || echo "None found"'
    run_cmd "$log" "DMI Vendor String (virtualization check)" \
        bash -c 'dmidecode -s system-manufacturer 2>/dev/null || echo "dmidecode not available"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 14: Cloud & Infrastructure Agents ────────────────────────────────────────
collect_cloud() {
    local log="$LOG_CLOUD"
    write_header "$log" "14 — CLOUD INFRASTRUCTURE & AGENT ARTIFACTS"
    msg "Collecting: Cloud & Infrastructure Agent Artifacts..."

    # ── Cloud-init ────────────────────────────────────────────────────────
    section "$log" "Cloud-Init"
    run_cmd "$log" "Cloud-Init Status" \
        bash -c 'cloud-init status --long 2>/dev/null || echo "cloud-init not available"'
    run_cmd "$log" "Cloud-Init Configuration (/etc/cloud/)" \
        bash -c 'ls -laR /etc/cloud/ 2>/dev/null && cat /etc/cloud/cloud.cfg 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Cloud-Init Log (/var/log/cloud-init.log)" \
        bash -c 'cat /var/log/cloud-init.log 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Cloud-Init Output Log (/var/log/cloud-init-output.log)" \
        bash -c 'cat /var/log/cloud-init-output.log 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Cloud-Init Instance Data (/run/cloud-init/)" \
        bash -c 'ls -laR /run/cloud-init/ 2>/dev/null && cat /run/cloud-init/instance-data.json 2>/dev/null || echo "Not found"'

    # ── IMDS — Instance Metadata Service ─────────────────────────────────
    section "$log" "Instance Metadata Service (IMDS)"
    {
        echo "  NOTE: Querying IMDS to document what an attacker could have accessed."
        echo "  These requests are logged by most cloud providers."
        echo ""
    } >> "$log"
    run_cmd "$log" "AWS IMDS — Identity Document" \
        bash -c 'curl -sf --max-time 3 http://169.254.169.254/latest/dynamic/instance-identity/document 2>/dev/null || echo "AWS IMDS not reachable"'
    run_cmd "$log" "AWS IMDS — Security Credentials List" \
        bash -c 'curl -sf --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || echo "AWS IMDS not reachable"'
    run_cmd "$log" "GCP IMDS — Instance Info" \
        bash -c 'curl -sf --max-time 3 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true 2>/dev/null || echo "GCP IMDS not reachable"'
    run_cmd "$log" "Azure IMDS — Instance Info" \
        bash -c 'curl -sf --max-time 3 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || echo "Azure IMDS not reachable"'

    # ── AWS ───────────────────────────────────────────────────────────────
    section "$log" "AWS Tools & Agents"
    run_cmd "$log" "AWS CLI Configuration" \
        bash -c 'for h in /root /home/*; do
                     for f in "$h/.aws/config" "$h/.aws/credentials"; do
                         [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                     done
                 done 2>/dev/null || echo "No AWS configs found"'
    run_cmd "$log" "AWS SSM Agent Status" \
        bash -c 'systemctl status amazon-ssm-agent 2>/dev/null || echo "SSM agent not found"'
    run_cmd "$log" "AWS SSM Agent Logs" \
        bash -c 'cat /var/log/amazon/ssm/amazon-ssm-agent.log 2>/dev/null | tail -200 || echo "Not found"'
    run_cmd "$log" "AWS CloudWatch Agent Status" \
        bash -c 'systemctl status amazon-cloudwatch-agent 2>/dev/null || echo "CloudWatch agent not found"'

    # ── GCP ───────────────────────────────────────────────────────────────
    section "$log" "GCP Tools & Agents"
    run_cmd "$log" "GCP Guest Agent Status" \
        bash -c 'systemctl status google-guest-agent 2>/dev/null || echo "GCP guest agent not found"'
    run_cmd "$log" "GCP Guest Agent Logs" \
        bash -c 'cat /var/log/google-guest-agent.log 2>/dev/null | tail -200 || journalctl -u google-guest-agent --no-pager -n 200 2>/dev/null || echo "Not found"'
    run_cmd "$log" "gcloud CLI Configuration" \
        bash -c 'for h in /root /home/*; do
                     d="$h/.config/gcloud"
                     [ -d "$d" ] && echo "=== $d ===" && ls -laR "$d"
                 done 2>/dev/null || echo "No gcloud configs found"'

    # ── Azure ─────────────────────────────────────────────────────────────
    section "$log" "Azure Tools & Agents"
    run_cmd "$log" "Azure WaLinux Agent Status" \
        bash -c 'systemctl status walinuxagent 2>/dev/null || echo "Azure agent not found"'
    run_cmd "$log" "Azure WaLinux Agent Log" \
        bash -c 'cat /var/log/waagent.log 2>/dev/null | tail -200 || echo "Not found"'

    # ── Infrastructure Automation ─────────────────────────────────────────
    section "$log" "Infrastructure Automation Agents"
    run_cmd "$log" "Puppet Agent Status" \
        bash -c 'puppet agent --version 2>/dev/null && systemctl status puppet 2>/dev/null || echo "Puppet not found"'
    run_cmd "$log" "Chef Client Status" \
        bash -c 'chef-client --version 2>/dev/null && systemctl status chef-client 2>/dev/null || echo "Chef not found"'
    run_cmd "$log" "Ansible Facts / Pull Config" \
        bash -c 'cat /etc/ansible/ansible.cfg 2>/dev/null || echo "Ansible config not found"'
    run_cmd "$log" "SaltStack Minion Status" \
        bash -c 'systemctl status salt-minion 2>/dev/null || echo "Salt not found"'
    run_cmd "$log" "Terraform State Files (find)" \
        bash -c 'find / -xdev -name "terraform.tfstate" -not -path "*/proc/*" 2>/dev/null | head -20 || echo "None found"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 15: Anti-Forensics & Rootkit Indicators ───────────────────────────────────
collect_anti_forensics() {
    local log="$LOG_ANTI_FORENSICS"
    write_header "$log" "15 — ANTI-FORENSICS & ROOTKIT INDICATORS"
    msg "Collecting: Anti-Forensics & Rootkit Indicators..."

    # ── /proc vs ps discrepancy ───────────────────────────────────────────
    section "$log" "PID Discrepancy Check — /proc vs ps (Rootkit Indicator)"
    {
        echo "  Comparing PIDs visible in /proc against ps output."
        echo "  PIDs present in /proc but absent from ps may indicate a kernel-level rootkit."
        echo ""
        echo "  PIDs from /proc:"
        ls /proc | grep '^[0-9]' | sort -n > /tmp/lbftt_proc_pids.tmp 2>/dev/null
        cat /tmp/lbftt_proc_pids.tmp
        echo ""
        echo "  PIDs from ps:"
        ps -eo pid --no-headers | tr -d ' ' | sort -n > /tmp/lbftt_ps_pids.tmp 2>/dev/null
        cat /tmp/lbftt_ps_pids.tmp
        echo ""
        echo "  PIDs in /proc but NOT in ps (suspicious if non-empty):"
        comm -23 /tmp/lbftt_proc_pids.tmp /tmp/lbftt_ps_pids.tmp || echo "  comm failed"
        rm -f /tmp/lbftt_proc_pids.tmp /tmp/lbftt_ps_pids.tmp
    } >> "$log" 2>&1

    # ── /proc vs ss port discrepancy ──────────────────────────────────────
    section "$log" "Network Port Discrepancy Check — /proc/net vs ss (Rootkit Indicator)"
    {
        echo "  Comparing listening ports in /proc/net/tcp against ss output."
        echo "  Ports in /proc/net but absent from ss may indicate port hiding."
        echo ""
        echo "  Listening ports from /proc/net/tcp (hex local_address:port):"
        awk '$4 == "0A" {print $2}' /proc/net/tcp 2>/dev/null | \
            awk -F: '{cmd="printf \"%d\" 0x"$2; cmd | getline dec; close(cmd); print dec}' | sort -n | uniq
        echo ""
        echo "  Listening ports from ss -tlnp:"
        ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -oE '[0-9]+$' | sort -n | uniq
    } >> "$log" 2>&1

    # ── Kernel symbol anomalies ───────────────────────────────────────────
    run_cmd "$log" "Kernel Symbol Table — Unexpected Entries (/proc/kallsyms)" \
        bash -c 'if [ -r /proc/kallsyms ]; then
                     echo "Total symbols: $(wc -l < /proc/kallsyms)"
                     echo ""
                     echo "Symbols not in standard kernel sections (potential hooks):"
                     grep -v " [TtRrDdBbAaVvWwCcSs] " /proc/kallsyms | head -100 || echo "None found"
                 else
                     echo "/proc/kallsyms not readable (kernel.kptr_restrict may be set)"
                 fi'

    # ── /dev anomalies ────────────────────────────────────────────────────
    run_cmd "$log" "/dev Directory Anomalies — Non-Device Files (Rootkit Hiding Spot)" \
        bash -c 'find /dev -not -type b -not -type c -not -type d -not -type l -not -type p \
                     -exec ls -la {} \; 2>/dev/null | grep -v "^total" || echo "None found"'
    run_cmd "$log" "/dev — All Files with Type" \
        bash -c 'find /dev -maxdepth 2 -exec ls -la {} \; 2>/dev/null | head -200'

    # ── Preload / shared library hijacking ───────────────────────────────
    run_cmd "$log" "LD Preload File (/etc/ld.so.preload)" \
        bash -c 'if [ -f /etc/ld.so.preload ]; then
                     echo "  [ALERT] /etc/ld.so.preload EXISTS — potential injection vector"
                     cat /etc/ld.so.preload
                     echo ""
                     echo "  Hashing referenced libraries:"
                     while IFS= read -r lib; do
                         [ -f "$lib" ] && sha256sum "$lib" || echo "  MISSING: $lib"
                     done < /etc/ld.so.preload
                 else
                     echo "  /etc/ld.so.preload not present — OK"
                 fi'
    run_cmd "$log" "Unexpected .so Files in Non-Standard Paths" \
        bash -c 'find / -xdev -name "*.so" -not -path "*/lib/*" -not -path "*/lib64/*" \
                     -not -path "*/usr/lib*" -not -path "*/proc/*" \
                     -exec ls -la {} \; 2>/dev/null | head -100 || echo "None found"'

    # ── Rootkit scanner ───────────────────────────────────────────────────
    section "$log" "Rootkit Scanners"
    run_cmd "$log" "rkhunter — Rootkit Hunter" \
        bash -c 'if command -v rkhunter &>/dev/null; then
                     rkhunter --check --skip-keypress --no-mail-on-warning 2>&1
                 else
                     echo "rkhunter not installed."
                     echo "To use: apt install rkhunter  or  yum install rkhunter"
                 fi'
    run_cmd "$log" "chkrootkit" \
        bash -c 'if [ -x "${SCRIPT_DIR}/chkrootkit" ]; then
                     "${SCRIPT_DIR}/chkrootkit" 2>&1
                 elif command -v chkrootkit &>/dev/null; then
                     chkrootkit 2>&1
                 else
                     echo "chkrootkit not found."
                     echo "To use: apt install chkrootkit  or place binary on USB as chkrootkit"
                 fi'

    # ── Timestomping detection ────────────────────────────────────────────
    section "$log" "Timestomping Detection"
    run_cmd "$log" "Files Where ctime is Significantly Newer than mtime" \
        bash -c 'find / -xdev -type f -not -path "*/proc/*" -not -path "*/sys/*" \
                     -not -path "*/run/*" 2>/dev/null | while IFS= read -r f; do
                     mtime=$(stat -c %Y "$f" 2>/dev/null)
                     ctime=$(stat -c %Z "$f" 2>/dev/null)
                     [ -z "$mtime" ] || [ -z "$ctime" ] && continue
                     diff=$(( ctime - mtime ))
                     if [ "$diff" -gt 86400 ]; then
                         echo "DIFF=${diff}s  $(stat -c "%n  mtime=%y  ctime=%z" "$f")"
                     fi
                 done 2>/dev/null | sort -rn | head -100'
    run_cmd "$log" "System Binaries Modified After OS Install Date" \
        bash -c 'install_date=$(stat -c %Y /etc/os-release 2>/dev/null || echo 0)
                 find /bin /sbin /usr/bin /usr/sbin -type f 2>/dev/null | while IFS= read -r f; do
                     mtime=$(stat -c %Y "$f" 2>/dev/null)
                     [ "$mtime" -gt "$install_date" ] && \
                         echo "NEWER THAN OS INSTALL: $(stat -c "%n  mtime=%y" "$f")"
                 done 2>/dev/null | head -100 || echo "Check failed"'
    run_cmd "$log" "ext4 inode crtime via debugfs (creation time — hard to forge)" \
        bash -c 'root_dev=$(df / | tail -1 | awk "{print \$1}")
                 if command -v debugfs &>/dev/null && [ -b "$root_dev" ]; then
                     echo "Root device: $root_dev"
                     echo "Sample inode crtime for key binaries:"
                     for f in /bin/bash /usr/bin/ssh /usr/bin/sudo; do
                         inode=$(stat -c %i "$f" 2>/dev/null)
                         [ -n "$inode" ] && echo "$f (inode $inode):" && \
                             debugfs -R "stat <$inode>" "$root_dev" 2>/dev/null | grep -E "(crtime|ctime|mtime|atime)"
                     done
                 else
                     echo "debugfs not available or root is not a block device"
                 fi'

    # ── Misc evasion indicators ───────────────────────────────────────────
    run_cmd "$log" "Files with Both Execute and Write Permissions (world-writable executables)" \
        bash -c 'find / -xdev -type f -perm -0111 -perm -0002 \
                     -not -path "*/proc/*" 2>/dev/null | head -100 || echo "None found"'
    run_cmd "$log" "Processes with Mismatched Comm vs Exe Name" \
        bash -c 'for pid in /proc/[0-9]*/; do
                     comm=$(cat "${pid}comm" 2>/dev/null)
                     exe=$(readlink "${pid}exe" 2>/dev/null)
                     [ -z "$exe" ] && continue
                     base=$(basename "$exe" 2>/dev/null)
                     [ "$comm" != "$base" ] && [ "${base%%.*}" != "$comm" ] && \
                         echo "PID=$(basename $pid)  comm=$comm  exe=$exe"
                 done 2>/dev/null | head -50 || echo "None found"'
    run_cmd "$log" "Large Files in Unusual Locations (/tmp, /dev/shm, /var/tmp)" \
        bash -c 'find /tmp /var/tmp /dev/shm -type f -size +1M \
                     -exec ls -lah {} \; 2>/dev/null || echo "None found"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 16: Web Servers & Application Artifacts ───────────────────────────────────
collect_web_app() {
    local log="$LOG_WEB_APP"
    write_header "$log" "16 — WEB SERVERS, DATABASES & APPLICATION ARTIFACTS"
    msg "Collecting: Web & Application Server Artifacts..."

    # ── Web server detection ──────────────────────────────────────────────
    section "$log" "Web Server Detection"
    run_cmd "$log" "Running Web Server Processes" \
        bash -c 'ps auxww | grep -iE "(apache|nginx|httpd|caddy|lighttpd|tomcat|gunicorn|uwsgi|node|ruby|python.*http)" | grep -v grep || echo "None detected"'

    # ── Apache ────────────────────────────────────────────────────────────
    section "$log" "Apache"
    run_cmd "$log" "Apache — Version" \
        bash -c 'apache2 -v 2>/dev/null || httpd -v 2>/dev/null || echo "Apache not installed"'
    run_cmd "$log" "Apache — Configuration (/etc/apache2/ or /etc/httpd/)" \
        bash -c 'cat /etc/apache2/apache2.conf 2>/dev/null || cat /etc/httpd/conf/httpd.conf 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Apache — Virtual Hosts" \
        bash -c 'ls -la /etc/apache2/sites-enabled/ 2>/dev/null && cat /etc/apache2/sites-enabled/* 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Apache — Access Log (last 500 lines)" \
        bash -c 'tail -500 /var/log/apache2/access.log 2>/dev/null || tail -500 /var/log/httpd/access_log 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Apache — Error Log (last 500 lines)" \
        bash -c 'tail -500 /var/log/apache2/error.log 2>/dev/null || tail -500 /var/log/httpd/error_log 2>/dev/null || echo "Not found"'

    # ── Nginx ─────────────────────────────────────────────────────────────
    section "$log" "Nginx"
    run_cmd "$log" "Nginx — Version" \
        bash -c 'nginx -v 2>&1 || echo "Nginx not installed"'
    run_cmd "$log" "Nginx — Configuration (/etc/nginx/)" \
        bash -c 'cat /etc/nginx/nginx.conf 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Nginx — Site Configurations" \
        bash -c 'ls -la /etc/nginx/sites-enabled/ 2>/dev/null && cat /etc/nginx/sites-enabled/* 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Nginx — Access Log (last 500 lines)" \
        bash -c 'tail -500 /var/log/nginx/access.log 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Nginx — Error Log (last 500 lines)" \
        bash -c 'tail -500 /var/log/nginx/error.log 2>/dev/null || echo "Not found"'

    # ── Web root analysis ─────────────────────────────────────────────────
    section "$log" "Web Root Analysis"
    run_cmd "$log" "Web Root Directories — Listing" \
        bash -c 'for d in /var/www /srv/www /srv/http /usr/share/nginx/html; do
                     [ -d "$d" ] && echo "=== $d ===" && find "$d" -type f | head -200
                 done 2>/dev/null || echo "No standard web roots found"'
    run_cmd "$log" "Recently Modified Files in Web Roots (last 7 days)" \
        bash -c 'for d in /var/www /srv/www /srv/http; do
                     [ -d "$d" ] && find "$d" -type f -mtime -7 -exec ls -la {} \; 2>/dev/null
                 done || echo "No web roots found"'
    run_cmd "$log" "Potential Web Shells — PHP Files with exec/system/passthru" \
        bash -c 'for d in /var/www /srv/www /srv/http /tmp; do
                     [ -d "$d" ] && grep -rlE "(exec|system|passthru|shell_exec|eval)\s*\(" "$d" \
                         --include="*.php" --include="*.phtml" --include="*.php5" 2>/dev/null
                 done | head -50 || echo "None found"'
    run_cmd "$log" "Potential Web Shells — JSP/ASP/CGI in Web Roots" \
        bash -c 'for d in /var/www /srv/www /srv/http; do
                     [ -d "$d" ] && find "$d" -type f \( -name "*.jsp" -o -name "*.jspx" \
                         -o -name "*.cgi" -o -name "*.pl" \) -exec ls -la {} \; 2>/dev/null
                 done || echo "None found"'

    # ── PHP session files ─────────────────────────────────────────────────
    run_cmd "$log" "PHP Session Files (/var/lib/php/sessions/)" \
        bash -c 'ls -la /var/lib/php/sessions/ 2>/dev/null || ls -la /tmp/sess_* 2>/dev/null || echo "No PHP session files found"'

    # ── Database servers ──────────────────────────────────────────────────
    section "$log" "Database Servers"
    run_cmd "$log" "MySQL / MariaDB — Status" \
        bash -c 'systemctl status mysql mariadb 2>/dev/null || echo "MySQL/MariaDB not running"'
    run_cmd "$log" "MySQL — Error Log" \
        bash -c 'cat /var/log/mysql/error.log 2>/dev/null | tail -300 || echo "Not found"'
    run_cmd "$log" "MySQL — Configuration" \
        bash -c 'cat /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null || cat /etc/my.cnf 2>/dev/null || echo "Not found"'
    run_cmd "$log" "PostgreSQL — Status" \
        bash -c 'systemctl status postgresql 2>/dev/null || echo "PostgreSQL not running"'
    run_cmd "$log" "PostgreSQL — Log (last 300 lines)" \
        bash -c 'find /var/log/postgresql -name "*.log" 2>/dev/null | xargs tail -300 2>/dev/null || echo "Not found"'
    run_cmd "$log" "MongoDB — Status" \
        bash -c 'systemctl status mongod 2>/dev/null || echo "MongoDB not running"'
    run_cmd "$log" "MongoDB — Log (last 300 lines)" \
        bash -c 'tail -300 /var/log/mongodb/mongod.log 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Redis — Status" \
        bash -c 'systemctl status redis redis-server 2>/dev/null || echo "Redis not running"'
    run_cmd "$log" "Redis — Configuration" \
        bash -c 'cat /etc/redis/redis.conf 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "Not found"'

    # ── Application servers ───────────────────────────────────────────────
    section "$log" "Application Servers"
    run_cmd "$log" "Tomcat — Status & Version" \
        bash -c 'systemctl status tomcat* 2>/dev/null; find / -xdev -name "catalina.sh" 2>/dev/null | head -5'
    run_cmd "$log" "Node.js Processes" \
        bash -c 'ps auxww | grep -i node | grep -v grep || echo "None running"'
    run_cmd "$log" "Gunicorn / uWSGI Processes" \
        bash -c 'ps auxww | grep -iE "(gunicorn|uwsgi)" | grep -v grep || echo "None running"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 17: Profile-Based Persistence ─────────────────────────────────────────────
collect_persistence() {
    local log="$LOG_PERSISTENCE"
    write_header "$log" "17 — PROFILE-BASED PERSISTENCE & STARTUP HOOKS"
    msg "Collecting: Profile-Based Persistence..."

    # ── Shell profile files ───────────────────────────────────────────────
    section "$log" "Shell Profile & RC Files — All Users"
    run_cmd "$log" "Global Shell Profiles" \
        bash -c 'for f in /etc/profile /etc/bash.bashrc /etc/zshrc /etc/zsh/zshrc \
                             /etc/environment /etc/bashrc; do
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || true'
    run_cmd "$log" "Global Profile.d Scripts (/etc/profile.d/)" \
        bash -c 'ls -la /etc/profile.d/ 2>/dev/null && cat /etc/profile.d/* 2>/dev/null || echo "Not found"'
    run_cmd "$log" "Per-User Shell Profiles (.bashrc .profile .zshrc etc.)" \
        bash -c 'for h in /root /home/*; do
                     for f in .bashrc .bash_profile .profile .zshrc .zprofile \
                               .bash_logout .xsession .xinitrc .xprofile; do
                         fp="$h/$f"
                         [ -f "$fp" ] && echo "=== $fp ===" && cat "$fp"
                     done
                 done 2>/dev/null || true'

    # ── Editor & tool configs with hook potential ─────────────────────────
    section "$log" "Editor & Tool Config Files with Hook Potential"
    run_cmd "$log" "Vim Configuration (.vimrc)" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.vimrc"
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" "Git Configuration (.gitconfig) — Hooks" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.gitconfig"
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" "Git Repository Hooks (find)" \
        bash -c 'find / -xdev -path "*/.git/hooks/*" -type f \
                     -not -path "*/proc/*" 2>/dev/null | head -50 | \
                     xargs -I{} bash -c "echo \"=== {} ===\"; cat \"{}\"" 2>/dev/null || echo "None found"'

    # ── Per-user SSH config ───────────────────────────────────────────────
    run_cmd "$log" "Per-User SSH Config Files (~/.ssh/config)" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.ssh/config"
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || echo "None found"'

    # ── Python persistence paths ──────────────────────────────────────────
    section "$log" "Python Persistence Paths"
    run_cmd "$log" "Python sitecustomize.py (executed on every Python start)" \
        bash -c 'python3 -c "import site; print(site.getusersitepackages(), site.getsitepackages())" 2>/dev/null
                 find / -xdev -name "sitecustomize.py" -not -path "*/proc/*" 2>/dev/null | \
                     xargs -I{} bash -c "echo \"=== {} ===\"; cat \"{}\"" 2>/dev/null || echo "None found"'
    run_cmd "$log" "Python usercustomize.py" \
        bash -c 'find / -xdev -name "usercustomize.py" -not -path "*/proc/*" 2>/dev/null | \
                     xargs -I{} bash -c "echo \"=== {} ===\"; cat \"{}\"" 2>/dev/null || echo "None found"'
    run_cmd "$log" "Python .pth Files in site-packages (code injection via path)" \
        bash -c 'find / -xdev -name "*.pth" -path "*/site-packages/*" 2>/dev/null | \
                     xargs -I{} bash -c "echo \"=== {} ===\"; cat \"{}\"" 2>/dev/null | head -200 || echo "None found"'

    # ── User config directories ───────────────────────────────────────────
    section "$log" "User Config Directories (~/.config/)"
    run_cmd "$log" "~/.config Directory Listings — All Users" \
        bash -c 'for h in /root /home/*; do
                     d="$h/.config"
                     [ -d "$d" ] && echo "=== $d ===" && find "$d" -type f | head -100
                 done 2>/dev/null || echo "None found"'

    # ── Desktop autostart (GUI systems) ───────────────────────────────────
    section "$log" "Desktop Autostart & Session Entries"
    run_cmd "$log" "GNOME / KDE / XDG Autostart — System" \
        bash -c 'for d in /etc/xdg/autostart /usr/share/gnome/autostart; do
                     [ -d "$d" ] && echo "=== $d ===" && ls -la "$d" && cat "$d"/*.desktop 2>/dev/null
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" "GNOME / KDE / XDG Autostart — Per User" \
        bash -c 'for h in /root /home/*; do
                     d="$h/.config/autostart"
                     [ -d "$d" ] && echo "=== $d ===" && ls -la "$d" && cat "$d"/*.desktop 2>/dev/null
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" "Xsession / Display Manager Startup Scripts" \
        bash -c 'for f in /etc/X11/Xsession.d/* /etc/gdm3/PostLogin/* /etc/lightdm/lightdm.conf; do
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || echo "None found"'

    # ── PAM & NSS module injection ────────────────────────────────────────
    section "$log" "PAM & NSS Module Integrity"
    run_cmd "$log" "PAM Modules Loaded — Non-Standard Paths" \
        bash -c 'find /lib*/security /usr/lib*/security -name "*.so" 2>/dev/null | \
                     xargs -I{} sha256sum {} 2>/dev/null'
    run_cmd "$log" "NSS Configuration (/etc/nsswitch.conf)" \
        cat /etc/nsswitch.conf

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ── 18: Cryptographic Material & Secrets ──────────────────────────────────────
collect_secrets() {
    local log="$LOG_SECRETS"
    write_header "$log" "18 — CRYPTOGRAPHIC MATERIAL & CREDENTIAL ARTIFACTS"
    {
        echo "  SENSITIVITY NOTICE: This log may contain paths to private keys,"
        echo "  credential files, and other sensitive material. Handle with"
        echo "  appropriate chain-of-custody controls. The tool records file"
        echo "  EXISTENCE, METADATA, and HASHES — not the raw key contents —"
        echo "  except where file content is explicitly required for analysis."
        echo ""
    } >> "$log"
    msg "Collecting: Cryptographic Material & Secrets..."

    # ── Private key detection ─────────────────────────────────────────────
    section "$log" "Private Key File Detection"
    run_cmd "$log" "Files Containing PEM Private Key Headers" \
        bash -c 'grep -rlI "BEGIN.*PRIVATE KEY" / --include="*.pem" --include="*.key" \
                     --include="*.crt" --include="*.p12" --include="*.pfx" \
                     2>/dev/null | head -100 || echo "None found (restricted search)"'
    run_cmd "$log" "Private Key Files — Metadata and Hashes (no content)" \
        bash -c 'find / -xdev -type f \( -name "*.key" -o -name "*.pem" -o -name "*.p12" \
                     -o -name "*.pfx" -o -name "id_rsa" -o -name "id_ecdsa" \
                     -o -name "id_ed25519" -o -name "id_dsa" \) \
                     -not -path "*/proc/*" 2>/dev/null | while IFS= read -r f; do
                     echo "=== $f ==="
                     stat -c "  Perms: %A  Owner: %U:%G  Size: %s  Modified: %y" "$f" 2>/dev/null
                     sha256sum "$f" 2>/dev/null
                 done | head -300'
    run_cmd "$log" "SSH Private Keys — All Users (metadata only)" \
        bash -c 'for h in /root /home/*; do
                     for f in "$h/.ssh/id_rsa" "$h/.ssh/id_ecdsa" "$h/.ssh/id_ed25519" \
                               "$h/.ssh/id_dsa"; do
                         [ -f "$f" ] && echo "=== $f ===" && \
                             stat -c "  Perms: %A  Owner: %U:%G  Size: %s" "$f" && \
                             sha256sum "$f"
                     done
                 done 2>/dev/null || echo "None found"'

    # ── SSL/TLS certificates ──────────────────────────────────────────────
    section "$log" "SSL/TLS Certificates"
    run_cmd "$log" "System CA Bundle" \
        bash -c 'ls -la /etc/ssl/certs/ 2>/dev/null | head -50'
    run_cmd "$log" "Non-Standard Certificate Locations" \
        bash -c 'find / -xdev -type f \( -name "*.crt" -o -name "*.cer" -o -name "*.der" \) \
                     -not -path "*/usr/share/*" -not -path "*/proc/*" 2>/dev/null | \
                     head -100 | while IFS= read -r f; do
                         echo "=== $f ===" && \
                         openssl x509 -in "$f" -noout -subject -issuer -dates 2>/dev/null || \
                         sha256sum "$f"
                     done'

    # ── GPG ───────────────────────────────────────────────────────────────
    section "$log" "GPG Keyrings"
    run_cmd "$log" "GPG Public Keys — All Users" \
        bash -c 'for h in /root /home/*; do
                     gpgdir="$h/.gnupg"
                     [ -d "$gpgdir" ] && echo "=== $h ===" && \
                         gpg --homedir "$gpgdir" --list-keys 2>/dev/null || \
                         ls -la "$gpgdir" 2>/dev/null
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" "GPG Agent Sockets" \
        bash -c 'find /tmp /run -name "S.gpg-agent*" -exec ls -la {} \; 2>/dev/null || echo "None found"'

    # ── Cloud credentials ─────────────────────────────────────────────────
    section "$log" "Cloud Provider Credential Files"
    run_cmd "$log" "AWS Credentials Files (~/.aws/credentials)" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.aws/credentials"
                     [ -f "$f" ] && echo "=== $f ===" && \
                         stat -c "  Perms: %A  Owner: %U:%G  Modified: %y" "$f" && \
                         grep -v "aws_secret_access_key" "$f"
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" "GCP Service Account Key Files" \
        bash -c 'for h in /root /home/*; do
                     d="$h/.config/gcloud"
                     [ -d "$d" ] && find "$d" -name "*.json" -exec echo "=== {} ===" \; \
                         -exec sha256sum {} \; 2>/dev/null
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" "Kubernetes Config Files (~/.kube/config)" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.kube/config"
                     [ -f "$f" ] && echo "=== $f ===" && \
                         stat -c "  Perms: %A  Owner: %U:%G" "$f" && \
                         grep -v "token:\|client-key-data:\|client-certificate-data:" "$f"
                 done 2>/dev/null || echo "None found"'

    # ── Credential files ──────────────────────────────────────────────────
    section "$log" "Plaintext Credential Files"
    run_cmd "$log" ".netrc Files (plaintext FTP/HTTP credentials)" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.netrc"
                     [ -f "$f" ] && echo "=== $f ===" && \
                         stat -c "  Perms: %A  Owner: %U:%G" "$f" && cat "$f"
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" ".pgpass Files (PostgreSQL passwords)" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.pgpass"
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" ".my.cnf Files (MySQL credentials)" \
        bash -c 'for h in /root /home/*; do
                     f="$h/.my.cnf"
                     [ -f "$f" ] && echo "=== $f ===" && cat "$f"
                 done 2>/dev/null || echo "None found"'
    run_cmd "$log" ".env Files in Web/App Directories (may contain secrets)" \
        bash -c 'find /var/www /srv /opt /home /root -name ".env" -type f \
                     -not -path "*/node_modules/*" 2>/dev/null | \
                     xargs -I{} bash -c "echo \"=== {} ===\"; cat \"{}\"" 2>/dev/null | head -300 || echo "None found"'

    # ── Password managers & keystores ─────────────────────────────────────
    section "$log" "Password Manager & Keystore Files"
    run_cmd "$log" "KeePass Database Files (.kdbx)" \
        bash -c 'find / -xdev -name "*.kdbx" -not -path "*/proc/*" 2>/dev/null | \
                     while IFS= read -r f; do
                         echo "=== $f ===" && \
                         stat -c "  Perms: %A  Owner: %U:%G  Size: %s  Modified: %y" "$f" && \
                         sha256sum "$f"
                     done | head -100 || echo "None found"'
    run_cmd "$log" "Java Keystores (.jks, .keystore)" \
        bash -c 'find / -xdev \( -name "*.jks" -o -name "*.keystore" \) \
                     -not -path "*/proc/*" 2>/dev/null | \
                     while IFS= read -r f; do
                         echo "=== $f ===" && \
                         stat -c "  Perms: %A  Owner: %U:%G  Size: %s" "$f" && \
                         sha256sum "$f"
                     done | head -100 || echo "None found"'

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"
}

# ==============================================================================
# COLLECTION MODES
# ==============================================================================

# ── 19: ClamAV Antivirus Scan ─────────────────────────────────────────────────
#
# Forensically safe flags — no files are removed, modified, or quarantined.
# Two scan passes:
#   Pass 1 — Process memory: scans /proc/*/exe and /proc/*/fd for all running
#             processes, identifying malicious executables still in memory.
#   Pass 2 — High-probability directories: targeted filesystem scan of locations
#             most commonly used for malware staging and persistence.
#
# Tool detection priority:
#   1. clamscan on the target system (installed)
#   2. clamscan binary on the USB drive beside this script
#   3. Skip with full instructions logged
#
collect_clamav() {
    local log="$LOG_CLAMAV"
    write_header "$log" "19 — CLAMAV ANTIVIRUS SCAN (READ-ONLY — NO REMOVAL)"
    {
        echo "  FORENSIC NOTICE:"
        echo "  All ClamAV scans are performed in READ-ONLY mode."
        echo "  No files will be removed, quarantined, or modified."
        echo "  Flags enforced: --no-remove (implied default, explicitly set)"
        echo "  Flags NOT used: --remove, --quarantine, --move"
        echo ""
    } >> "$log"
    msg "Collecting: ClamAV Antivirus Scan..."

    # ── Extract portable bundle if present ───────────────────────────────
    # The portable ClamAV bundle ships as a single .tar.gz on the USB.
    # If found, extract it to a temp directory for this run.
    local bundle_tmp=""
    local bundle_tarball
    bundle_tarball=$(ls "${SCRIPT_DIR}"/clamav-*-portable-*.tar.gz 2>/dev/null | head -1)

    if [[ -f "$bundle_tarball" ]]; then
        bundle_tmp=$(mktemp -d /tmp/clamav-dfir-XXXXXX)
        msg "  Extracting portable ClamAV bundle to ${bundle_tmp}..."
        echo "  Extracting bundle: ${bundle_tarball}" >> "$log"
        if tar xf "$bundle_tarball" -C "$bundle_tmp" --strip-components=1 2>>"$log"; then
            echo "  Bundle extracted successfully." >> "$log"
        else
            msg_warn "  Bundle extraction failed — will fall back to system clamscan"
            echo "  [WARN] Bundle extraction failed." >> "$log"
            rm -rf "$bundle_tmp"
            bundle_tmp=""
        fi
    fi

    # ── Locate clamscan binary ────────────────────────────────────────────
    # Priority:
    #   1. Portable bundle wrapper (clamscan.sh) extracted from USB tarball
    #   2. System-installed clamscan
    #   3. Bare clamscan binary directly on USB (legacy support)
    local clamscan_bin=""
    local clamscan_source=""

    if [[ -n "$bundle_tmp" && -x "${bundle_tmp}/bin/clamscan.sh" ]]; then
        clamscan_bin="${bundle_tmp}/bin/clamscan.sh"
        clamscan_source="USB portable bundle"
    elif command -v clamscan &>/dev/null; then
        clamscan_bin=$(command -v clamscan)
        clamscan_source="system"
    elif [[ -x "${SCRIPT_DIR}/clamscan" ]]; then
        clamscan_bin="${SCRIPT_DIR}/clamscan"
        clamscan_source="USB (bare binary)"
    fi

    if [[ -z "$clamscan_bin" ]]; then
        section "$log" "ClamAV — Not Available"
        {
            echo "  [SKIPPED] clamscan not found on system or USB drive."
            echo ""
            echo "  To enable ClamAV scanning:"
            echo ""
            echo "  Option 1 — Install on target system (requires internet/repo access):"
            echo "    Debian/Ubuntu : apt install clamav"
            echo "    RHEL/CentOS   : yum install clamav clamav-update"
            echo "    Fedora        : dnf install clamav"
            echo ""
            echo "  Option 2 — Place portable bundle on USB drive (recommended):"
            echo "    Copy the bundle tarball to the same directory as this script:"
            echo "      clamav-1.4.2-portable-x86_64-with-db.tar.gz"
            echo "    See ClamAV-Portable-Bundle-Guide.docx for full build steps."
        } >> "$log"
        msg_warn "clamscan not found — skipping ClamAV scan"
        [[ -n "$bundle_tmp" ]] && rm -rf "$bundle_tmp"
        register_log "$log"
        msg_ok "Saved → $(basename "$log")"
        return 0
    fi

    # ── Locate virus database ─────────────────────────────────────────────
    # Priority:
    #   1. db/ directory inside the extracted portable bundle
    #   2. clamav-db/ directory on the USB beside this script
    #   3. System default (/var/lib/clamav)
    #   4. No --database flag (let clamscan use its compiled-in default)
    local db_flag=""
    local db_source=""
    local usb_db_dir="${SCRIPT_DIR}/clamav-db"

    if [[ -n "$bundle_tmp" && -d "${bundle_tmp}/db" ]] && \
       ls "${bundle_tmp}/db"/*.c?d &>/dev/null 2>&1; then
        db_flag="--database=${bundle_tmp}/db"
        db_source="portable bundle  (${bundle_tmp}/db)"
    elif [[ -d "$usb_db_dir" ]] && ls "$usb_db_dir"/*.c?d &>/dev/null 2>&1; then
        db_flag="--database=${usb_db_dir}"
        db_source="USB  (${usb_db_dir})"
    elif [[ -d "/var/lib/clamav" ]] && ls /var/lib/clamav/*.c?d &>/dev/null 2>&1; then
        db_flag="--database=/var/lib/clamav"
        db_source="system  (/var/lib/clamav)"
    else
        db_flag=""
        db_source="compiled-in default (no override)"
    fi

    # ── Log tool information ──────────────────────────────────────────────
    section "$log" "ClamAV Tool Information"
    {
        echo "  Binary source   : ${clamscan_source}"
        echo "  Binary path     : ${clamscan_bin}"
        echo "  ClamAV version  : $("$clamscan_bin" --version 2>/dev/null | head -1)"
        echo "  Database source : ${db_source}"
        echo ""
        echo "  Virus database info:"
        local db_dir_check
        db_dir_check="${bundle_tmp}/db"
        [[ -z "$db_flag" || "$db_source" == system* ]] && db_dir_check="/var/lib/clamav"
        [[ "$db_source" == USB* ]] && db_dir_check="${usb_db_dir}"
        if [[ -n "$bundle_tmp" && -x "${bundle_tmp}/bin/sigtool.sh" ]]; then
            "${bundle_tmp}/bin/sigtool.sh" --info "${db_dir_check}"/main.c?d  2>/dev/null | grep -E "Version|Build|Sigs" || true
            "${bundle_tmp}/bin/sigtool.sh" --info "${db_dir_check}"/daily.c?d 2>/dev/null | grep -E "Version|Build|Sigs" || true
        elif command -v sigtool &>/dev/null; then
            sigtool --info "${db_dir_check}"/main.c?d  2>/dev/null | grep -E "Version|Build|Sigs" || true
            sigtool --info "${db_dir_check}"/daily.c?d 2>/dev/null | grep -E "Version|Build|Sigs" || true
        else
            ls -lh "${db_dir_check}"/*.c?d 2>/dev/null || \
                echo "  Database files not found in ${db_dir_check}"
        fi
    } >> "$log"

    # ── Signature update prompt ───────────────────────────────────────────
    section "$log" "Virus Signature Update"
    local freshclam_bin=""
    local freshclam_conf=""

    if [[ -n "$bundle_tmp" && -x "${bundle_tmp}/bin/freshclam.sh" ]]; then
        freshclam_bin="${bundle_tmp}/bin/freshclam.sh"
        freshclam_conf="${bundle_tmp}/etc/freshclam.conf"
    elif command -v freshclam &>/dev/null; then
        freshclam_bin=$(command -v freshclam)
    elif [[ -x "${SCRIPT_DIR}/freshclam" ]]; then
        freshclam_bin="${SCRIPT_DIR}/freshclam"
    fi

    if [[ -n "$freshclam_bin" ]]; then
        echo ""
        echo -e "  ${YELLOW}[?]${RESET} Updating ClamAV signatures requires network access."
        echo -e "  ${YELLOW}[?]${RESET} Network activity may be undesirable during active investigations."
        echo -ne "  ${BOLD}Update virus signatures now? [y/N]: ${RESET}"
        read -r update_sigs

        if [[ "${update_sigs,,}" == "y" ]]; then
            msg "  Updating signatures..."
            echo "  Running freshclam to update signatures..." >> "$log"
            local freshclam_args=()
            # Always pass --config-file when using the portable bundle
            if [[ -n "$freshclam_conf" && -f "$freshclam_conf" ]]; then
                freshclam_args+=("--config-file=${freshclam_conf}")
            fi
            # Always use absolute path for --datadir — relative paths fail
            if [[ -n "$bundle_tmp" && -d "${bundle_tmp}/db" ]]; then
                freshclam_args+=("--datadir=${bundle_tmp}/db")
            elif [[ -n "$db_flag" ]]; then
                freshclam_args+=("--datadir=${usb_db_dir}")
            fi
            if timeout 120 "$freshclam_bin" "${freshclam_args[@]}" >> "$log" 2>&1; then
                msg_ok "  Signatures updated"
                echo "  Signature update: SUCCESS" >> "$log"
            else
                msg_warn "  freshclam returned non-zero — signatures may be partially updated"
                echo "  Signature update: WARNING — non-zero exit" >> "$log"
            fi
        else
            echo "  Signature update skipped by examiner." >> "$log"
            msg "  Signature update skipped — using existing database"
        fi
    else
        echo "  freshclam not available — using existing signature database." >> "$log"
        msg_warn "freshclam not found — proceeding with existing signatures"
    fi

    # ── Common scan flags — enforces read-only forensic operation ─────────
    local SCAN_FLAGS=(
        --infected                  # only report infected files — keeps log clean
        --recursive                 # scan subdirectories
        --no-summary                # suppress per-scan summary footer
        --stdout                    # also print detections to terminal
        --follow-dir-symlinks=0     # do not follow directory symlinks
        --follow-file-symlinks=0    # do not follow file symlinks
        --max-filesize=100M         # skip files larger than 100 MB
        --max-scansize=100M         # cap total scan data per file
        --max-recursion=10          # limit archive recursion depth
        --suppress-ok-results       # omit OK lines — detections only
    )
    # Append database flag if a database location was resolved above
    [[ -n "$db_flag" ]] && SCAN_FLAGS+=("$db_flag")
    # NOTE: --remove is deliberately NOT included.
    # NOTE: --move and --quarantine are deliberately NOT included.

    # ── PASS 1: Process Memory / Running Executables ──────────────────────
    section "$log" "PASS 1 — Running Process Executables (/proc/*/exe)"
    {
        echo "  Scanning executable images of all running processes."
        echo "  This catches malware that is currently loaded in memory"
        echo "  even if the on-disk file has been deleted."
        echo ""
        echo "  Scan start: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } >> "$log"

    msg "  Pass 1: Scanning running process executables..."
    local pass1_start pass1_end

    # Build a deduplicated list of exe targets — avoids rescanning the same
    # binary multiple times when many processes share it (e.g. bash, python).
    local exe_targets=()
    local seen_exe=()
    for exe_link in /proc/[0-9]*/exe; do
        local resolved
        resolved=$(readlink "$exe_link" 2>/dev/null) || continue
        # Skip already-seen targets and kernel threads (no exe link)
        [[ " ${seen_exe[*]} " == *" ${resolved} "* ]] && continue
        seen_exe+=("$resolved")
        # Also scan the /proc link directly to catch deleted-but-running binaries
        exe_targets+=("$exe_link")
    done

    {
        echo "  Unique process executables targeted: ${#exe_targets[@]}"
        echo ""
    } >> "$log"

    pass1_start=$(date +%s)
    if [[ ${#exe_targets[@]} -gt 0 ]]; then
        "$clamscan_bin" "${SCAN_FLAGS[@]}" \
            "${exe_targets[@]}" 2>&1 | \
            grep -v "^$" | head -200 >> "$log" || true
    else
        echo "  No process exe targets found." >> "$log"
    fi
    pass1_end=$(date +%s)

    {
        echo ""
        echo "  Pass 1 elapsed: $(( pass1_end - pass1_start ))s"
        echo "  Pass 1 complete: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    } >> "$log"
    msg_ok "  Pass 1 complete ($(( pass1_end - pass1_start ))s)"

    # ── PASS 2: Open File Descriptors (/proc/*/fd) ────────────────────────
    section "$log" "PASS 2 — Open File Descriptors (/proc/*/fd)"
    {
        echo "  Scanning file descriptors held open by running processes."
        echo "  This catches malicious libraries, scripts, or data files"
        echo "  that processes currently have open — including deleted files"
        echo "  still accessible via file descriptor."
        echo ""
        echo "  Scan start: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } >> "$log"

    msg "  Pass 2: Scanning open file descriptors..."
    local pass2_start pass2_end
    pass2_start=$(date +%s)

    "$clamscan_bin" "${SCAN_FLAGS[@]}" \
        /proc/[0-9]*/fd/ 2>/dev/null | \
        grep -v "^$" | grep -v "Permission denied" | head -500 >> "$log" 2>&1 || true

    pass2_end=$(date +%s)
    {
        echo ""
        echo "  Pass 2 elapsed: $(( pass2_end - pass2_start ))s"
        echo "  Pass 2 complete: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    } >> "$log"
    msg_ok "  Pass 2 complete ($(( pass2_end - pass2_start ))s)"

    # ── PASS 3: High-Probability Filesystem Directories ───────────────────
    section "$log" "PASS 3 — High-Probability Filesystem Directories"
    {
        echo "  Targeted scan of directories most commonly used for malware"
        echo "  staging, persistence, and web shell deployment."
        echo ""
        echo "  Directories targeted:"
    } >> "$log"

    # Ordered by likelihood of containing malware — most suspicious first
    local SCAN_DIRS=(
        /tmp
        /var/tmp
        /dev/shm
        /run
        /root
        /home
        /var/www
        /srv
        /opt
        /usr/local/bin
        /usr/local/sbin
        /usr/local/lib
        /etc/cron.d
        /etc/cron.daily
        /etc/cron.hourly
        /etc/cron.weekly
        /etc/cron.monthly
        /etc/init.d
        /etc/profile.d
        /var/spool/cron
    )

    # Log which directories actually exist on this system
    local existing_scan_dirs=()
    for d in "${SCAN_DIRS[@]}"; do
        if [[ -d "$d" ]]; then
            echo "    [EXISTS] $d" >> "$log"
            existing_scan_dirs+=("$d")
        else
            echo "    [SKIP]   $d (not present)" >> "$log"
        fi
    done

    {
        echo ""
        echo "  Scan start: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } >> "$log"

    msg "  Pass 3: Scanning high-probability directories..."
    local pass3_start pass3_end
    pass3_start=$(date +%s)

    if [[ ${#existing_scan_dirs[@]} -gt 0 ]]; then
        "$clamscan_bin" "${SCAN_FLAGS[@]}" \
            "${existing_scan_dirs[@]}" 2>&1 | \
            grep -v "^$" >> "$log" || true
    else
        echo "  No target directories found on this system." >> "$log"
    fi

    pass3_end=$(date +%s)
    {
        echo ""
        echo "  Pass 3 elapsed: $(( pass3_end - pass3_start ))s"
        echo "  Pass 3 complete: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    } >> "$log"
    msg_ok "  Pass 3 complete ($(( pass3_end - pass3_start ))s)"

    # ── Scan summary ──────────────────────────────────────────────────────
    section "$log" "ClamAV Scan Summary"
    {
        local total_elapsed=$(( pass3_end - pass1_start ))
        echo "  Pass 1 (process exe)    : $(( pass1_end - pass1_start ))s"
        echo "  Pass 2 (open fds)       : $(( pass2_end - pass2_start ))s"
        echo "  Pass 3 (filesystem)     : $(( pass3_end - pass3_start ))s"
        echo "  Total elapsed           : ${total_elapsed}s"
        echo ""
        echo "  Detections (FOUND lines in this log):"
        local detections
        detections=$(grep -c ": FOUND" "$log" 2>/dev/null) || detections=0
        if [[ "$detections" -gt 0 ]]; then
            echo "  *** ${detections} DETECTION(S) — see FOUND entries above ***"
            echo ""
            echo "  Detection summary:"
            grep ": FOUND" "$log" 2>/dev/null | sed 's/^/    /' || true
        else
            echo "  No detections found."
        fi
        echo ""
        echo "  REMINDER: No files were removed, modified, or quarantined."
    } >> "$log"

    register_log "$log"
    msg_ok "Saved → $(basename "$log")"

    # ── Clean up extracted bundle temp directory ──────────────────────────
    if [[ -n "$bundle_tmp" && -d "$bundle_tmp" ]]; then
        rm -rf "$bundle_tmp"
        msg "  Portable ClamAV bundle cleaned up from ${bundle_tmp}"
    fi
}

# ==============================================================================
# COLLECTION RUNNER
# Central dispatcher — takes a profile name and runs the correct module set.
# All collection modes funnel through here to eliminate code duplication and
# ensure consistent pre-flight checks, case warnings, and finalization.
# ==============================================================================

# Warn if no case has been created; give examiner the chance to abort or proceed.
# Returns 0 to proceed, 1 to abort.
require_case_or_confirm() {
    if [[ -n "$CASE_NUMBER" ]]; then
        return 0
    fi
    echo ""
    echo -e "  ${YELLOW}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "  ${YELLOW}│  WARNING: No case has been created.                         │${RESET}"
    echo -e "  ${YELLOW}│  All collection logs will show [not set] for case fields.   │${RESET}"
    echo -e "  ${YELLOW}│  It is strongly recommended to create a case first          │${RESET}"
    echo -e "  ${YELLOW}│  (option 3 on the main menu).                               │${RESET}"
    echo -e "  ${YELLOW}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    echo -ne "  ${BOLD}Proceed without a case? [y/N]: ${RESET}"
    read -r go
    [[ "${go,,}" == "y" ]] && return 0 || return 1
}

# Core runner — called by every profile function.
# Usage: run_profile <PROFILE_NAME> <collect_fn> [collect_fn ...]
run_profile() {
    local profile="$1"; shift

    check_root
    check_mount
    require_case_or_confirm || return 0
    setup_collection "$profile"

    msg "Starting ${profile} collection for $(hostname -s)..."
    {
        echo "  Profile : ${profile}"
        echo "  Start   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } >> "$MANIFEST"

    # Execute each collection function passed as arguments
    local fn
    for fn in "$@"; do
        "$fn"
    done

    finalize_manifest "$profile"
    echo ""
    msg_ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_ok " ${profile} COMPLETE"
    msg_ok " Case directory: ${CASE_DIR}"
    msg_ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ==============================================================================
# COLLECTION PROFILES
# Each function defines the ordered module list for that profile and calls
# run_profile. Volatile artifacts (memory, processes, network) always come
# first where applicable — order is forensically significant.
# ==============================================================================

# ── Baseline (Non-DFIR) ───────────────────────────────────────────────────────
run_baseline() {
    run_profile "BASELINE" \
        collect_system_info \
        collect_hardware_info \
        collect_user_info \
        collect_scheduled_jobs \
        collect_process_info \
        collect_network_info \
        collect_software_info \
        collect_filesystem_info \
        collect_file_listing
}

# ── Full IR ───────────────────────────────────────────────────────────────────
run_full_ir() {
    run_profile "FULL_IR" \
        collect_memory \
        collect_process_info \
        collect_network_info \
        collect_system_info \
        collect_hardware_info \
        collect_user_info \
        collect_scheduled_jobs \
        collect_log_files \
        collect_software_info \
        collect_containers \
        collect_cloud \
        collect_anti_forensics \
        collect_web_app \
        collect_persistence \
        collect_secrets \
        collect_filesystem_info \
        collect_file_listing \
        collect_clamav \
        collect_triage_files_profile
}

# ── Fast IR ───────────────────────────────────────────────────────────────────
run_fast_ir() {
    run_profile "FAST_IR" \
        collect_memory \
        collect_process_info \
        collect_network_info \
        collect_system_info \
        collect_user_info \
        collect_scheduled_jobs \
        collect_anti_forensics \
        collect_log_files \
        collect_triage_files_profile
}

# ── Network IR ────────────────────────────────────────────────────────────────
run_network_ir() {
    run_profile "NETWORK_IR" \
        collect_memory \
        collect_process_info \
        collect_network_info \
        collect_log_files \
        collect_containers \
        collect_cloud \
        collect_anti_forensics \
        collect_triage_files_profile
}

# ── Web Intrusion ─────────────────────────────────────────────────────────────
run_web_intrusion() {
    run_profile "WEB_INTRUSION" \
        collect_memory \
        collect_process_info \
        collect_network_info \
        collect_web_app \
        collect_filesystem_info \
        collect_log_files \
        collect_persistence \
        collect_anti_forensics \
        collect_triage_files_profile
}

# ── Cloud IR ──────────────────────────────────────────────────────────────────
run_cloud_ir() {
    run_profile "CLOUD_IR" \
        collect_memory \
        collect_process_info \
        collect_network_info \
        collect_cloud \
        collect_containers \
        collect_secrets \
        collect_log_files \
        collect_anti_forensics \
        collect_triage_files_profile
}

# ── Malware / APT ─────────────────────────────────────────────────────────────
run_malware_apt() {
    run_profile "MALWARE_APT" \
        collect_memory \
        collect_process_info \
        collect_anti_forensics \
        collect_clamav \
        collect_persistence \
        collect_scheduled_jobs \
        collect_filesystem_info \
        collect_log_files \
        collect_secrets \
        collect_triage_files_profile
}

# ── Insider Threat ────────────────────────────────────────────────────────────
run_insider_threat() {
    run_profile "INSIDER_THREAT" \
        collect_process_info \
        collect_user_info \
        collect_log_files \
        collect_persistence \
        collect_secrets \
        collect_filesystem_info \
        collect_scheduled_jobs \
        collect_network_info \
        collect_triage_files_profile
}

# ── Profile-aware triage archive wrapper ──────────────────────────────────────
# collect_triage_files requires a mode argument (FAST/FULL).  For IR profiles
# we use FULL coverage; the function already exists and handles the file list.
collect_triage_files_profile() {
    collect_triage_files "FULL"
}

# ==============================================================================
# MENU
# ==============================================================================

print_banner() {
    echo -e "${BLUE}"
    cat <<'BANNER'
  ╔══════════════════════════════════════════════════════════════╗
  ║        Linux Baseline & Forensic Triage Tool (LBFTT)         ║
  ║                       Version 1.5.1                          ║
  ║  ──────────────────────────────────────────────────────────  ║
  ║               Written by: John G. Asmussen                   ║
  ║             EGA Technology Specialists, LLC.                 ║
  ║                       GNU GPL v3.0                           ║
  ╚══════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${RESET}"
}

# Print current case status block — used in both the main menu and
# the profile selection menu so the examiner always sees case context.
print_case_status() {
    if [[ -n "$CASE_NUMBER" ]]; then
        echo -e "  ${GREEN}${BOLD}● ACTIVE CASE${RESET}"
        echo -e "    ${BOLD}Case No  :${RESET} ${CASE_NUMBER}"
        echo -e "    ${BOLD}Case Name:${RESET} ${CASE_NAME:-[not set]}"
        echo -e "    ${BOLD}Examiner :${RESET} ${CASE_EXAMINER:-[not set]}"
        echo -e "    ${BOLD}Agency   :${RESET} ${CASE_AGENCY:-[not set]}"
    else
        echo -e "  ${YELLOW}${BOLD}● NO ACTIVE CASE${RESET}${YELLOW} — create one before collecting (option 3)${RESET}"
    fi
}

show_profile_menu() {
    while true; do
        clear
        print_banner
        echo -e "  ${BOLD}Target   :${RESET} $(hostname -f 2>/dev/null || hostname)"
        echo -e "  ${BOLD}Date/Time:${RESET} $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo -e "  ${BOLD}Output   :${RESET} ${DEST}/<hostname>.<timestamp>.<PROFILE>/"
        echo ""
        print_case_status
        echo ""

        # ── Pre-Flight ───────────────────────────────────────────────────────
        echo -e "  ${BOLD}PRE-FLIGHT${RESET}"
        echo -e "  ${CYAN}1)${RESET}  Check USB Mount Location"
        echo -e "  ${CYAN}2)${RESET}  Check Root / Sudo Privileges"
        echo -e "  ${CYAN}3)${RESET}  ${BOLD}Create / Edit Case${RESET}"
        echo ""

        # ── Baseline ─────────────────────────────────────────────────────────
        echo -e "  ${BOLD}BASELINE  ${RESET}${BLUE}(Non-DFIR / System Administration)${RESET}"
        echo -e "  ${CYAN}4)${RESET}  ${GREEN}BASELINE${RESET}"
        echo -e "     System normalcy snapshot — no memory acquisition"
        echo ""

        # ── IR Profiles ──────────────────────────────────────────────────────
        echo -e "  ${BOLD}INCIDENT RESPONSE PROFILES${RESET}"
        echo -e "  ${CYAN} 5)${RESET}  ${RED}FULL IR${RESET}"
        echo -e "      All 18 modules + ClamAV scan — complete forensic collection (slow)"
        echo ""
        echo -e "  ${CYAN} 6)${RESET}  ${YELLOW}FAST IR${RESET}"
        echo -e "      Memory, processes, network, users, jobs, anti-forensics, logs"
        echo ""
        echo -e "  ${CYAN} 7)${RESET}  ${YELLOW}NETWORK IR${RESET}"
        echo -e "      Network intrusion — connections, firewall, containers, cloud, logs"
        echo ""
        echo -e "  ${CYAN} 8)${RESET}  ${YELLOW}WEB INTRUSION${RESET}"
        echo -e "      Web server compromise — web app, filesystem, logs, persistence"
        echo ""
        echo -e "  ${CYAN} 9)${RESET}  ${YELLOW}CLOUD IR${RESET}"
        echo -e "      Cloud/container incident — cloud agents, containers, secrets, logs"
        echo ""
        echo -e "  ${CYAN}10)${RESET}  ${YELLOW}MALWARE / APT${RESET}"
        echo -e "      Malware & advanced threat — memory, anti-forensics, ClamAV scan, persistence"
        echo ""
        echo -e "  ${CYAN}11)${RESET}  ${YELLOW}INSIDER THREAT${RESET}"
        echo -e "      User activity & data access — users, logs, secrets, persistence"
        echo ""

        echo -e "  ${CYAN}─────────────────────────────────────────────────────${RESET}"
        echo -e "  ${CYAN} 0)${RESET}  Exit"
        echo ""
        echo -ne "  ${BOLD}Choose an option [0-11]: ${RESET}"
        read -r choice

        case "$choice" in
            1)  clear; check_mount
                echo ""; read -rp "  Press ENTER to continue..." ;;

            2)  clear; check_root
                echo ""; read -rp "  Press ENTER to continue..." ;;

            3)  clear; create_case
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            4)  clear; run_baseline
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            5)  clear; run_full_ir
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            6)  clear; run_fast_ir
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            7)  clear; run_network_ir
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            8)  clear; run_web_intrusion
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            9)  clear; run_cloud_ir
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            10) clear; run_malware_apt
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            11) clear; run_insider_threat
                echo ""; read -rp "  Press ENTER to return to menu..." ;;

            0)  clear
                echo -e "  ${GREEN}Exiting LBFTT.${RESET}"
                echo -e "  ${YELLOW}Remember to unmount the forensic drive before removing it:${RESET}"
                echo -e "  ${BOLD}    sudo umount ${DEST}${RESET}"
                echo ""
                exit 0 ;;

            *)  msg_err "Invalid option. Please choose 0–11."
                sleep 1 ;;
        esac
    done
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

# CLI / non-interactive mode:
#   sudo ./LBFTT.sh baseline
#   sudo ./LBFTT.sh full_ir
#   sudo ./LBFTT.sh fast_ir
#   sudo ./LBFTT.sh network_ir
#   sudo ./LBFTT.sh web_intrusion
#   sudo ./LBFTT.sh cloud_ir
#   sudo ./LBFTT.sh malware_apt
#   sudo ./LBFTT.sh insider_threat
if [[ $# -gt 0 ]]; then
    case "${1,,}" in
        baseline)       run_baseline       ;;
        full_ir)        run_full_ir        ;;
        fast_ir)        run_fast_ir        ;;
        network_ir)     run_network_ir     ;;
        web_intrusion)  run_web_intrusion  ;;
        cloud_ir)       run_cloud_ir       ;;
        malware_apt)    run_malware_apt    ;;
        insider_threat) run_insider_threat ;;
        *)
            echo ""
            echo "  Usage: $0 [profile]"
            echo ""
            echo "  Profiles:"
            echo "    baseline        System normalcy snapshot (non-DFIR)"
            echo "    full_ir         All 18 modules + ClamAV scan"
            echo "    fast_ir         Volatile + critical artifacts"
            echo "    network_ir      Network intrusion investigation"
            echo "    web_intrusion   Web server compromise"
            echo "    cloud_ir        Cloud/container incident"
            echo "    malware_apt     Malware & advanced persistent threat + ClamAV scan"
            echo "    insider_threat  User activity & data access"
            echo ""
            echo "  Interactive: sudo $0"
            echo ""
            exit 1
            ;;
    esac
else
    show_profile_menu
fi
