#!/bin/sh
# setup.sh - integrate ModuleGate into a kernel tree.
#
# Run with cwd = repo-sync root (the dir containing common/):
#   setup.sh [--cleanup | <commit-or-tag>]
#
# Symlinks security/module-gate at the driver, hooks security/Makefile
# and security/Kconfig (idempotent), and appends module_gate to the LSM
# default list (verified). Full clone: keeps .git for pinning/versioning.
# No tree compat probes needed: the kernel_post_load_data hook signature
# is identical from 5.10 through 6.18 (verified, not guessed).
set -eu

GKI_ROOT=$(pwd)
NAME="module-gate"
REPO_URL="https://github.com/sysretq0/android-module-gate"

initialize_variables() {
    if [ -d "$GKI_ROOT/security" ]; then
        SECURITY_DIR="$GKI_ROOT/security"
    elif [ -d "$GKI_ROOT/common/security" ]; then
        SECURITY_DIR="$GKI_ROOT/common/security"
    else
        echo '[ERROR] "security/" directory not found.'
        exit 127
    fi

    SECURITY_MAKEFILE=$SECURITY_DIR/Makefile
    SECURITY_KCONFIG=$SECURITY_DIR/Kconfig
}

perform_cleanup() {
    echo "[+] Cleaning up ModuleGate..."
    [ -L "$SECURITY_DIR/module-gate" ] && rm -f "$SECURITY_DIR/module-gate" && echo "[-] Symlink removed."
    grep -q "module-gate" "$SECURITY_MAKEFILE" 2>/dev/null && sed -i '/module-gate/d' "$SECURITY_MAKEFILE" && echo "[-] Makefile reverted."
    grep -q "security/module-gate/Kconfig" "$SECURITY_KCONFIG" 2>/dev/null && sed -i '/security\/module-gate\/Kconfig/d' "$SECURITY_KCONFIG" && echo "[-] Kconfig reverted."
    grep -q "module_gate" "$SECURITY_KCONFIG" 2>/dev/null && sed -i 's/,module_gate//g' "$SECURITY_KCONFIG" && echo "[-] LSM list reverted."
}

setup_gate() {
    echo "[+] Setting up ModuleGate..."
    if [ -d "$NAME/.git" ]; then
        ( cd "$NAME"
          git fetch origin +refs/heads/*:refs/remotes/origin/* >/dev/null 2>&1 || true
          if [ -n "${1-}" ]; then
              git fetch origin "$1" || true
              git checkout -q "$1"
          else
              git checkout -q main || git checkout -q master || true
              git pull --ff-only || true
          fi
        )
        echo "[+] Repository updated."
    elif [ ! -d "$NAME" ]; then
        if [ -n "${1-}" ]; then
            git clone --branch "$1" "$REPO_URL" "$NAME"
        else
            git clone "$REPO_URL" "$NAME"
        fi
        echo "[+] Repository cloned."
    fi

    # Modern LSM infrastructure required (all GKI 5.10+ have it).
    if ! grep -q "DEFINE_LSM" "$SECURITY_DIR/../include/linux/lsm_hooks.h" 2>/dev/null; then
        echo "[ERROR] Modern LSM infrastructure not found."
        exit 1
    fi

    cd "$SECURITY_DIR"
    if command -v realpath >/dev/null 2>&1; then
        rel="$(realpath --relative-to="$SECURITY_DIR" "$GKI_ROOT/$NAME/kernel/src" 2>/dev/null || true)"
    else
        rel="$GKI_ROOT/$NAME/kernel/src"
    fi
    [ -n "$rel" ] || rel="$GKI_ROOT/$NAME/kernel/src"
    ln -sfn "$rel" module-gate
    echo "[+] Symlink created."

    grep -q "module-gate/" "$SECURITY_MAKEFILE" || \
        printf '\nobj-$(CONFIG_MODULE_GATE) += module-gate/\n' >> "$SECURITY_MAKEFILE"
    echo "[+] Makefile updated."

    if ! grep -q "security/module-gate/Kconfig" "$SECURITY_KCONFIG"; then
        awk '
            /^endmenu[[:space:]]*$/ { last_match = NR }
            { lines[NR] = $0 }
            END {
                for (i = 1; i <= NR; i++) {
                    if (i == last_match) print "source \"security/module-gate/Kconfig\""
                    print lines[i]
                }
            }
        ' "$SECURITY_KCONFIG" > "$SECURITY_KCONFIG.tmp" && mv "$SECURITY_KCONFIG.tmp" "$SECURITY_KCONFIG"
        echo "[+] Kconfig updated."
    else
        echo "[-] Kconfig already modified."
    fi

    # Activate in the LSM default list (verified below). Scoped to the
    # LSM stanza; appends after the selinux token present on all trees.
    sed -i '/^config LSM$/,/^help$/ { /^[[:space:]]*default/ { /module_gate/! s/selinux/selinux,module_gate/ } }' "$SECURITY_KCONFIG"
    if grep -q "module_gate" "$SECURITY_KCONFIG"; then
        echo "[+] LSM list includes module_gate."
    else
        echo "[ERROR] LSM list update failed (no selinux token in defaults?)."
        exit 1
    fi

    echo "[+] Done."
}

if [ "$#" -eq 0 ]; then
    initialize_variables
    setup_gate
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 [--cleanup | <commit-or-tag>]"
elif [ "$1" = "--cleanup" ]; then
    initialize_variables
    perform_cleanup
else
    initialize_variables
    setup_gate "$@"
fi
