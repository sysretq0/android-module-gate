#!/bin/sh
# load-list.sh - persist ModuleGate state across reboots (ROM/init side).
#
# The kernel keeps list + mode in RAM only: every boot starts empty in
# audit. This script restores both from a file on persistent storage,
# then enforces. Run it from init.rc AFTER the stores it reads exist:
#
#   on post-fs-data
#       exec u:root -- /system/bin/mg-load-list.sh
#
# Flow: TOFU enrolls this boot's vendor modules during audit (first-stage
# init runs before this trigger), then this script merges the persisted
# manual adds and flips the switch. Order matters: adds first, mode last.
#
# File format: one hex SHA256 per line, # comments ok. Keep it on a
# persistent, root-only path (default below).
LIST="${MG_LIST:-/data/misc/module_gate/allowlist}"
SYS=/sys/kernel/module_gate

[ -d "$SYS" ] || exit 0  # gate not built in: nothing to do

if [ -f "$LIST" ]; then
    while IFS= read -r h || [ -n "$h" ]; do
        case "$h" in ''|'#'*) continue;; esac
        echo "$h" > "$SYS/add" 2>/dev/null || echo "mg-load-list: reject $h"
    done < "$LIST"
fi
echo 1 > "$SYS/mode" 2>/dev/null && echo "mg-load-list: enforcing" || echo "mg-load-list: enforce refused"
