#!/bin/sh
# hash-manifest.sh - build the name->hash manifest that gives ModuleGate
# audit hashes an identity. Run on-device as root (adb su / KSU shell):
#
#   sh hash-manifest.sh [/vendor/lib/modules /vendor_dlkm ...] > /sdcard/mg-manifest.txt
#
# Then match: every `module-gate: ... sha256:H ...` dmesg line joins
# against this file (H -> path). No manifest, no names -- the kernel
# stores hashes only by design, so provenance lives here, in userspace.
# Re-run after OTAs / vendor updates (module bytes change, hashes follow).
set -u
found=0
for d in "$@" /vendor/lib/modules /vendor_dlkm/lib/modules /system/lib/modules /data/adb/modules; do
    [ -d "$d" ] || continue
    find "$d" -name '*.ko' 2>/dev/null | while IFS= read -r ko; do
        h=$(sha256sum "$ko" 2>/dev/null | cut -d' ' -f1)
        [ -n "$h" ] && { echo "$h  $ko"; found=1; }
    done
done
[ "$found" = "1" ] || echo "hash-manifest: no .ko files under: $*" >&2
