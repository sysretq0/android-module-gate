# ModuleGate

Tiny LSM: audit + gate kernel module loads. Every `insmod`/`modprobe`/init/autoload path converges on `finit_module` → `kernel_post_load_data(LOADING_MODULE)`; this hooks exactly that, hashing the actual module bytes (SHA256) instead of trusting names.

- **Audit mode** (default): unknown hashes auto-enroll (TOFU), allowed, logged
- **Enforce mode**: unknown hashes denied with `-EPERM`, logged, counted
- **Boot never enforces** (`system_state < SYSTEM_RUNNING`): a wrong list can't brick boot; audit still records everything
- **Enforcement is never compiled in.** There is no Kconfig, cmdline, or
  default that turns enforcement on. The only path is an explicit runtime
  write to `mode` -- preferably ROM-side, in `init.rc`, so it survives
  factory resets and needs no app, no manager, no root session:
  `on post-fs-data` (strict) or `on property:sys.boot_completed=1`
  (relaxed), plus the sepolicy allow for init below. Until that write
  lands, the device is in audit: observing, enrolling, allowing.

## Persistence (RAM-only state)

List + mode reset every boot. TOFU re-enrolls vendor modules silently,
but manual adds evaporate -- so persist them ROM-side: keep a hash file
(one hex per line) on persistent storage and restore it with
`tools/load-list.sh` from the same init.rc trigger, *before* the mode
write (adds first, enforce last). The kernel stays stateless by design;
durability is the ROM's job.
- One hook, once per load — no hot path, no timers, no polling

Inspired by [Baseband Guard](https://github.com/showdo/BBG) (see Partition Guard for the full story); sibling of [Partition Guard](https://github.com/sysretq0/android-partition-guard).

## Threat model

Closes the LKM door: even with root, `insmod evil.ko` dies unless allowlisted. Does not stop userspace malware (SELinux/Play Protect's layer), boot-image tampering (already won), or built-ins. Guardrail, not cage.

## sysfs (`/sys/kernel/module_gate/`)

| Node | Access | Meaning |
|---|---|---|
| `mode` | 0600 | `0` audit, `1` enforce |
| `enrolled` | 0400 | enrolled SHA256 hashes, one per line |
| `denied` | 0400 | denial counter |
| `add` | 0200 | enroll a hex hash |
| `remove` | 0200 | drop a hex hash |

## SELinux

`/sys/kernel/module_gate/` is unlabeled sysfs by default: confined
domains get DAC-permitted but SELinux-denied. `sepolicy/module_gate.te`
holds the snippet (init rw only if driven from init.rc; shell rw
because the CoreShift daemon runs as `u:r:shell:s0`; never
`untrusted_app`). Apply via
`magiskpolicy --live` or a companion module's `sepolicy.rule`.

## Integrate

```sh
bash kernel/setup.sh            # tracks main
bash kernel/setup.sh <ref>      # pin
```

## License

GPL-2.0-only (kernel code).
