# ModuleGate

Tiny LSM: audit + gate kernel module loads. Every `insmod`/`modprobe`/init/autoload path converges on `finit_module` → `kernel_post_load_data(LOADING_MODULE)`; this hooks exactly that, hashing the actual module bytes (SHA256) instead of trusting names.

- **Audit mode** (default): unknown hashes auto-enroll (TOFU), allowed, logged
- **Enforce mode**: unknown hashes denied with `-EPERM`, logged, counted
- **Boot never enforces** (`system_state < SYSTEM_RUNNING`): a wrong list can't brick boot; audit still records everything
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
holds the snippet (init rw only if you drive enforcement from init.rc;
otherwise shell/su is enough; never `untrusted_app`). Apply via
`magiskpolicy --live` or a companion module's `sepolicy.rule`.

## Integrate

```sh
bash kernel/setup.sh            # tracks main
bash kernel/setup.sh <ref>      # pin
```

## License

GPL-2.0-only (kernel code).
