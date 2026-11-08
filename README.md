# SamTimer

One-tap Android root for Samsung Galaxy devices, built around the
**CVE-2026-98260** timer exploit (posix-cpu-timers UAF) and a
**KernelSU-Next** late-load module with Samsung KDP/RKP/DEFEX compatibility.

> Based on the **CVE-2026-98260-aurora** repo — its timer LPE port
> (real-cred zero-write / fake-cred ksud late-load chains) is what
> `app/src/main/cpp/timer.c` evolved from.

> [!WARNING]
> For devices you own or are explicitly authorized to test. The exploit is a
> probabilistic kernel UAF — a failed run can leave the system unstable until
> the next reboot. Rebooting always restores the phone to a clean, unrooted
> state.

## Overview

| | |
| --- | --- |
| Exploit | CVE-2026-98260 (timer.c payload, built by Gradle) |
| Root module | KernelSU-Next 3.4.2 (`ksud-next-generic-kdp`, android14-6.1 no-patch-text) |
| Execution context | Shizuku shell (uid 2000) |
| su authorization | KernelSU-Next manager (`com.rifsxd.ksunext`), domain `u:r:ksu:s0` |
| Root lifetime | Per-boot (ephemeral — cleared on reboot) |

Tested on **SM-S921N** (e1s, Exynos 2400), kernel `6.1.162-android14-11`, OneUI 9 (original).

**Port target (this tree):** **SM-S948U** (Galaxy S26 Ultra, T-Mobile), Android 16 / One UI 9.0, kernel `6.12.69-android16-6-pa4ef354-abogkiS948USQU5BZJA-4k`. Kernel addresses/sites and key offsets were re-derived from `Kerneldump/vmlinux.elf` (symtab) and `Kerneldump/kallsyms*`; cred/task layout, SELinux blob/workqueue UMH internals, and tracepoint size/field parsing for 6.12 still require **on-device validation** before relying on the full fake/KSU chain.

## Features

- Material 3 Compose UI (English / Korean, follows the system locale)
- Live root badge — detects the loaded KernelSU module every few seconds
- Confirmation dialog before every run; **re-root** button stays available
  when already rooted
- **Auto-root after reboot** — boot receiver → WorkManager chain that waits
  for Shizuku, then runs the chain headless with progress notifications;
  a failed run disables the option itself (boot-loop protection)
- The exploit payload is compiled automatically by Gradle — `assembleDebug`
  always ships a fresh binary

## Requirements

1. **Shizuku** running (wireless debugging). For auto-root: enable Shizuku's
   boot auto-start and grant its permission to SamTimer once.
2. **KernelSU-Next manager** (`com.rifsxd.ksunext`) installed — su is only
   granted to apps the manager authorizes.

## Build

```sh
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

- `app/src/main/cpp/timer.c` is compiled into
  `app/src/main/jniLibs/arm64-v8a/libtimer.so` by the `buildPayload` task
  (NDK is auto-detected: `ANDROID_NDK_HOME` → `local.properties` → SDK →
  `~/android-ndk-r27c`)
- `libksud.so` is a prebuilt KernelSU-Next late-load daemon
- `./gradlew clean` removes all outputs **including** the generated payload
  (the prebuilt `libksud.so` is kept)

## Usage

1. Start Shizuku, open SamTimer
2. Tap **Root now** → confirm → wait 1–7 minutes
3. Grant `su` to your apps in the KernelSU-Next manager
4. Optionally enable **Auto-root after reboot**

## Chain

1. `timer.c` leaks the child cred through the kmem trace, clears the DEFEX
   `creds_hash` slot, installs a forged uid-0 cred (the `selinux_state` write
   lands at `-7` so `initialized` survives — an 8-byte zero at offset 0 kills
   the policy-loaded flag and breaks every property write)
2. The root worker adopts `u:r:init:s0`, binds `ksud` over `/system/bin/logcat`
   inside a private mount namespace (KDP-safe exec) and runs
   `late-load --package-name com.rifsxd.ksunext`
3. KernelSU-Next loads (no-patch-text build — live text patching panics on
   Exynos 2400), SELinux is restored to enforcing by ksud
4. Success is verified through the KSU driver's `reboot()` backdoor ioctl
5. Failed-plant zombies are kept unreaped by a parked holder process until
   reboot (reaping them corrupts live kernel memory — keep it alive)

## Credits / upstream

- [CVE-2026-98260-aurora](https://github.com/sbmatch/CVE-2026-98260-aurora) — this app is built on the `aurora` repo's timer
  LPE port: the `timer.c` payload (real-cred zero-write and fake-cred /
  ksud late-load chains) started there and lives in this project as
  `app/src/main/cpp/timer.c`
- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy) —
  the verified Samsung KSU late-load flow this app mirrors (`su_daemon.c`
  shape, `.ksud-stage` staging, manager pairing)
- [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) —
  per-target `ksud`/`kernelsu.ko` pairs and the Samsung KDP/RKP/DEFEX port
  methodology (exact-release vermagic, no-patch-text for Exynos)
- [rushiranpise/Root-My-Galaxy-Payloads](https://github.com/rushiranpise/Root-My-Galaxy-Payloads) —
  Samsung delta patches for KernelSU 3.2.5–3.4.2, KernelSU-Next and
  ReSukiSU; `ksud-next-generic-kdp` (KernelSU-Next 3.4.2) used here
- [tiann/KernelSU](https://github.com/tiann/KernelSU) ·
  [KernelSU-Next/KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next) —
  the root module lineage
- [DirtyFrag](https://github.com/mitschud/DirtyFrag) (CVE-2026-43284, DFRoot
  lineage) — the autorun / failed-run-interlock pattern
- [Shizuku](https://github.com/RikkaApps/Shizuku) — shell-uid execution
  without a PC

## Disclaimer

Use at your own risk. The authors take no responsibility for data loss,
bricked devices, or anything else that happens to hardware you point this at.
