# Design Document — Process Hollowing Detector

## Overview

The detector is a single-binary C program that runs on Linux and looks for signs
that a running process has had its memory replaced with different code (process
hollowing).

Two main detection methods are used:

1. **ELF header comparison** — compare the ELF header at the base address in
   live process memory against the same binary on disk.  Any difference in
   the identity bytes, type, or machine fields means the image was tampered.

2. **Anonymous executable region detection** — a normal process should not
   have executable memory that has no backing file.  Every executable region
   should map back to a `.so` or the main binary.  A region with no path is
   a strong indicator that injected shellcode is running.

---

## Data flow

```
main()
  ├── scan_all_processes()          iterate /proc, call check_process per PID
  ├── check_process(pid)
  │     ├── get_exe_path()          readlink /proc/pid/exe
  │     ├── parse_maps_line()       read /proc/pid/maps line by line
  │     │     └── find base addr    first r-xp region matching exe path
  │     └── elf_header_mismatch()   open exe + /proc/pid/mem, compare headers
  └── monitor_process(pid)         ptrace-based live syscall monitor
```

---

## Why /proc/pid/mem for reading process memory

`/proc/<pid>/mem` gives direct byte-level access to any region of a process's
address space.  We `lseek()` to the base address found in `/proc/<pid>/maps`
and `read()` the first 64 bytes (the ELF header).  This works as root without
disturbing the process (no stops, no signals).

---

## False positive considerations

- **JVM / Node.js / LuaJIT** — JIT compilers create anonymous executable regions
  by design.  The detector will flag these.  A production version would maintain
  a whitelist of known-JIT processes.

- **VDSO** — The kernel maps `[vdso]` with execute permission but it has a
  bracketed name, not an empty path, so `is_anon` stays 0 and it is not flagged.

- **Entry point ASLR** — PIE binaries load at a randomised base, so the entry
  point field in the ELF header is a relative offset.  We only compare the
  identity bytes, type, and machine — fields that are constant regardless of
  load address.

---

## Limitations (known)

- ptrace monitor is single-threaded only (toggle approach for entry/exit stops).
- Does not scan kernel threads (they have no `/proc/<pid>/exe`).
- Detection is based on the current memory state, not on history.
  An attacker who finishes hollowing before the scan runs will not be caught
  by the static scan (but would be caught by the monitor mode).
