# Research Notes

## Process Hollowing — Background

Process hollowing (also called "process replacement") is a code injection
technique first documented in the Windows world but applicable to any OS with
a process model that separates the process container from its memory image.

### How it works (Linux variant)

1. A legitimate process is launched (e.g. `/bin/bash`).
2. The attacker allocates new anonymous memory with `mmap(PROT_READ|PROT_WRITE)`.
3. Malicious shellcode or a full ELF is written into that region with `write()`
   or `ptrace(PTRACE_POKEDATA)`.
4. The region is made executable with `mprotect(PROT_READ|PROT_EXEC)`.
5. Execution is redirected (e.g. via a fake return address, overwriting the
   original entry point, or a direct `jump`).

The result: `ps`, `top`, `/proc/<pid>/cmdline` all show the original binary
name, but the code actually running is completely different.

---

## Detection signals used in this project

| Signal | Source | Reliability |
|--------|--------|-------------|
| ELF magic/type mismatch | `/proc/<pid>/mem` vs disk | High |
| Anonymous executable region | `/proc/<pid>/maps` | Medium-High |
| `mprotect(PROT_EXEC)` on anon region | ptrace syscall monitor | High |
| `mmap(PROT_EXEC)` | ptrace syscall monitor | Medium |

---

## Key references

- Robert Love, *Linux Kernel Development* (3rd ed.) — Chapter on memory management
- Michael Kerrisk, *The Linux Programming Interface* — Chapters 23 (ptrace), 48 (/proc)
- Tool Calmness CTF writeup on process injection (2022) — practical Linux hollowing
- `man 5 proc` — `/proc/<pid>/maps` format documentation
- `man 2 ptrace` — PTRACE_SYSCALL, PTRACE_GETREGS semantics
- ELF-64 Object File Format spec (SCO, v1.5) — e_ident layout
- Volatility Foundation: memory forensics and process reconstruction

---

## Related tools

| Tool | What it does | Relevance |
|------|-------------|-----------|
| `strace` | traces syscalls for one process | reference for ptrace use |
| `gdb` | attaches with ptrace, reads memory | same mechanism as this tool |
| YARA | pattern matching on memory regions | alternative detection approach |
| `pmap` | pretty-prints `/proc/<pid>/maps` | same data source |
