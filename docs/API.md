# Function Reference

All functions are defined in `detector.c`.  There is no public header; this
document serves as the internal API reference for the thesis.

---

## Structs

### `struct mem_region`
One memory mapping parsed from `/proc/<pid>/maps`.

| Field | Type | Description |
|-------|------|-------------|
| `start` | `unsigned long` | region start virtual address |
| `end`   | `unsigned long` | region end virtual address |
| `perms` | `char[8]` | permission string e.g. `r-xp` |
| `path`  | `char[512]` | backing file path, or empty if anonymous |
| `is_exec` | `int` | 1 if the `x` bit is set |
| `is_anon` | `int` | 1 if `path` is empty (no backing file) |

### `struct scan_result`
Output of scanning one process.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | `pid_t` | process ID |
| `exe` | `char[512]` | resolved path from `/proc/<pid>/exe` |
| `anon_exec_count` | `int` | number of anonymous executable regions found |
| `elf_mismatch` | `int` | 1 if disk vs memory ELF header differ |
| `suspicious` | `int` | 1 if any indicator is set |

---

## Functions

### `get_exe_path(pid, buf, n)`
Resolves `/proc/<pid>/exe` via `readlink`.  
Returns 0 on success, -1 on failure.

### `parse_maps_line(line, region)`
Parses one text line from `/proc/<pid>/maps` into a `mem_region`.  
Returns 0 on success, -1 if the line could not be parsed.

### `elf_header_mismatch(pid, exe_path, base_addr)`
Opens `exe_path` and `/proc/<pid>/mem`.  Reads an `Elf64_Ehdr` from each
and compares `e_ident`, `e_type`, and `e_machine`.  
Returns 1 if a mismatch is detected, 0 if clean or unreadable.

### `check_process(pid, result)`
Full scan of one process: resolves exe, parses maps, calls
`elf_header_mismatch`.  Fills `result`.  
Returns 0 on success, -1 if `/proc/<pid>/maps` cannot be opened (process
likely exited between the directory listing and the read).

### `scan_all_processes()`
Iterates `/proc`, calls `check_process` for every numeric directory,
and prints/logs findings.

### `monitor_process(pid)`
Attaches to `pid` with `PTRACE_ATTACH` and watches for
`mmap(PROT_EXEC)` and `mprotect(PROT_EXEC)` syscalls until the process
exits or the user sends SIGINT.

### `log_event(result, severity, msg)`
Prints a formatted log line to stdout and, if `--report` was given,
appends a JSON object to the report file.
