# Process Hollowing Detection System

**Optimized Real-time Monitor for Linux Process Integrity**

*Master's Thesis Project - Informatics & Cybersecurity*

---

## 📋 Project Overview

### Problem Statement

Process hollowing is a sophisticated code injection technique used by advanced malware and adversaries to execute arbitrary code while evading traditional security detection mechanisms. The attack works by:

1. Creating or spawning a legitimate process in a suspended state
2. Replacing the process memory image with malicious code
3. Resuming execution while maintaining the legitimate process context

This technique is particularly dangerous because:
- **Low signature footprint** – the process name and arguments appear legitimate
- **Kernel-level evasion** – security tools see legitimate process metadata
- **Memory obfuscation** – the actual loaded code differs from the on-disk binary
- **Minimal audit trail** – traditional logging may not detect the substitution

### Research Objective

Develop a **lightweight, real-time detection system** for process hollowing attacks on Linux by:
- Correlating process metadata with actual memory mappings
- Detecting discrepancies between disk binaries and loaded memory
- Providing low CPU/memory overhead suitable for production environments
- Establishing a baseline for Linux process integrity monitoring

---

## 🎯 Key Features (Planned)

### Phase 1: /proc Filesystem Analysis
- [ ] Parse `/proc/[pid]/maps` for memory region analysis
- [ ] Compare executable on disk vs. memory-mapped image
- [ ] Detect unsigned or mismatched code regions
- [ ] Generate baseline of legitimate processes

### Phase 2: Real-time Monitoring with ptrace
- [ ] Attach ptrace handlers to process creation
- [ ] Monitor `mmap()` and `execve()` syscalls
- [ ] Capture memory changes in real-time
- [ ] Log suspicious process transformations

### Phase 3: Optimization & Performance
- [ ] Implement inotify-based selective scanning
- [ ] Reduce overhead through sampling strategies
- [ ] Optimize for multi-core systems
- [ ] Benchmark against system baselines

### Phase 4: Reporting & Validation
- [ ] Generate forensic reports for detected incidents
- [ ] Validate against known process hollowing samples
- [ ] Performance comparison with existing tools
- [ ] Documentation and academic publication

---

## 📚 Technical Approach

### Detection Methods

#### 1. **Memory Mapping Analysis**
```
/proc/[pid]/maps contains all memory regions for a process.
We verify that:
  - Executable region hash matches on-disk binary
  - No unexpected code injection markers present
  - Memory protections align with expected values
```

#### 2. **Process Binary Verification**
```
/proc/[pid]/exe points to the original executable.
We compare:
  - File headers (ELF magic, sections)
  - Loaded segment checksums
  - Entry point alignment
  - Symbol table consistency
```

#### 3. **System Call Monitoring**
```
ptrace() intercepts syscalls:
  - execve() – process loading
  - mmap()/mprotect() – memory modifications
  - write() – suspicious code writes
```

### System Architecture

```
┌─────────────────────────────────────────────────┐
│     Detector Application                        │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────┐  ┌──────────────┐             │
│  │ /proc Scanner│  │ ptrace Monitor│            │
│  └──────────────┘  └──────────────┘             │
│        │                 │                      │
│        └────────┬────────┘                      │
│               Analysis                          │
│                 │                               │
│        ┌────────▼─────────┐                     │
│        │  Threat Detection │                    │
│        │  & Classification │                    │
│        └────────┬──────────┘                    │
│               │                                 │
│        ┌──────▼──────────┐                      │
│        │ Logging & Alerts│                      │
│        └─────────────────┘                      │
└─────────────────────────────────────────────────┘
```

---

## 🛠 Building & Usage

### Requirements

- **OS:** Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **Compiler:** GCC 9.0+ or Clang 10.0+
- **Tools:** `make`, `gcc`, standard C library
- **Privileges:** Root or CAP_SYS_PTRACE + CAP_SYS_ADMIN for monitoring

### Compilation

```bash
# Clone repository
git clone https://github.com/yourusername/process-hollowing-detector.git
cd process-hollowing-detector

# Build
make

# Optional: build with debug symbols
make DEBUG=1

# Clean compiled artifacts
make clean
```

### Running the Detector

```bash
# Basic scan
sudo ./detector

# Scan with verbose output
sudo ./detector -v

# Monitor specific process
sudo ./detector -p <PID>

# Continuous monitoring mode (future)
sudo ./detector --monitor

# Generate report
sudo ./detector --report output.json
```

---

## 📊 Expected Results & Metrics

### Detection Accuracy
- **True Positive Rate (TPR):** Target > 95% on known process hollowing samples
- **False Positive Rate (FPR):** Target < 2% on standard system processes
- **Detection Latency:** < 100ms from attack execution

### Performance Overhead
- **CPU Usage:** < 2% during baseline scan
- **Memory Footprint:** < 50MB resident set
- **I/O Impact:** Minimal (buffered reads only)

### Comparative Analysis
Benchmarked against:
- YARA rules for process memory scanning
- Traditional ptrace-based monitors
- Commercial EDR baseline detection

---

## 📁 Project Structure

```
process-hollowing-detector/
├── detector.c              # Main application
├── Makefile               # Build configuration
├── README.md             # This file
├── .gitignore            # Git exclusions
├── docs/
│   ├── DESIGN.md         # Detailed design document
│   ├── RESEARCH.md       # Literature & references
│   └── API.md            # Function documentation
├── tests/
│   ├── test_samples/     # Known process hollowing samples
│   └── test_runner.sh    # Test harness
├── reports/
│   └── thesis_draft.md   # Academic thesis framework
└── assets/
    └── architecture.png  # System diagram
```

---

## 🔬 Related Work & References

### Key Research Areas
- **Code Injection Techniques:** DLL injection, Code Caves, Process Hollowing
- **Windows Security:** [Paper] "Advanced Code Injection Techniques"
- **Linux Process Model:** Linux kernel scheduling, memory management
- **Memory Forensics:** Volatility framework, memory image analysis

### Existing Tools
- `ptrace` – Linux process tracing (POSIX)
- `strace` – System call monitor (baseline)
- `gdb` – Debugger-based analysis (reference)
- YARA – Pattern matching for memory scanning

---

## 📝 Development Timeline

| Phase | Duration | Deliverables | Status |
|-------|----------|--------------|--------|
| P1: Foundation | Week 1-2 | /proc parser, basic scanner | ⏳ In Progress |
| P2: Real-time | Week 3-4 | ptrace integration, syscall hooks | 📋 Planned |
| P3: Optimization | Week 5-6 | Performance tuning, sampling | 📋 Planned |
| P4: Validation | Week 7-8 | Testing, benchmarks, report | 📋 Planned |

---

## 📚 Thesis Components

This project serves as the implementation backbone for:

1. **Literature Review** – Process injection techniques and detection
2. **Methodology** – Hybrid approach: static + dynamic analysis
3. **Implementation** – Actual working detector system
4. **Evaluation** – Performance metrics and accuracy testing
5. **Conclusion** – Contributions to Linux security monitoring

The final report will include:
- Complete source code (in appendix)
- Benchmark results and graphs
- Proof-of-concept attacks detected
- Recommendations for production deployment

---

## 👤 Author Information

**Student Name:** [Your Name]  
**Program:** Master's in [Informatics/Cybersecurity]  
**University:** [Your University]  
**Date:** January 2024  
**Advisor:** [Professor Name]

---

## 📄 License

This project is provided for educational and research purposes. All source code is available under the MIT License.

---

## 🤝 Contributing

This is an active thesis project. For contributions or suggestions:
1. Create an issue with your proposal
2. Fork and submit a pull request
3. Ensure all code follows the style guide

---

## 🔗 Quick Links

- **Full Documentation:** `/docs`
- **Build Guide:** `Makefile` and section above
- **Testing:** `/tests`
- **Thesis Framework:** `/reports/thesis_draft.md`

---

**Status:** 🟡 In Active Development (Phase 1: Foundation)

Last Updated: January 2024
# hollow-processors-
