# Network Packet Analyzer & Real-Time Traffic Monitor
> **A Modern C++17 Systems Programming Project**  
> *Inspired by the core concepts of 'nload' (Copyright © Roland Riegel), A clean, educational, high-performance systems tool.*

---

## 📌 Project Overview

This project is a lightweight, real-time network packet and traffic monitor written in modern **C++17**. It extracts low-level networking telemetry from the Linux kernel Virtual Filesystem (`/proc/net/dev`), computes dynamic data throughput rates and moving averages, corrects for hardware counter overflows, and displays an interactive live dashboard with ASCII bandwidth graphs in the console.

### Key Highlights for Systems Programming Coursework
* **Modern C++17 Standards**: Uses `std::string_view`, `<charconv>` (`std::from_chars`), `std::optional`, `std::unique_ptr`, and `std::chrono`.
* **Zero-Copy Parsing**: Kernel `/proc/net/dev` lines are sliced and parsed without dynamic heap allocations or string copying.
* **$O(1)$ Sliding Window**: Traffic statistics use `std::deque` for constant-time window pruning rather than $O(N)$ vector shifts.
* **Hardware Rollover Compensation**: Corrects 32-bit driver counter wraparounds on high-speed gigabit interfaces.
* **Lightweight & Portable**: Operates via standard ANSI terminal sequences without requiring complex curses/ncurses dependencies.

---

## 📂 Project Architecture

```
Network-packet-analyzer/
├── Makefile                # One-command build and test tool
├── CMakeLists.txt          # Modern CMake 3.15+ build configuration
├── README.md               # Architecture documentation & student guide
├── src/
│   ├── main.cpp            # Entry point: CLI parsing, signal handling & sampling loop
│   ├── proc_parser.hpp     # Zero-copy /proc/net/dev parser header & systems documentation
│   ├── proc_parser.cpp     # Parser implementation using std::from_chars
│   ├── network_device.hpp  # Device model & 32-bit hardware rollover handling
│   ├── network_device.cpp  # Device telemetry update coordination
│   ├── traffic_stats.hpp   # Real-time throughput, moving averages & deque sliding window
│   ├── traffic_stats.cpp   # Rate calculation math & unit formatting (Mbit/s, MB)
│   ├── terminal_view.hpp   # Terminal dashboard & ASCII visual graph generator
│   └── terminal_view.cpp   # ANSI escape code layout renderer
└── tests/
    └── test_analyzer.cpp   # Unit tests for parser, rollover fix, and rate calculation
```

---

## 🧠 Systems Programming Concepts Explained

### 1. How Kernel Network Data Extraction Works
* **What is `/proc`?**  
  The Linux `/proc` directory is a virtual pseudo-filesystem synthesized in RAM by the kernel's Virtual Filesystem (VFS) switch. It does not exist on disk.
* **Kernel Origin (`net/core/net-procfs.c`)**:  
  When user-space reads `/proc/net/dev`, the kernel triggers `dev_seq_show()`. It iterates through all active network devices via `for_each_netdev_rcu()` and extracts `struct rtnl_link_stats64` from the network card driver.
* **The 16 Telemetry Columns**:
  * **Receive (Rx)**: `bytes`, `packets`, `errs` (CRC errors), `drop` (buffer exhaustion), `fifo` (DMA overrun), `frame` (framing errors), `compressed`, `multicast`.
  * **Transmit (Tx)**: `bytes`, `packets`, `errs`, `drop` (queue full), `fifo` (DMA underrun), `colls` (Ethernet collisions), `carrier` (loss of carrier signal), `compressed`.

### 2. 32-Bit Counter Rollover & Overflow Compensation
* On 32-bit systems or legacy network drivers, hardware counters are stored as 32-bit integers ($2^{32} - 1 \approx 4.29 \text{ GB}$).
* On a saturated **1 Gbps link**, the byte counter wraps from 4,294,967,295 back to 0 every **~34 seconds**! (On a 10 Gbps link, every ~3.4 seconds).
* **The Solution**:  
  `NetworkDevice::fixCounterOverflow()` detects when `current < previous` and accumulates $+2^{32}$ (`0x100000000ULL`) into the upper 32 bits, ensuring continuous monotonic rate calculations.

### 3. Zero-Allocation String Parsing
* Traditional code uses `std::string::substr()` and `std::stringstream`, which allocate heap memory on every token.
* This project parses lines using `std::string_view` (16-byte `(pointer, length)` pairs) and parses integers directly into registers using `std::from_chars`.

---

## 🚀 Building & Running

### Option 1: Using Make (Simplest)
```bash
# Build the application
make

# Run the analyzer
./network-analyzer

# Run on a specific interface with custom interval (e.g. eth0 at 250ms)
./network-analyzer -i eth0 -t 250

# Run automated unit tests
make test

# Clean build artifacts
make clean
```

*(On Windows with MinGW, run `mingw32-make` and `mingw32-make test`)*

### Option 2: Using CMake
```bash
mkdir build && cd build
cmake ..
cmake --build .
ctest --output-on-failure
```

---

## 🖥️ Command-Line Options

```
Usage: ./network-analyzer [options]

Options:
  -i, --interface <name>   Network interface to monitor (e.g. eth0, wlan0, lo)
  -t, --interval <ms>      Sampling interval in milliseconds (default: 500)
  -s, --simulate           Simulate dynamic network traffic (for non-Linux demo)
  -l, --list               List all auto-detected interfaces and exit
  -h, --help               Display help information
```

---
## 📚 Learning Project

This repository contains a minimal, modern C++17 implementation of a network packet analyzer. 
It demonstrates:
- Zero‑copy parsing of `/proc/net/dev` using `std::string_view` and `std::from_chars`.
- Handling of 32‑bit counter rollovers.
- Real‑time throughput calculations with sliding‑window averages.
- Portable ANSI‑escape‑based terminal UI.

The project is intentionally lightweight and contains no external dependencies beyond the C++ standard library.

### Credits

* Inspired by the original **nload** tool by Roland Riegel (feedback@roland-riegel.de).
