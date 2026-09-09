# IDA-certiBridge — Technical Details & Reference

Comprehensive documentation, full feature list, CLI command references, and architecture details for IDA-certiBridge.

---

## Features

- **Live Session Diary (`DIARY.md`)**: Automatically populated with active binary name, image base, architecture, Hex-Rays readiness, and bound port whenever an IDB is opened or analyzed.
  > **Note on Diary Location:** The active `DIARY.md` (and `diary.json`) is generated inside your IDA **plugins directory** (e.g. `<plugins>/certibridge/DIARY.md` or alongside the opened `.i64` database), **not** in this repository root.
- **Zero Hardcoded Paths**: Dynamic path resolution across all components. Works seamlessly with portable IDAs, standard installs, and environment variables (`IDAUSR`, `IDA_DIR`, `APPDATA`).
- **Universal Zero-Boilerplate CLI (`cb.py`)**: Instant command execution for all bridge operations with auto-discovered active ports and hot-reload.
- **Clean Decompilation**: Fast, high-signal function decompilation API via `ida_hexrays` with zero bloat.
- **Signature Engine (SigMaker Match & Surpass)**: Generates the shortest 100% unique wildcard pattern for any function or address. Solves small/common stubs via deep scanning, caller Xref context, boundary extension, and data references.
- **Advanced Reverse Engineering Commands**:
  - **RTTI Class & VTable Discovery (`find_class`, `class`)**: Search classes by name across `.data`/`.rdata`, resolve `TypeDescriptor`, `RTTICompleteObjectLocator`, VTable pointers, base class hierarchies, and virtual method lists.
  - **Fuzzy Function Hashing & Patch Diffing (`func_hash`, `func_diff`)**: In-process C++ Trend Micro TLSH 70-character locality sensitive hashing. Compute function digests and calculate patch similarity distance (0 = identical, < 30 = patch variant).
  - **Auto-Analysis Gating (`auto_wait`)**: Synchronizes with IDA's background auto-analysis engine (`auto_is_ok`) with configurable timeout.
  - **VTable Recovery**: Inspect virtual tables, resolve method pointers, and generate C++ struct definitions (`vtable`, `find_vtables`).
  - **RTTI Reconstruction**: Parse MSVC 64-bit `RTTICompleteObjectLocator` descriptors to recover class names and inheritance hierarchies (`rtti`).
  - **Pattern Scanning**: Search IDA wildcard byte patterns across memory segments with optional RIP displacement evaluation (`find`).
  - **Memory Inspection & Mnemonic Patching**: Read raw bytes/disassembly and apply safe database patches with raw hex or live x86/x64 assembly mnemonics (`bytes`, `patch`).
  - **Call Graph & CFG**: Trace callers/callees with runtime thunk filtering and extract basic block control-flow graphs (`callers`, `callees`, `cfg`).
- **Vendored C++ Engine Submodules (`src/vendor`)**:
  - `httplib`, `json` (nlohmann), `tomlplusplus`, `spdlog`
  - `simdjson`: Ultra-fast JSON parsing for large symbol/xref dumps
  - `miniz`: Single-source compression for memory dumps and diary snapshots
  - `zydis`: High-speed x86/x64 instruction decoding and analysis
  - `asmjit`: Complete x86/x64 JIT assembler for hook trampolines and shellcode
  - `tlsh`: Trend Micro Locality Sensitive Hashing for fuzzy function matching and binary diffing
- **Rust Runner (`tools/runner`)**: Dedicated build and shipping utility (`cargo xtask`).

---

## Quick Start (30-Second Setup)

### 1. Clone with Submodules
```bash
git clone --recurse-submodules https://github.com/hella-certified/IDA-certiBridge.git
cd IDA-certiBridge

# If cloned previously without submodules:
git submodule update --init --recursive
```

### 2. Prerequisites
- **IDA Pro**: 7.5+, 8.x, or 9.x (standard install or portable) with Hex-Rays decompiler.
- **Compiler**: Visual Studio 2022 (MSVC C++20) & CMake 3.20+.
- **Rust Toolchain**: `cargo` (for the xtask runner).
- **Python**: 3.9+.

### 3. Build & Ship to IDA
Builds the C++ core engine in Release mode and delivers all IDAPython and binary components directly to your IDA plugins directory:
```bash
cargo xtask build
```
*If using a portable or custom IDA directory, specify it directly: `cargo xtask deploy "C:/path/to/ida"` (or set `portablePath` in `config.toml`).*

### 4. Open IDA Pro & Verify
1. Open any binary or database (`.i64`) in IDA Pro.
2. The IDA output console displays:
   ```
   [certiBridge] online at http://127.0.0.1:13381 for 'target.exe' (hotkey: Ctrl-Shift-R)
   ```
3. Test connectivity instantly from your terminal:
   ```bash
   python cb.py status
   ```

---

## Universal CLI Wrapper (`cb.py`)

No verbose `curl` or multi-line python urllib scripts needed. Run all commands directly via `cb.py`:

```bash
# Check status of active IDA session
python cb.py status

# Decompile function (returns raw C pseudocode directly)
python cb.py decompile WinMain --raw

# Generate unique wildcard signature for a function or address
python cb.py sig WinMain

# Scan memory for wildcard pattern
python cb.py find "48 83 EC 38 E8 ? ? ? ? E8"

# Scan memory with RIP displacement target resolution
python cb.py find "48 8D 0D ? ? ? ? E8" 3 7

# Inspect virtual method table & generate C++ struct
python cb.py vtable 0x7FF649CA9430 --count 16

# Scan data segments for candidate virtual tables
python cb.py find_vtables --seg .rdata

# Parse MSVC 64-bit RTTI descriptor
python cb.py rtti 0x7FF649CA9430

# Trace callers & callees (filters runtime thunks)
python cb.py callers WinMain
python cb.py callees WinMain

# Extract basic block control flow graph
python cb.py cfg WinMain --format mermaid

# Read memory bytes & apply database hotpatch (hex or live assembly mnemonics)
python cb.py bytes WinMain 16
python cb.py patch WinMain "90 90 90"
python cb.py patch 0x7FF64635D2B0 "mov eax, 1; ret"

# Find class by RTTI and recover VTable methods & hierarchy
python cb.py class PerspectiveCamera

# Wait for IDA background auto-analysis to finish
python cb.py auto_wait --timeout 15

# Compute TLSH fuzzy function hash & calculate patch similarity distance
python cb.py hash 0x7FF64635D2B0
python cb.py diff 0x7FF64635D2B0 0x7FF64635D690
python cb.py diff T1431101500070FDADEC95216A58123729D37F351B9E2534CADAE53415EF5D40AF5501A3 0x7FF64635D2B0

# Labeling & Renaming
python cb.py rename 0x14136B940 "Live_StartLocalReplay"
python cb.py rename_var 0x14136B940 v15 "replayContext"

# Search strings and cross-references
python cb.py strings "Failed to start"

# Hot-reload plugin mid-session
python cb.py reload
```

### Python Module Usage
`cb.py` can also be imported in any Python script:
```python
import cb

# Decompile
cCode = cb.decompile("WinMain", raw=True)

# Signature
sigData = cb.sig("WinMain")

# VTable
vtbl = cb.vtable("0x7FF649CA9430")
```

---

## Build & Ship (`cargo xtask`)

The `cargo xtask` runner is strictly scoped to building and shipping the plugin:

### 1. Build & Auto-Ship
Builds the C++ core daemon in Release mode and automatically ships all components to IDA plugins:
```bash
cargo xtask build
```

### 2. Ship Only (Deploy)
Copies the IDAPython components and C++ binaries directly into the IDA plugins folder:
```bash
cargo xtask deploy
# or specify an explicit path:
cargo xtask deploy "path/to/ida"
```

### 3. Path Configuration
Configure IDA paths interactively without manual text editing:
```bash
cargo xtask config
```

---

## Configuration

Paths are resolved dynamically without hardcoding. You can configure paths in `config.toml` (copied from `config.example.toml`, or auto-created on first run by `cargo xtask`):

```toml
[ida]
portablePath = ""
pluginsPath = ""

[bridge]
basePort = 13371
maxPort = 13390
host = "127.0.0.1"

[diary]
outputMarkdown = "DIARY.md"
outputJson = "diary.json"
```

---

## Structure

```
IDA-certiBridge/
├── assets/                     # Media & project banner
├── cb.py                       # Universal CLI & Python client wrapper
├── config.example.toml         # Clean configuration template
├── CMakeLists.txt              # CMake build for C++ core engine
├── src/
│   ├── core/                   # C++ core engine & bridge server
│   ├── py/                     # IDAPython plugin & decompiler
│   └── vendor/                 # Vendored submodules (httplib, json, tomlplusplus, spdlog, simdjson, miniz, zydis, asmjit, tlsh)
├── tools/
│   └── runner/                 # Rust build & ship runner (cargo xtask)
└── skills/
    └── ida-certibridge/        # AI agent guide (SKILL.md)
```
