---
name: ida-certibridge
description: >-
  Inspect active IDA Pro sessions, read open binary dump metadata from the live AI Diary,
  query clean function decompilation, search strings/xrefs, label functions/variables,
  generate unique wildcard signatures, and inspect vtables via IDA-certiBridge.
---

# IDA-certiBridge AI Guide

Control and inspect active IDA Pro instances with zero bloat using the `cb.py` universal CLI wrapper.

## 1. Quick Bridge Commands (`cb.py`)

Always use `python cb.py <command>` from the project root. It auto-discovers the active IDA port automatically (no hardcoded paths or ports needed):

```bash
# Check status of active IDA session & target binary
python cb.py status

# Query clean C pseudocode decompilation (cached by default; pass --dirty to re-analyze; --timeout for big functions)
python cb.py decompile 0x14136B940 --raw
python cb.py decompile PlayerCmd_EnableHealthShield --raw --timeout 180

# Generate 100% unique wildcard signature (auto resolves small/common stubs via deep & xref analysis)
python cb.py sig 0x14136B940
python cb.py sig WinMain

# Scan memory for wildcard byte pattern
python cb.py find "48 89 5C 24 ? 48 83 EC ?"

# Scan with automatic RIP-relative displacement resolution
python cb.py find "48 8D 0D ? ? ? ? E8" 3 7

# Inspect virtual method table & generate C++ struct
python cb.py vtable 0x7FF649CA9430 --count 16

# Scan data segments for candidate virtual tables
python cb.py find_vtables --seg .rdata

# Parse MSVC 64-bit RTTI descriptor
python cb.py rtti 0x7FF649CA9430

# Trace callers & callees (filters compiler runtime thunks)
python cb.py callers 0x14136B940
python cb.py callees 0x14136B940

# Extract basic block control flow graph (Mermaid or JSON)
python cb.py cfg 0x14136B940 --format mermaid

# Find class by RTTI and recover VTable methods & inheritance hierarchy
python cb.py class PerspectiveCamera
python cb.py class Camera --limit 5

# Wait for IDA background auto-analysis to finish
python cb.py auto_wait --timeout 30

# Compute TLSH fuzzy function hash & calculate patch similarity distance
python cb.py hash 0x7FF64635D2B0
python cb.py diff 0x7FF64635D2B0 0x7FF64635D690
python cb.py diff T1431101500070FDADEC95216A58123729D37F351B9E2534CADAE53415EF5D40AF5501A3 0x7FF64635D2B0

# Read raw memory bytes & hex dump
python cb.py bytes 0x14136B940 32

# Apply database hotpatch (hex or live assembly mnemonics)
python cb.py patch 0x14136B940 "90 90 90"
python cb.py patch 0x14136B940 "mov eax, 1; ret"

# Labeling & Renaming
python cb.py rename 0x14136B940 "Live_StartLocalReplay"
python cb.py rename_var 0x14136B940 v15 "replayContext"

# Search or generate string lists (deadline protected, capped xrefs)
python cb.py strings "Failed to start" --limit 20
python cb.py strings --limit 50 --timeout 60

# Hot-reload plugin mid-session
python cb.py reload
```

## 2. The Live AI Diary

Whenever an IDB is opened or auto-analysis completes, the bridge writes active dump metadata to `DIARY.md` directly inside the IDA **plugins directory** (or next to the opened `.i64` database), **not** in this repository root.

Query `python cb.py status` or read the diary to obtain:
- Target binary filename & IDB path
- Bound instance port (e.g. `13381`, `13382` for multiple dumps)
- Image base address (`0x...`)
- Architecture (`x86_64` / `x86`)
- Hex-Rays readiness & analysis status

## 3. Python Module Usage

If working inside a Python script:
```python
import cb

# Decompile
cCode = cb.decompile("WinMain", raw=True)

# Generate unique signature
sigData = cb.sig("WinMain")
# sigData['pattern'] -> IDA format ("48 83 EC 38 E8 ? ? ? ? E8 ? ? ? ?")
# sigData['rip']     -> {'rip_offset': 1, 'disp_len': 4, 'insn_len': 5, 'disp32': 87}

# VTable
vtbl = cb.vtable("0x7FF649CA9430")
```

## 4. Shipped Console Helpers (Inside IDA)

Within the IDAPython console inside IDA Pro, the `certibridge` module exposes all commands directly:
```python
import certibridge

certibridge.decompile(0x14136B940)
certibridge.makeSig(0x14136B940)
certibridge.findPattern("48 89 5C 24 ? 48 83 EC")
certibridge.vtable(0x7FF649CA9430)
certibridge.callers(0x14136B940)
certibridge.reload()
```

## 5. Builder & Delivery Runner (cargo xtask)

The Rust xtask runner is strictly scoped to building and shipping the plugin:
- `cargo xtask build`: Compiles the C++ core daemon in Release mode and automatically ships to IDA plugins.
- `cargo xtask deploy`: Ships IDAPython components and C++ daemon to IDA plugins directory.
- Dynamic path discovery: checks environment variables (`IDAUSR`, `IDA_DIR`, `APPDATA`) and `config.toml`, prompting only if no plugins directory is found.
