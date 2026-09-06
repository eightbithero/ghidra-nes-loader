# ghidra-nes-loader

Ghidra SRE extension for reverse engineering NES / Famicom ROM files (`.nes`).

## Features

- **Loader** — reads the iNES format, builds the NES CPU address map, models the mapper's bank layout honestly (fixed banks in the default space, switchable banks as overlays), labels all hardware registers and interrupt vectors
- **NES ROM Analyzer** — resolves NMI / RESET / IRQ-BRK vectors and creates entry-point functions, both in the fixed bank and per switchable bank
- **NES CDL File Analyzer** — applies Code/Data Logger traces from an emulator to guide disassembly
- **Exporter** — exports the disassembly as a ca65 v2.18 source plus an ld65 linker script that reassemble back into a byte-identical `.nes` file

## Requirements

| Component | Version |
|-----------|---------|
| Ghidra SRE | 11.4.2 |
| Java | 21 |
| cc65 (ca65 / ld65), for reassembly only | 2.18 |

## Build

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle buildExtension
```

The extension zip is written to `dist/`.

## Install

1. In Ghidra: **File → Install Extensions**
2. Click the `+` button and select the zip from `dist/`
3. Restart Ghidra

Headless alternative: unzip the archive into
`~/Library/ghidra/ghidra_11.4.2_PUBLIC/Extensions/` (see `docs/MAPPER_GUIDELINES.md`).

## Supported Mappers

| # | Name | Fixed in default space | Switchable (overlays) |
|---|------|------------------------|-----------------------|
| 0 | NROM | whole PRG-ROM (`PRG_ROM`, or `PRG_ROM_LO`/`PRG_ROM_HI` mirror for 16 KB) | — |
| 1 | MMC1 | last 16 KB bank at `$C000` | all 16 KB banks at `$8000` |
| 2 | UxROM | last 16 KB bank at `$C000` | all 16 KB banks at `$8000` |
| 4 | MMC3 (TxROM) | last 8 KB bank at `$E000` | all 8 KB banks at `$8000` |
| 7 | AxROM | nothing | all 32 KB banks at `$8000` |
| 71 | Camerica BF9093 (UxROM clone) | last 16 KB bank at `$C000` | all 16 KB banks at `$8000` |
| other | — | NROM fallback | — |

Adding a new mapper: follow `docs/MAPPER_GUIDELINES.md`.

## Usage

### Loading a ROM

Open a `.nes` file in Ghidra — the loader is selected automatically.
The following memory map is created:

| Block | Address | Description |
|-------|---------|-------------|
| `ZERO_PAGE`, `STACK` | `$0000–$01FF` | Defined by the 6502 language spec |
| `RAM` | `$0200–$07FF` | Rest of the CPU internal 2 KB RAM |
| `PPU_REGS` | `$2000–$2007` | PPU registers |
| `APU_IO` | `$4000–$4017` | APU and I/O registers |
| `SRAM` | `$6000–$7FFF` | Battery-backed SRAM (only if the header battery flag is set) |
| `PRG_WINDOW` | mapper dependent | Uninitialized block covering the switchable window (MMC1, UxROM, MMC3). Keeps addresses valid without giving auto-analysis bytes to misinterpret |
| `PRG_BANK_<n>` (non-overlay) | `$C000` / `$E000` | Hardwired bank; interrupt vectors are readable here |
| `PRG_BANK_<n>` (overlay) | `$8000` | One overlay address space per switchable bank, including bank 0 |
| `PRG_ROM` / `PRG_ROM_LO` / `PRG_ROM_HI` | `$8000–$FFFF` | NROM only |

Bank layout principle: power-on bank state is undefined on real hardware, so no
switchable bank is ever placed in the default address space. Static references
from fixed code into the window resolve to `PRG_WINDOW` addresses instead of to
an arbitrary bank's bytes.

Hardware registers (`PPUCTRL`, `PPUDATA`, `SQ1_VOL`, `JOY1`, …) are labeled in
the default space. Vector labels `VEC_NMI`, `VEC_RESET`, `VEC_IRQ_BRK` are
placed in every space that maps `$FFFA–$FFFF`: the default space for
fixed-bank mappers and each overlay bank whose range covers the table (AxROM).

ROM metadata is stored in the program options under **NES ROM**
(`PRG ROM Size`, `Mapper`) for use by the analyzers and the exporter.

### NES ROM Analyzer

Enabled by default. Creates `RESET`, `NMI_Handler`, `IRQ_Handler` functions
from the vector table in the default space. For every overlay bank that
covers `$FFFA–$FFFF` it additionally creates per-bank handlers
`RESET_BANK<n>`, `NMI_Handler_BANK<n>`, `IRQ_Handler_BANK<n>` inside that
bank's overlay space. A vector that points into `PRG_WINDOW` gets a label and
an entry point but no function, since the handler is bank-dependent.

### CDL Analysis

CDL (Code/Data Logger) files are produced by emulators such as [FCEUX](https://fceux.com) or [Mesen](https://www.mesen.ca) and record which bytes were executed as code and which were read as data.

1. Run a gameplay session in the emulator with CDL logging enabled
2. In Ghidra: **Analysis → Auto Analyze → NES CDL File Analyzer** (disabled by default)
3. Set the **CDL File Path** option to the `.cdl` file
4. Run analysis

The CDL file size must exactly match the PRG-ROM size. Bank `PRG_BANK_<n>`
maps to the file offset `n × bank size`, so hints are applied to every overlay
bank, not only to the fixed one.

### Exporting

**File → Export Program → NES ca65 Assembly** generates two files side-by-side:

| File | Description |
|------|-------------|
| `<name>.asm` | ca65 v2.18 assembly source with build instructions in the header comment |
| `<name>.cfg` | ld65 linker script generated automatically for the ROM's mapper layout |

#### Options

| Option | Description |
|--------|-------------|
| **Source .nes file (for CHR-ROM)** | Path to the original `.nes` file. When set, the original 16-byte header and CHR-ROM data are read and embedded in the `HEADER` / `CHARS` segments. If omitted, a placeholder comment with `.incbin` instructions is written instead. |

#### Reassembly

Build instructions are included at the top of the `.asm` file as a comment. In short:

```bash
ca65 --cpu 6502 -o <name>.o <name>.asm
ld65 -C <name>.cfg -o <name>.nes <name>.o
```

Requirements: **ca65 v2.18** and **ld65 v2.18** from the [cc65 toolchain](https://cc65.github.io).
The rebuilt ROM is byte-identical to the original (verified with `cmp` on the reference ROMs listed in `docs/MAPPER_GUIDELINES.md`).

#### Segment layout

| Segment | Content |
|---------|---------|
| `ZEROPAGE` | `$0000–$00FF` — Ghidra symbols exported as `.res` reservations (`.exportzp`) |
| `STACK` | `$0100–$01FF` — stack page, also laid out with `.res` (games use part of it as work RAM) |
| `BSS` | `$0200–$07FF` — internal RAM variables |
| `SRAM` | `$6000–$7FFF` — battery-backed SRAM variables (if present) |
| `HEADER` | 16-byte iNES header |
| `PRG_ROM` / `PRG_BANK_<n>` | PRG-ROM code and data (one segment per initialized memory block) |
| `CHARS` | CHR-ROM pattern table data |

Output order of PRG segments reproduces the original file order: fixed blocks
below `$C000`, then overlay banks by number, then fixed blocks at `$C000+`.

#### What the exporter does with the code

- Hardware register addresses are replaced with equates (`PPUCTRL`, `PPUDATA`, `JOY1`, …); `VEC_NMI`/`VEC_RESET`/`VEC_IRQ` are emitted as equates too
- References to labeled RAM / zero-page / SRAM addresses use the symbol name
- Absolute-mode instructions targeting addresses below `$0100` get the `a:` prefix so ca65 does not shrink them to zero-page form and shift the code
- Ghidra comments (EOL, PRE, POST, PLATE, REPEATABLE) are exported as `;` comments
- Symbols inside `PRG_WINDOW` and synthetic flow targets pointing there are emitted as `name := $addr` equates, because the window has no bytes
- `PRG_WINDOW` itself is excluded from the `.cfg` (a fill region would inject phantom bytes into the rebuilt ROM)
- Overlay banks are emitted as raw `.byte` sequences; only non-overlay blocks are exported as disassembly

## Project layout

```
src/main/java/nesloader/
├── loader/NesLoader.java          # iNES detection, memory map, register/vector labels, mapper factory
├── analyzer/NesAnalyzer.java      # vector resolution (default space + per overlay bank)
├── analyzer/CdlAnalyzer.java      # CDL hints → disassembly/data
├── exporter/NesExporter.java      # ca65 .asm + ld65 .cfg export
├── exporter/FileChooserOption.java# custom file-picker exporter option
├── format/INesHeader.java         # iNES header parser
├── format/CdlFile.java            # CDL flag parser
├── mapper/Mapper.java             # mapper strategy interface
├── mapper/{Nrom,Mmc1,UxRom,Mmc3,AxRom}Mapper.java
└── util/NesMemoryMap.java         # hardware register / vector constants
docs/MAPPER_GUIDELINES.md          # rules + headless verification recipe for new mappers
```

## References

- [NES Dev Wiki — iNES format](https://www.nesdev.org/wiki/INES)
- [PPU registers](https://www.nesdev.org/wiki/PPU_registers)
- [APU registers](https://www.nesdev.org/wiki/APU_registers)
- [2A03 CPU](https://www.nesdev.org/wiki/2A03)
- [NROM](https://www.nesdev.org/wiki/NROM) · [MMC1](https://www.nesdev.org/wiki/MMC1) · [UxROM](https://www.nesdev.org/wiki/UxROM) · [Mapper 71](https://www.nesdev.org/wiki/INES_Mapper_071) · [MMC3](https://www.nesdev.org/wiki/MMC3) · [AxROM](https://www.nesdev.org/wiki/AxROM)
