# ghidra-nes-loader

Ghidra SRE extension for reverse engineering NES ROM files (`.nes`).

## Features

- **Loader** — reads iNES format, builds the full NES CPU address map, labels all hardware registers
- **NES Analyzer** — resolves NMI / RESET / IRQ-BRK interrupt vectors and creates entry-point functions
- **CDL Analyzer** — applies Code/Data Logger traces from an emulator to guide disassembly
- **Exporter** — dumps the disassembled listing as a `.asm` file (ca65 compatible)

## Requirements

| Component | Version |
|-----------|---------|
| Ghidra SRE | 11.4.2 |
| Java | 21 |

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

## Usage

### Loading a ROM

Open a `.nes` file in Ghidra — the loader is selected automatically.
The following memory map is created:

| Block | Address | Description |
|-------|---------|-------------|
| `RAM` | `$0000–$07FF` | CPU internal RAM (2 KB) |
| `PPU_REGS` | `$2000–$2007` | PPU registers |
| `APU_IO` | `$4000–$4017` | APU and I/O registers |
| `SRAM` | `$6000–$7FFF` | Battery-backed SRAM (if present) |
| `PRG_ROM` / `PRG_BANK_*` | `$8000–$FFFF` | PRG-ROM (mapper dependent) |

Hardware registers (PPU, APU, controllers) and interrupt vectors (`VEC_NMI`, `VEC_RESET`, `VEC_IRQ_BRK`) are labeled automatically.

### CDL Analysis

CDL (Code/Data Logger) files are produced by emulators such as [FCEUX](https://fceux.com) or [Mesen](https://www.mesen.ca) and record which bytes were executed as code and which were read as data.

1. Run a gameplay session in the emulator with CDL logging enabled
2. In Ghidra: **Analysis → Auto Analyze → NES CDL File Analyzer**
3. Set the **CDL File Path** option to the `.cdl` file
4. Run analysis

The CDL file size must exactly match the PRG-ROM size.

### Exporting

**File → Export Program → NES Assembly Listing** produces a `.asm` file with labels and disassembled instructions.

## Supported Mappers

| # | Name | Status |
|---|------|--------|
| 0 | NROM | supported |
| 1 | MMC1 | supported (all banks mapped as overlays) |
| other | — | fallback to NROM layout |

## CPU Memory Map Reference

- [NES Dev Wiki — iNES format](https://www.nesdev.org/wiki/INES)
- [PPU registers](https://www.nesdev.org/wiki/PPU_registers)
- [APU registers](https://www.nesdev.org/wiki/APU_registers)
- [2A03 CPU](https://www.nesdev.org/wiki/2A03)
- [MMC1](https://www.nesdev.org/wiki/MMC1)
