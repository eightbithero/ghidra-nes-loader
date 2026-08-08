This extension is used for loading ROM data to Ghidra SRE for further analysis.

## Hardware
NES - Nintendo Entertainment System / Family Computer (Famicom) / Dendy

## ENV
Ghidra SRE 11.4.2
Java 21.0.9
GHIDRA_INSTALL_DIR - /Users/lmaxim/ghidra-prog/ghidra
jdk - /Library/Java/JavaVirtualMachines/jdk-21.jdk

## Contains 
Analyzer - for automatic code analysis
Loader - for properly read input ROM format, and prepare memory and address layout
Exporter - for exporting disassembled listing for futher recompile

## ROM file formats
https://www.nesdev.org/wiki/INES

## Supported Mappers
Nintendo MMC1 https://www.nesdev.org/wiki/MMC1
UxROM https://www.nesdev.org/wiki/UxROM (ines mapper 2 + ines mapper 71)
AxROM https://www.nesdev.org/wiki/AxROM

## Adding a new bank-switching mapper
MUST follow docs/MAPPER_GUIDELINES.md. Key rules: only hardwired banks go into
the default address space; every switchable bank (including bank 0) is an
overlay block `PRG_BANK_<n>`; the switchable window is an uninitialized
`PRG_WINDOW` block when fixed code references it, or nothing at all when the
whole $8000-$FFFF switches (AxROM). Vectors, VEC_* labels and export equates
are handled generically — do not duplicate in mappers. Verify with the
headless recipe in the doc (import layout dump + ca65/ld65 round-trip must be
byte-identical).

## APU Registers
https://www.nesdev.org/wiki/APU_registers

## PPU registers
https://www.nesdev.org/wiki/PPU_registers

## 2A03 registers
https://www.nesdev.org/wiki/2A03

## Examle ROM Data Map
https://datacrystal.tcrf.net/wiki/Snake_Rattle_N_Roll/ROM_map
https://datacrystal.tcrf.net/wiki/Snake_Rattle_N_Roll/RAM_map
