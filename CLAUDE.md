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

## APU Registers
https://www.nesdev.org/wiki/APU_registers

## PPU registers
https://www.nesdev.org/wiki/PPU_registers

## 2A03 registers
https://www.nesdev.org/wiki/2A03

## Examle ROM Data Map
https://datacrystal.tcrf.net/wiki/Snake_Rattle_N_Roll/ROM_map
https://datacrystal.tcrf.net/wiki/Snake_Rattle_N_Roll/RAM_map
