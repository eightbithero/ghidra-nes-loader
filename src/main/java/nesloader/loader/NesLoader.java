package nesloader.loader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.Option;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import nesloader.format.INesHeader;
import nesloader.mapper.AxRomMapper;
import nesloader.mapper.Mapper;
import nesloader.mapper.Mmc1Mapper;
import nesloader.mapper.NromMapper;
import nesloader.mapper.UxRomMapper;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import nesloader.util.NesMemoryMap;

/**
 * Ghidra Loader for NES ROM files in iNES format (.nes).
 *
 * Responsibilities:
 *   1. Detect the iNES magic header.
 *   2. Create the NES CPU address-space layout (RAM, PPU regs, APU/IO regs).
 *   3. Delegate PRG-ROM mapping to the appropriate mapper implementation.
 *   4. Label hardware registers and interrupt vectors.
 */
public class NesLoader extends AbstractLibrarySupportLoader {

    public static final String LOADER_NAME = "NES iNES ROM Loader";

    @Override
    public String getName() {
        return LOADER_NAME;
    }

    // -------------------------------------------------------------------------
    // Detection
    // -------------------------------------------------------------------------

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> specs = new ArrayList<>();
        BinaryReader reader = new BinaryReader(provider, true /* little-endian */);
        if (INesHeader.isValid(reader)) {
            specs.add(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
        }
        return specs;
    }

    // -------------------------------------------------------------------------
    // Loading
    // -------------------------------------------------------------------------

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
                        Program program, TaskMonitor monitor, MessageLog log)
            throws IOException {

        BinaryReader reader = new BinaryReader(provider, true);
        INesHeader header;
        try {
            header = INesHeader.parse(reader);
        } catch (IOException e) {
            log.appendMsg(getName(), "Failed to parse iNES header: " + e.getMessage());
            return;
        }

        log.appendMsg(getName(), "Detected: " + header);

        try {
            monitor.setMessage("Creating NES memory map…");
            createMemoryMap(program, header, monitor, log);

            monitor.setMessage("Mapping PRG-ROM (mapper " + header.getMapperNumber() + ")…");
            Mapper mapper = getMapper(header, log);
            mapper.mapMemory(program, provider, header, monitor, log);

            monitor.setMessage("Labeling vectors and registers…");
            labelVectors(program, log);
            labelRegisters(program, log);

            // Store ROM metadata for other analyzers (e.g. CdlAnalyzer)
            program.getOptions("NES ROM")
                   .setInt("PRG ROM Size", header.getPrgRomSize());
            program.getOptions("NES ROM")
                   .setInt("Mapper", header.getMapperNumber());

        } catch (AddressOverflowException e) {
            throw new IOException("Address overflow while mapping ROM: " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Memory map
    // -------------------------------------------------------------------------

    private void createMemoryMap(Program program, INesHeader header,
                                  TaskMonitor monitor, MessageLog log) {

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        // Internal 2 KB RAM: $0000-$01FF is covered by the language-defined
        // ZERO_PAGE and STACK blocks (6502.pspec), so map only $0200-$07FF here.
        MemoryBlockUtils.createUninitializedBlock(program, false, "RAM",
            space.getAddress(NesMemoryMap.RAM_START + 0x200), NesMemoryMap.RAM_SIZE - 0x200,
            "CPU internal RAM ($0200-$07FF)", "NES Loader", true, true, false, log);

        // PPU registers ($2000-$2007)
        MemoryBlockUtils.createUninitializedBlock(program, false, "PPU_REGS",
            space.getAddress(NesMemoryMap.PPU_REG_START), NesMemoryMap.PPU_REG_SIZE,
            "PPU registers", "NES Loader", true, true, false, log);

        // APU and I/O registers ($4000-$4017)
        MemoryBlockUtils.createUninitializedBlock(program, false, "APU_IO",
            space.getAddress(NesMemoryMap.APU_IO_START), NesMemoryMap.APU_IO_SIZE,
            "APU and I/O registers", "NES Loader", true, true, false, log);

        // Optional battery-backed SRAM ($6000-$7FFF)
        if (header.hasBattery()) {
            MemoryBlockUtils.createUninitializedBlock(program, false, "SRAM",
                space.getAddress(NesMemoryMap.SRAM_START), NesMemoryMap.SRAM_SIZE,
                "Battery-backed SRAM", "NES Loader", true, true, false, log);
        }
    }

    // -------------------------------------------------------------------------
    // Symbols
    // -------------------------------------------------------------------------

    private void labelVectors(Program program, MessageLog log) {
        AddressSpace space  = program.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symbols = program.getSymbolTable();
        Memory memory       = program.getMemory();

        Map<Long, String> vectors = new LinkedHashMap<>();
        vectors.put(NesMemoryMap.VEC_NMI,     "VEC_NMI");
        vectors.put(NesMemoryMap.VEC_RESET,   "VEC_RESET");
        vectors.put(NesMemoryMap.VEC_IRQ_BRK, "VEC_IRQ_BRK");

        // Label the vector table in every space that actually maps it: the
        // default space for fixed-bank layouts, and each overlay bank whose
        // range covers it (all-switchable layouts like AxROM have no
        // default-space memory at $FFFA at all).
        for (Map.Entry<Long, String> e : vectors.entrySet()) {
            Address addr = space.getAddress(e.getKey());
            if (memory.getBlock(addr) != null) {
                createLabel(symbols, addr, e.getValue(), log);
            }
        }
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isOverlay()) continue;
            if (block.getStart().getOffset() > NesMemoryMap.VEC_NMI
                    || block.getEnd().getOffset() < NesMemoryMap.VEC_IRQ_BRK + 1) continue;
            AddressSpace ovl = block.getStart().getAddressSpace();
            for (Map.Entry<Long, String> e : vectors.entrySet()) {
                createLabel(symbols, ovl.getAddress(e.getKey()), e.getValue(), log);
            }
        }
    }

    private void labelRegisters(Program program, MessageLog log) {
        AddressSpace space  = program.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symbols = program.getSymbolTable();

        Map<Long, String> regs = new LinkedHashMap<>();
        // PPU
        regs.put(NesMemoryMap.PPUCTRL,   "PPUCTRL");
        regs.put(NesMemoryMap.PPUMASK,   "PPUMASK");
        regs.put(NesMemoryMap.PPUSTATUS, "PPUSTATUS");
        regs.put(NesMemoryMap.OAMADDR,   "OAMADDR");
        regs.put(NesMemoryMap.OAMDATA,   "OAMDATA");
        regs.put(NesMemoryMap.PPUSCROLL, "PPUSCROLL");
        regs.put(NesMemoryMap.PPUADDR,   "PPUADDR");
        regs.put(NesMemoryMap.PPUDATA,   "PPUDATA");
        // APU
        regs.put(NesMemoryMap.SQ1_VOL,    "SQ1_VOL");
        regs.put(NesMemoryMap.SQ1_SWEEP,  "SQ1_SWEEP");
        regs.put(NesMemoryMap.SQ1_LO,     "SQ1_LO");
        regs.put(NesMemoryMap.SQ1_HI,     "SQ1_HI");
        regs.put(NesMemoryMap.SQ2_VOL,    "SQ2_VOL");
        regs.put(NesMemoryMap.SQ2_SWEEP,  "SQ2_SWEEP");
        regs.put(NesMemoryMap.SQ2_LO,     "SQ2_LO");
        regs.put(NesMemoryMap.SQ2_HI,     "SQ2_HI");
        regs.put(NesMemoryMap.TRI_LINEAR, "TRI_LINEAR");
        regs.put(NesMemoryMap.TRI_LO,     "TRI_LO");
        regs.put(NesMemoryMap.TRI_HI,     "TRI_HI");
        regs.put(NesMemoryMap.NOISE_VOL,  "NOISE_VOL");
        regs.put(NesMemoryMap.NOISE_LO,   "NOISE_LO");
        regs.put(NesMemoryMap.NOISE_HI,   "NOISE_HI");
        regs.put(NesMemoryMap.DMC_FREQ,   "DMC_FREQ");
        regs.put(NesMemoryMap.DMC_RAW,    "DMC_RAW");
        regs.put(NesMemoryMap.DMC_START,  "DMC_START");
        regs.put(NesMemoryMap.DMC_LEN,    "DMC_LEN");
        regs.put(NesMemoryMap.OAM_DMA,    "OAM_DMA");
        regs.put(NesMemoryMap.APU_STATUS, "APU_STATUS");
        regs.put(NesMemoryMap.JOY1,       "JOY1");
        regs.put(NesMemoryMap.JOY2,       "JOY2");

        for (Map.Entry<Long, String> e : regs.entrySet()) {
            createLabel(symbols, space.getAddress(e.getKey()), e.getValue(), log);
        }
    }

    private void createLabel(SymbolTable symbols, Address addr, String name, MessageLog log) {
        try {
            symbols.createLabel(addr, name, SourceType.IMPORTED);
        } catch (Exception e) {
            log.appendMsg(getName(), "Cannot label " + name + ": " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Mapper factory
    // -------------------------------------------------------------------------

    private Mapper getMapper(INesHeader header, MessageLog log) {
        return switch (header.getMapperNumber()) {
            case 0 -> new NromMapper();
            case 1 -> new Mmc1Mapper();
            case 2, 71 -> new UxRomMapper(header.getMapperNumber());
            case 7 -> new AxRomMapper();
            default -> {
                log.appendMsg(getName(),
                    "Unsupported mapper " + header.getMapperNumber() + ", using NROM fallback.");
                yield new NromMapper();
            }
        };
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
                                          DomainObject domainObject, boolean isLoadIntoProgram) {
        return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
    }
}
