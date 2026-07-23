package nesloader.exporter;

import java.io.*;
import java.util.*;
import java.util.regex.*;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import nesloader.util.NesMemoryMap;

/**
 * Exports the disassembled NES program as a ca65 v2.18-compatible assembly source.
 *
 * Output files (generated side-by-side):
 *   <name>.asm  — assembly source (includes build instructions as a header comment)
 *   <name>.cfg  — ld65 linker configuration
 *
 * Workflow:
 *   ca65 --cpu 6502 -o <name>.o <name>.asm
 *   ld65 -C <name>.cfg -o <name>.nes <name>.o
 *
 * Option "Source .nes file": path to the original ROM; when supplied, CHR-ROM data
 * is read from it and embedded in the CHARS segment. If omitted, the CHARS segment
 * contains a placeholder comment.
 */
public class NesExporter extends Exporter {

    private static final String OPT_SRC_ROM = "Source .nes file (for CHR-ROM)";

    private String sourceNesPath = "";

    // -------------------------------------------------------------------------
    // Static tables
    // -------------------------------------------------------------------------

    /** Equate names written to the .asm header — must not be re-emitted as labels. */
    private static final Set<String> EQUATE_NAMES = Set.of(
        "PPUCTRL", "PPUMASK", "PPUSTATUS", "OAMADDR", "OAMDATA",
        "PPUSCROLL", "PPUADDR", "PPUDATA",
        "SQ1_VOL", "SQ1_SWEEP", "SQ1_LO", "SQ1_HI",
        "SQ2_VOL", "SQ2_SWEEP", "SQ2_LO", "SQ2_HI",
        "TRI_LINEAR", "TRI_LO", "TRI_HI",
        "NOISE_VOL", "NOISE_LO", "NOISE_HI",
        "DMC_FREQ", "DMC_RAW", "DMC_START", "DMC_LEN",
        "OAM_DMA", "APU_STATUS", "JOY1", "JOY2",
        "VEC_NMI", "VEC_RESET", "VEC_IRQ");

    /** 6502 relative-branch mnemonics. */
    private static final Set<String> BRANCH_MNEMONICS = Set.of(
        "BEQ", "BNE", "BCC", "BCS", "BMI", "BPL", "BVC", "BVS");

    /** Call/jump mnemonics — same single-target flow shape as a branch. */
    private static final Set<String> CALL_JUMP_MNEMONICS = Set.of("JSR", "JMP");

    /** Hardware register address → equate name, used to replace hex literals in output. */
    private static final Map<Integer, String> HW_REG_MAP = buildHwRegMap();

    private static Map<Integer, String> buildHwRegMap() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(0x2000, "PPUCTRL");
        m.put(0x2001, "PPUMASK");
        m.put(0x2002, "PPUSTATUS");
        m.put(0x2003, "OAMADDR");
        m.put(0x2004, "OAMDATA");
        m.put(0x2005, "PPUSCROLL");
        m.put(0x2006, "PPUADDR");
        m.put(0x2007, "PPUDATA");
        m.put(0x4000, "SQ1_VOL");
        m.put(0x4001, "SQ1_SWEEP");
        m.put(0x4002, "SQ1_LO");
        m.put(0x4003, "SQ1_HI");
        m.put(0x4004, "SQ2_VOL");
        m.put(0x4005, "SQ2_SWEEP");
        m.put(0x4006, "SQ2_LO");
        m.put(0x4007, "SQ2_HI");
        m.put(0x4008, "TRI_LINEAR");
        m.put(0x400A, "TRI_LO");
        m.put(0x400B, "TRI_HI");
        m.put(0x400C, "NOISE_VOL");
        m.put(0x400E, "NOISE_LO");
        m.put(0x400F, "NOISE_HI");
        m.put(0x4010, "DMC_FREQ");
        m.put(0x4011, "DMC_RAW");
        m.put(0x4012, "DMC_START");
        m.put(0x4013, "DMC_LEN");
        m.put(0x4014, "OAM_DMA");
        m.put(0x4015, "APU_STATUS");
        m.put(0x4016, "JOY1");
        m.put(0x4017, "JOY2");
        return Collections.unmodifiableMap(m);
    }

    // -------------------------------------------------------------------------
    // Constructor / options
    // -------------------------------------------------------------------------

    public NesExporter() {
        super("NES ca65 Assembly", "asm", null);
    }

    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        return List.of(new FileChooserOption(OPT_SRC_ROM, sourceNesPath,
            "NES ROM files", "nes"));
    }

    @Override
    public void setOptions(List<Option> options) {
        for (Option opt : options) {
            if (OPT_SRC_ROM.equals(opt.getName()) && opt.getValue() instanceof String s) {
                sourceNesPath = s;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Export entry point
    // -------------------------------------------------------------------------

    @Override
    public boolean export(File file, DomainObject domainObject,
                          AddressSetView addressSet, TaskMonitor monitor)
            throws ExporterException, IOException {

        if (!(domainObject instanceof Program program)) {
            log.appendMsg("Domain object is not a Program.");
            return false;
        }

        int prgRomSize = program.getOptions("NES ROM").getInt("PRG ROM Size", 0);
        int mapperNum  = program.getOptions("NES ROM").getInt("Mapper", 0);

        Memory  memory  = program.getMemory();
        Listing listing = program.getListing();

        List<MemoryBlock> prgBlocks = collectPrgBlocks(memory);

        byte[] rawInesHeader = null;
        byte[] chrData       = null;

        if (!sourceNesPath.isBlank()) {
            File src = new File(sourceNesPath);
            if (src.isFile()) {
                Object[] result = readInesData(src);
                rawInesHeader = (byte[]) result[0];
                chrData       = (byte[]) result[1];
            } else {
                log.appendMsg("Source .nes file not found: " + sourceNesPath);
            }
        }

        int chrBanks = (rawInesHeader != null) ? (rawInesHeader[5] & 0xFF) : 0;
        boolean hasSram = memory.getBlock("SRAM") != null;

        String baseName = file.getName().replaceAll("\\.[^.]+$", "");
        File cfgFile = new File(file.getParent(), baseName + ".cfg");

        try (PrintWriter cfg = new PrintWriter(new FileWriter(cfgFile))) {
            writeCfg(cfg, prgBlocks, chrBanks, chrData != null ? chrData.length : 0, hasSram);
        }

        try (PrintWriter asm = new PrintWriter(new FileWriter(file))) {
            writeBuildHeader(asm, program, file.getName(), cfgFile.getName());
            writeEquates(asm);
            writeRamVariables(asm, program, hasSram);
            writeInesHeaderSegment(asm, program, rawInesHeader, mapperNum, prgRomSize);
            writePrgSegments(asm, program, listing, prgBlocks, memory, monitor);
            writeChrsSegment(asm, chrData);
        }

        return true;
    }

    // -------------------------------------------------------------------------
    // PRG block collection and ordering
    // -------------------------------------------------------------------------

    private List<MemoryBlock> collectPrgBlocks(Memory memory) {
        List<MemoryBlock> fixed    = new ArrayList<>();
        List<MemoryBlock> overlays = new ArrayList<>();

        for (MemoryBlock b : memory.getBlocks()) {
            if (!b.getName().startsWith("PRG_")) continue;
            if (b.isOverlay()) overlays.add(b);
            else               fixed.add(b);
        }

        fixed.sort(Comparator.comparing(MemoryBlock::getStart));
        overlays.sort(Comparator.comparingInt(b -> extractTrailingNumber(b.getName())));

        List<MemoryBlock> ordered   = new ArrayList<>();
        List<MemoryBlock> highFixed = new ArrayList<>();

        for (MemoryBlock b : fixed) {
            long start = b.getStart().getOffset();
            if (start >= 0xC000L) highFixed.add(b);
            else                  ordered.add(b);
        }

        ordered.addAll(overlays);
        ordered.addAll(highFixed);
        return ordered;
    }

    private int extractTrailingNumber(String name) {
        Matcher m = Pattern.compile("(\\d+)$").matcher(name);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    // -------------------------------------------------------------------------
    // Source .nes file reading
    // -------------------------------------------------------------------------

    private Object[] readInesData(File src) {
        try (RandomAccessFile raf = new RandomAccessFile(src, "r")) {
            byte[] hdr = new byte[16];
            raf.readFully(hdr);

            if (hdr[0] != 0x4E || hdr[1] != 0x45 || hdr[2] != 0x53 || hdr[3] != 0x1A) {
                log.appendMsg("Not a valid iNES file: " + src.getName());
                return new Object[]{null, null};
            }

            int     prgBanks  = hdr[4] & 0xFF;
            int     chrBanks  = hdr[5] & 0xFF;
            boolean trainer   = (hdr[6] & 0x04) != 0;
            long    chrOffset = 16L + (trainer ? 512 : 0) + (long) prgBanks * 16384;
            int     chrSize   = chrBanks * 8192;

            byte[] chrData = null;
            if (chrSize > 0 && chrOffset + chrSize <= raf.length()) {
                chrData = new byte[chrSize];
                raf.seek(chrOffset);
                raf.readFully(chrData);
            }

            return new Object[]{hdr, chrData};
        } catch (IOException e) {
            log.appendMsg("Failed to read source .nes: " + e.getMessage());
            return new Object[]{null, null};
        }
    }

    // -------------------------------------------------------------------------
    // Linker configuration (.cfg)
    // -------------------------------------------------------------------------

    private void writeCfg(PrintWriter cfg, List<MemoryBlock> prgBlocks,
                          int chrBanks, int chrDataLen, boolean hasSram) {
        cfg.println("MEMORY {");

        // RAM areas (nesdev CPU memory map). file="" — not written to the ROM image.
        cfg.printf ("    %-20s start=$0000, size=$0100, type=rw, file=\"\";%n", "ZP:");
        cfg.printf ("    %-20s start=$0100, size=$0100, type=rw, file=\"\";%n", "STACK:");
        cfg.printf ("    %-20s start=$0200, size=$0600, type=rw, file=\"\";%n", "RAM:");
        if (hasSram) {
            cfg.printf("    %-20s start=$6000, size=$2000, type=rw, file=\"\";%n", "SRAM:");
        }

        cfg.printf ("    %-20s start=$0000, size=$0010, type=ro, fill=yes, fillval=$FF;%n",
                    "HEADER:");

        for (MemoryBlock b : prgBlocks) {
            cfg.printf("    %-20s start=$%04X, size=$%04X, type=ro, fill=yes, fillval=$FF;%n",
                       b.getName() + ":",
                       b.getStart().getOffset(),
                       b.getSize());
        }

        if (chrBanks > 0 && chrDataLen > 0) {
            cfg.printf("    %-20s start=$0000, size=$%04X, type=ro, fill=yes, fillval=$FF;%n",
                       "CHR_ROM:", chrDataLen);
        }

        cfg.println("}");
        cfg.println();
        cfg.println("SEGMENTS {");
        cfg.printf ("    %-20s load=ZP, type=zp;%n", "ZEROPAGE:");
        cfg.printf ("    %-20s load=STACK, type=bss;%n", "STACK:");
        cfg.printf ("    %-20s load=RAM, type=bss;%n", "BSS:");
        if (hasSram) {
            cfg.printf("    %-20s load=SRAM, type=bss;%n", "SRAM:");
        }
        cfg.printf ("    %-20s load=HEADER, type=ro;%n", "HEADER:");
        for (MemoryBlock b : prgBlocks) {
            cfg.printf("    %-20s load=%s, type=ro;%n",
                       b.getName() + ":", b.getName());
        }
        if (chrBanks > 0 && chrDataLen > 0) {
            cfg.printf("    %-20s load=CHR_ROM, type=ro;%n", "CHARS:");
        }
        cfg.println("}");
    }

    // -------------------------------------------------------------------------
    // Build instructions header comment
    // -------------------------------------------------------------------------

    private void writeBuildHeader(PrintWriter asm, Program program,
                                  String asmName, String cfgName) {
        String base = asmName.replaceAll("\\.[^.]+$", "");
        asm.println("; ===========================================================================");
        asm.println("; NES ca65 Assembly Source");
        asm.println("; Generated by Ghidra NES Loader Exporter");
        asm.printf ("; Program : %s%n", program.getName());
        asm.printf ("; Language: %s%n", program.getLanguageID());
        asm.println(";");
        asm.println("; BUILD INSTRUCTIONS");
        asm.println("; ---------------------------------------------------------------------------");
        asm.println("; Requirements: ca65 v2.18, ld65 v2.18  (cc65 toolchain)");
        asm.println(";");
        asm.println("; Step 1 — assemble:");
        asm.printf (";   ca65 --cpu 6502 -o %s.o %s%n", base, asmName);
        asm.println(";");
        asm.println("; Step 2 — link:");
        asm.printf (";   ld65 -C %s -o %s.nes %s.o%n", cfgName, base, base);
        asm.println(";");
        asm.println("; Combined:");
        asm.printf (";   ca65 --cpu 6502 -o %s.o %s && ld65 -C %s -o %s.nes %s.o%n",
                    base, asmName, cfgName, base, base);
        asm.println(";");
        asm.println("; With debug info (for use with debuggers, e.g. Mesen/FCEUX):");
        asm.printf (";   ca65 --cpu 6502 -g -o %s.o %s%n", base, asmName);
        asm.printf (";   ld65 -C %s --dbgfile %s.dbg -o %s.nes %s.o%n", cfgName, base, base, base);
        asm.println(";");
        asm.printf ("; The linker script '%s' is generated alongside this file.%n", cfgName);
        asm.println("; If CHR-ROM was not embedded, see the CHARS segment at the end of this file.");
        asm.println("; ===========================================================================");
        asm.println();
    }

    // -------------------------------------------------------------------------
    // Hardware register equates
    // -------------------------------------------------------------------------

    private void writeEquates(PrintWriter asm) {
        asm.println("; ---------------------------------------------------------------------------");
        asm.println("; Hardware register equates");
        asm.println("; ---------------------------------------------------------------------------");
        // PPU
        asm.println("PPUCTRL    = $2000  ; PPU control");
        asm.println("PPUMASK    = $2001  ; PPU mask");
        asm.println("PPUSTATUS  = $2002  ; PPU status");
        asm.println("OAMADDR    = $2003  ; OAM address");
        asm.println("OAMDATA    = $2004  ; OAM data");
        asm.println("PPUSCROLL  = $2005  ; PPU scroll");
        asm.println("PPUADDR    = $2006  ; PPU address");
        asm.println("PPUDATA    = $2007  ; PPU data");
        // APU
        asm.println("SQ1_VOL    = $4000  ; Pulse 1 volume/duty");
        asm.println("SQ1_SWEEP  = $4001");
        asm.println("SQ1_LO     = $4002");
        asm.println("SQ1_HI     = $4003");
        asm.println("SQ2_VOL    = $4004  ; Pulse 2 volume/duty");
        asm.println("SQ2_SWEEP  = $4005");
        asm.println("SQ2_LO     = $4006");
        asm.println("SQ2_HI     = $4007");
        asm.println("TRI_LINEAR = $4008  ; Triangle linear counter");
        asm.println("TRI_LO     = $400A");
        asm.println("TRI_HI     = $400B");
        asm.println("NOISE_VOL  = $400C  ; Noise volume");
        asm.println("NOISE_LO   = $400E");
        asm.println("NOISE_HI   = $400F");
        asm.println("DMC_FREQ   = $4010  ; DMC frequency");
        asm.println("DMC_RAW    = $4011");
        asm.println("DMC_START  = $4012");
        asm.println("DMC_LEN    = $4013");
        asm.println("OAM_DMA    = $4014  ; Sprite DMA");
        asm.println("APU_STATUS = $4015");
        asm.println("JOY1       = $4016  ; Controller 1");
        asm.println("JOY2       = $4017  ; Controller 2 / APU frame counter");
        asm.println();
        // Interrupt vectors
        asm.println("VEC_NMI    = $FFFA");
        asm.println("VEC_RESET  = $FFFC");
        asm.println("VEC_IRQ    = $FFFE");
        asm.println();
    }

    // -------------------------------------------------------------------------
    // RAM variables (ZEROPAGE / BSS / SRAM segments)
    // -------------------------------------------------------------------------

    /**
     * Emits Ghidra symbols located in RAM as ca65 variable declarations, so
     * that instructions referencing them by name assemble correctly.
     *
     * Address ranges follow the nesdev CPU memory map:
     *   $0000-$00FF  zero page          → .segment "ZEROPAGE" (type zp)
     *   $0100-$01FF  hardware stack     → .segment "STACK" (games may use
     *                                     part of it as extra work RAM)
     *   $0200-$07FF  internal RAM       → .segment "BSS"
     *   $6000-$7FFF  PRG-RAM / SRAM     → .segment "SRAM" (if present)
     *
     * Each segment is laid out with .res reservations; unlabeled gaps are
     * padded so every variable lands on its original address. Segments fill
     * their memory areas exactly.
     */
    private void writeRamVariables(PrintWriter asm, Program program, boolean hasSram) {
        asm.println("; ---------------------------------------------------------------------------");
        asm.println("; RAM variables");
        asm.println("; ---------------------------------------------------------------------------");

        emitRamSegment(asm, program, "ZEROPAGE", 0x0000, 0x00FF, "zero page");
        emitRamSegment(asm, program, "STACK", 0x0100, 0x01FF, "hardware stack page");
        emitRamSegment(asm, program, "BSS", 0x0200, 0x07FF, "internal RAM");
        if (hasSram) {
            emitRamSegment(asm, program, "SRAM", 0x6000, 0x7FFF, "battery-backed SRAM");
        }
        asm.println();
    }

    /**
     * Emits one RAM segment: symbols become "name: .res n" reservations,
     * unlabeled space becomes anonymous ".res" padding.
     */
    private void emitRamSegment(PrintWriter asm, Program program, String segName,
                                long start, long end, String title) {
        List<Symbol> symbols = collectRamSymbols(program, start, end);

        String exportDirective = segName.equals("ZEROPAGE") ? ".exportzp" : ".export";
        for (Symbol sym : symbols) {
            long addr = sym.getAddress().getOffset();
            asm.printf("%-25s %-15s ; $%0" + (addr <= 0xFF ? 2 : 4) + "X%n",
                       exportDirective, sym.getName(), addr);
        }
        if (!symbols.isEmpty()) asm.println();

        asm.printf("%n.segment \"%s\"  ; $%04X-$%04X %s%n%n", segName, start, end, title);

        Listing listing = program.getListing();
        long pos = start;
        for (int i = 0; i < symbols.size(); i++) {
            Symbol sym  = symbols.get(i);
            long   addr = sym.getAddress().getOffset();

            if (addr > pos) {
                asm.printf("    .res $%04X%-15s ; $%04X-$%04X (unlabeled)%n",
                           addr - pos, "", pos, addr - 1);
            }

            // Aliases: additional symbols at the same address.
            for (Symbol alias : program.getSymbolTable().getSymbols(sym.getAddress())) {
                if (alias != sym && !EQUATE_NAMES.contains(alias.getName())) {
                    asm.printf("%s:%n", alias.getName());
                }
            }

            long next = (i + 1 < symbols.size())
                    ? symbols.get(i + 1).getAddress().getOffset()
                    : end + 1;
            long len = next - addr;

            CodeUnit cu = listing.getCodeUnitAt(sym.getAddress());
            String[] eolLines = cu != null ? splitComment(cu.getComment(CommentType.EOL))
                                            : new String[0];
            String inline = eolLines.length > 0 ? "  ; " + eolLines[0] : "";

            asm.printf("%-15s .res $%04X       ; $%04X%s%s%n",
                       sym.getName() + ":", len, addr,
                       len > 1 ? String.format("-$%04X", addr + len - 1) : "", inline);

            for (int j = 1; j < eolLines.length; j++) {
                asm.println(INDENT + "; " + eolLines[j]);
            }

            pos = next;
        }

        if (pos <= end) {
            asm.printf("    .res $%04X%-15s ; $%04X-$%04X (unlabeled)%n",
                       end + 1 - pos, "", pos, end);
        }
    }

    /** Primary symbols in [start..end] of the default address space, address order. */
    private List<Symbol> collectRamSymbols(Program program, long start, long end) {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        AddressSet   range = new AddressSet(space.getAddress(start), space.getAddress(end));

        List<Symbol> symbols = new ArrayList<>();
        SymbolIterator it = program.getSymbolTable().getPrimarySymbolIterator(range, true);
        while (it.hasNext()) {
            Symbol sym = it.next();
            if (!EQUATE_NAMES.contains(sym.getName())) {
                symbols.add(sym);
            }
        }
        return symbols;
    }

    // -------------------------------------------------------------------------
    // iNES header segment
    // -------------------------------------------------------------------------

    private void writeInesHeaderSegment(PrintWriter asm, Program program,
                                        byte[] rawHdr, int mapperNum, int prgRomSize) {
        asm.println("; ---------------------------------------------------------------------------");
        asm.println("; iNES header  (16 bytes)");
        asm.println("; ---------------------------------------------------------------------------");
        asm.println(".segment \"HEADER\"");
        asm.println();

        if (rawHdr != null) {
            int prgBanks = rawHdr[4] & 0xFF;
            int chrBanks = rawHdr[5] & 0xFF;
            int flags6   = rawHdr[6] & 0xFF;
            int flags7   = rawHdr[7] & 0xFF;

            String mirror = (flags6 & 0x08) != 0 ? "4-screen"
                          : (flags6 & 0x01) != 0 ? "vertical" : "horizontal";

            asm.println("    .byte $4E, $45, $53, $1A        ; \"NES\" + $1A (magic)");
            asm.printf ("    .byte $%02X                       ; PRG-ROM banks (%d x 16 KB = %d KB)%n",
                        prgBanks, prgBanks, prgBanks * 16);
            asm.printf ("    .byte $%02X                       ; CHR-ROM banks (%d x 8 KB%s)%n",
                        chrBanks, chrBanks, chrBanks == 0 ? ", CHR-RAM" : "");
            asm.printf ("    .byte $%02X                       ; Flags 6  mapper-lo=%d mirror=%s battery=%b trainer=%b%n",
                        flags6, (flags6 >> 4) & 0xF, mirror,
                        (flags6 & 0x02) != 0, (flags6 & 0x04) != 0);
            asm.printf ("    .byte $%02X                       ; Flags 7  mapper-hi=%d%n",
                        flags7, (flags7 >> 4) & 0xF);

            StringBuilder sb = new StringBuilder("    .byte");
            for (int i = 8; i < 16; i++) {
                sb.append(String.format(" $%02X", rawHdr[i] & 0xFF));
                if (i < 15) sb.append(",");
            }
            sb.append("   ; unused / NES 2.0 extension fields");
            asm.println(sb);
        } else {
            int prgBanks = prgRomSize / 16384;
            int flags6   = (mapperNum & 0x0F) << 4;
            int flags7   = (mapperNum >> 4)   << 4;

            asm.println("    .byte $4E, $45, $53, $1A        ; \"NES\" + $1A (magic)");
            asm.printf ("    .byte $%02X                       ; PRG-ROM banks (%d x 16 KB)%n",
                        prgBanks, prgBanks);
            asm.println("    .byte $00                       ; CHR-ROM banks (update if ROM uses CHR-ROM)");
            asm.printf ("    .byte $%02X                       ; Flags 6  (mapper lo nibble)%n", flags6);
            asm.printf ("    .byte $%02X                       ; Flags 7  (mapper hi nibble)%n", flags7);
            asm.println("    .byte $00, $00, $00, $00, $00, $00, $00, $00  ; unused");
        }

        asm.println();
    }

    // -------------------------------------------------------------------------
    // PRG-ROM segments
    // -------------------------------------------------------------------------

    private void writePrgSegments(PrintWriter asm, Program program, Listing listing,
                                  List<MemoryBlock> prgBlocks, Memory memory,
                                  TaskMonitor monitor) throws IOException {
        asm.println("; ---------------------------------------------------------------------------");
        asm.println("; PRG-ROM code and data");
        asm.println("; ---------------------------------------------------------------------------");

        for (MemoryBlock block : prgBlocks) {
            if (monitor.isCancelled()) break;

            asm.printf("%n.segment \"%s\"%n%n", block.getName());

            if (!block.isInitialized()) {
                asm.println("; (uninitialized block — skipped)");
                continue;
            }

            if (block.isOverlay()) {
                asm.println("; (overlay bank — raw bytes)");
                emitRawBlock(asm, block, memory);
            } else {
                AddressSet blockSet = new AddressSet(block.getStart(), block.getEnd());
                Map<Address, String> extraLabels = collectExtraLabels(listing, blockSet, program);
                emitCodeUnits(asm, listing, program, memory, blockSet, extraLabels, monitor);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Label collection — pre-pass for branch targets
    // -------------------------------------------------------------------------

    /**
     * Scans all branch/call/jump instructions in the given address set.
     * For each target that has no usable Ghidra symbol, registers a
     * synthetic LAB_XXXX label so it can be emitted when that address is reached.
     */
    private Map<Address, String> collectExtraLabels(Listing listing, AddressSetView set,
                                                    Program program) {
        Map<Address, String> extra = new LinkedHashMap<>();

        CodeUnitIterator it = listing.getCodeUnits(set, true);
        while (it.hasNext()) {
            CodeUnit cu = it.next();
            if (!(cu instanceof Instruction inst)) continue;
            String mnemonic = inst.getMnemonicString().toUpperCase();
            if (!BRANCH_MNEMONICS.contains(mnemonic) && !CALL_JUMP_MNEMONICS.contains(mnemonic)) {
                continue;
            }

            Address[] flows = inst.getFlows();
            if (flows == null) continue;

            for (Address target : flows) {
                if (!set.contains(target)) continue;
                if (usableSymbol(target, program) == null) {
                    extra.putIfAbsent(target,
                        String.format("LAB_%04X", target.getOffset()));
                }
            }
        }
        return extra;
    }

    /**
     * Returns the first symbol at {@code addr} whose name is not an equate
     * constant, or {@code null} if none exists.
     *
     * Dynamic symbols (e.g. Ghidra's auto-generated "DAT_0049") are skipped:
     * they exist only for the listing display and are never persisted, so
     * referencing them by name would produce an undefined symbol in ca65.
     */
    private Symbol usableSymbol(Address addr, Program program) {
        for (Symbol sym : program.getSymbolTable().getSymbols(addr)) {
            if (sym.isDynamic()) continue;
            if (!EQUATE_NAMES.contains(sym.getName())) return sym;
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Code unit emission
    // -------------------------------------------------------------------------

    /**
     * Iterates code units over the given address set and emits ca65 assembly.
     *
     * Label emission rules:
     *   - Symbols from Ghidra's symbol table are emitted, except those whose
     *     names clash with the equates declared in writeEquates().
     *   - If an address has no usable Ghidra symbol but is a branch target,
     *     the synthetic LAB_XXXX label from extraLabels is emitted instead.
     *
     * Instruction formatting:
     *   - Relative branch instructions use label names (not raw hex addresses)
     *     so that ca65 can compute the correct signed-byte offset.
     *   - Hardware register addresses ($2000-$2007, $4000-$4017) are replaced
     *     with their equate names (PPUCTRL, PPUDATA, JOY1, …).
     *
     * Comment emission (ca65 ";" syntax, multi-line comments become one
     * ";"-prefixed line per source line):
     *   - plate  — above the label, at column 0
     *   - pre    — after the label, indented
     *   - eol    — inline after the instruction/data (extra lines follow below);
     *              falls back to the repeatable comment when absent
     *   - post   — below the code unit, indented
     */
    private void emitCodeUnits(PrintWriter asm, Listing listing, Program program,
                               Memory memory, AddressSetView set,
                               Map<Address, String> extraLabels,
                               TaskMonitor monitor) throws IOException {

        CodeUnitIterator it = listing.getCodeUnits(set, true);

        while (it.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = it.next();
            Address  addr = cu.getAddress();

            emitCommentLines(asm, cu.getComment(CommentType.PLATE), "");

            // --- Label emission ---
            Symbol usable = usableSymbol(addr, program);
            if (usable != null) {
                for (Symbol sym : program.getSymbolTable().getSymbols(addr)) {
                    if (!EQUATE_NAMES.contains(sym.getName())) {
                        asm.printf("%s:%n", sym.getName());
                    }
                }
            } else {
                String synth = extraLabels.get(addr);
                if (synth != null) {
                    asm.printf("%s:%n", synth);
                }
            }

            emitCommentLines(asm, cu.getComment(CommentType.PRE), INDENT);

            String eol = cu.getComment(CommentType.EOL);
            if (eol == null) {
                eol = cu.getComment(CommentType.REPEATABLE);
            }
            String[] eolLines = splitComment(eol);
            String   inline   = eolLines.length > 0 ? "  ; " + eolLines[0] : "";

            // --- Instruction / data emission ---
            if (cu instanceof Instruction inst) {
                asm.printf("    %s%s%n",
                           formatInstruction(inst, program, extraLabels), inline);
            } else if (cu instanceof Data data) {
                emitDataUnit(asm, data, memory, inline);
            }

            for (int i = 1; i < eolLines.length; i++) {
                asm.println(INDENT + "; " + eolLines[i]);
            }

            emitCommentLines(asm, cu.getComment(CommentType.POST), INDENT);
        }
    }

    // -------------------------------------------------------------------------
    // Comment emission
    // -------------------------------------------------------------------------

    private static final String INDENT = "    ";

    /** Splits a Ghidra comment into individual lines; empty array when absent. */
    private String[] splitComment(String comment) {
        if (comment == null || comment.isEmpty()) {
            return new String[0];
        }
        return comment.split("\\r?\\n", -1);
    }

    /**
     * Emits a (possibly multi-line) Ghidra comment as a sequence of
     * single-line ca65 comments, one "; " line per source line.
     */
    private void emitCommentLines(PrintWriter asm, String comment, String indent) {
        for (String line : splitComment(comment)) {
            asm.println(indent + "; " + line);
        }
    }

    // -------------------------------------------------------------------------
    // Instruction formatting
    // -------------------------------------------------------------------------

    /**
     * Formats a single instruction for ca65 output.
     *
     * Branch/JSR/JMP instructions are formatted as  MNEMONIC label  (or
     * MNEMONIC (label) for indirect JMP) using the flow target's symbol —
     * for branches this also avoids Range errors that occur when absolute
     * addresses are used in relocatable segments; for JSR/JMP it just gives
     * readable output instead of a raw hex call/jump target.
     *
     * All other instructions go through hex-prefix normalisation and hardware
     * register address substitution.
     */
    private String formatInstruction(Instruction inst, Program program,
                                     Map<Address, String> extraLabels) {
        String mnemonic = inst.getMnemonicString().toUpperCase();

        if (BRANCH_MNEMONICS.contains(mnemonic) || CALL_JUMP_MNEMONICS.contains(mnemonic)) {
            Address[] flows = inst.getFlows();
            if (flows != null && flows.length == 1) {
                String label = labelAt(flows[0], program, extraLabels);
                // JMP can be indirect ("JMP ($1234)"); branches/JSR never are.
                boolean indirect = inst.toString().contains("(");
                return indirect ? mnemonic + " (" + label + ")" : mnemonic + " " + label;
            }
        }

        String text = fixHexPrefix(inst.toString());
        text = stripDynamicNames(text, inst, program);
        text = applyHwRegisters(text);
        text = applyRamSymbols(text, inst, program);
        text = fixArrayIndexSyntax(text);

        // A 3-byte instruction addressing a zero-page location must keep
        // absolute mode: without "a:" ca65 would pick the 2-byte zero-page
        // form and shift all following code.
        if (inst.getLength() == 3 && referencesZeroPage(inst)) {
            int sp = text.indexOf(' ');
            if (sp > 0 && sp + 1 < text.length()
                    && text.charAt(sp + 1) != '(' && text.charAt(sp + 1) != '#') {
                text = text.substring(0, sp + 1) + "a:" + text.substring(sp + 1);
            }
        }

        return text;
    }

    /** True if the instruction has a memory reference into $0000-$00FF. */
    private boolean referencesZeroPage(Instruction inst) {
        for (Reference ref : inst.getReferencesFrom()) {
            Address to = ref.getToAddress();
            if (to.isMemoryAddress() && to.getOffset() < 0x100) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the label name for {@code addr}: the first usable Ghidra symbol,
     * or the synthetic LAB_XXXX entry (creating one if necessary).
     */
    private String labelAt(Address addr, Program program,
                           Map<Address, String> extraLabels) {
        Symbol sym = usableSymbol(addr, program);
        if (sym != null) return sym.getName();
        return extraLabels.computeIfAbsent(addr,
            a -> String.format("LAB_%04X", a.getOffset()));
    }

    /**
     * Normalises hex literals from Ghidra format to ca65 format ($-prefix).
     *   0x1A2B  →  $1A2B
     *   1A2Bh   →  $1A2B
     */
    private String fixHexPrefix(String s) {
        s = s.replaceAll("0x([0-9a-fA-F]+)", "\\$$1");
        s = s.replaceAll("([0-9][0-9a-fA-F]*)h\\b",  "\\$$1");
        return s;
    }

    /**
     * Converts Ghidra's array-index operand syntax (used when a reference
     * lands inside a labeled range rather than exactly on it) into a ca65
     * arithmetic expression.
     *   NAME[21]   →  NAME+21
     *   NAME[-3]   →  NAME-3
     */
    private String fixArrayIndexSyntax(String text) {
        Matcher m = Pattern.compile("\\[(-?[0-9A-Za-z$]+)\\]").matcher(text);
        return m.replaceAll(mr -> {
            String offset = mr.group(1);
            return offset.startsWith("-") ? offset : "+" + offset;
        });
    }

    /**
     * Replaces hardware-register hex addresses with their equate names.
     * Example: {@code STA $2007} → {@code STA PPUDATA}.
     * Matching is case-insensitive and requires the address not to be
     * followed by another hex digit (to avoid partial matches).
     */
    private String applyHwRegisters(String text) {
        for (Map.Entry<Integer, String> e : HW_REG_MAP.entrySet()) {
            String hexPat = String.format("%04x", e.getKey());
            text = text.replaceAll(
                "(?i)\\$" + hexPat + "(?![0-9a-fA-F])",
                Matcher.quoteReplacement(e.getValue()));
        }
        return text;
    }

    /**
     * Replaces hex operand addresses that reference a named RAM/zero-page/SRAM
     * symbol with that symbol's name, so instructions read e.g. {@code LDA MYVAR}
     * instead of {@code LDA $0300}. Only touches addresses reached via a memory
     * reference from this instruction (so unrelated immediate hex values are
     * left untouched), and only when a usable Ghidra symbol exists there.
     */
    private String applyRamSymbols(String text, Instruction inst, Program program) {
        for (Reference ref : inst.getReferencesFrom()) {
            Address to = ref.getToAddress();
            if (!to.isMemoryAddress() || !isRamAddress(to.getOffset())) continue;

            Symbol sym = usableSymbol(to, program);
            if (sym == null) continue;

            // Matches both the 2-digit (zero-page mode) and 4-digit
            // (forced-absolute mode) hex forms Ghidra may print for the address.
            String hex = Long.toHexString(to.getOffset());
            text = text.replaceAll("(?i)\\$0*" + hex + "(?![0-9a-fA-F])",
                Matcher.quoteReplacement(sym.getName()));
        }
        return text;
    }

    /** True if {@code off} falls within the CPU-internal RAM or SRAM ranges. */
    private boolean isRamAddress(long off) {
        return (off >= NesMemoryMap.RAM_START && off <= NesMemoryMap.RAM_END)
            || (off >= NesMemoryMap.SRAM_START && off <= NesMemoryMap.SRAM_END);
    }

    /**
     * Replaces Ghidra's auto-generated dynamic names (e.g. {@code DAT_0049},
     * {@code LAB_fe12}) with the raw hex address they stand for.
     *
     * These names are synthesized on the fly by Ghidra purely for the listing
     * display — {@link Symbol#isDynamic()} — and are never persisted, so they
     * are never declared anywhere in the exported source. Left as-is they
     * assemble as references to an undefined ca65 symbol.
     */
    private String stripDynamicNames(String text, Instruction inst, Program program) {
        for (Reference ref : inst.getReferencesFrom()) {
            Address to = ref.getToAddress();
            if (!to.isMemoryAddress()) continue;

            Symbol sym = program.getSymbolTable().getPrimarySymbol(to);
            if (sym == null || !sym.isDynamic()) continue;

            int digits = inst.getLength() >= 3 ? 4 : 2;
            String hex = String.format("$%0" + digits + "X", to.getOffset());
            text = text.replaceAll("\\b" + Pattern.quote(sym.getName()) + "\\b",
                Matcher.quoteReplacement(hex));
        }
        return text;
    }

    // -------------------------------------------------------------------------
    // Data unit emission
    // -------------------------------------------------------------------------

    private void emitDataUnit(PrintWriter asm, Data data, Memory memory, String inlineComment)
            throws IOException {
        int len = data.getLength();
        if (len == 0) return;

        byte[] bytes = new byte[len];
        try {
            memory.getBytes(data.getAddress(), bytes);
        } catch (MemoryAccessException e) {
            asm.printf("    ; [unreadable %d byte(s) at %s]%n", len, data.getAddress());
            return;
        }

        if (len == 2 && isWordType(data)) {
            int lo = bytes[0] & 0xFF;
            int hi = bytes[1] & 0xFF;
            asm.printf("    .word $%04X%s%n", lo | (hi << 8), inlineComment);
        } else {
            emitByteLines(asm, bytes, inlineComment);
        }
    }

    private boolean isWordType(Data data) {
        String typeName = data.getDataType().getName().toLowerCase();
        return typeName.contains("word") || typeName.contains("pointer")
            || typeName.contains("addr");
    }

    // -------------------------------------------------------------------------
    // Raw block emission (overlay banks)
    // -------------------------------------------------------------------------

    private void emitRawBlock(PrintWriter asm, MemoryBlock block, Memory memory)
            throws IOException {
        long remaining = block.getSize();
        Address addr   = block.getStart();
        byte[]  buf    = new byte[256];

        while (remaining > 0) {
            int chunk = (int) Math.min(remaining, buf.length);
            try {
                memory.getBytes(addr, buf, 0, chunk);
                emitByteLines(asm, Arrays.copyOf(buf, chunk));
            } catch (MemoryAccessException e) {
                asm.printf("    ; [unreadable %d byte(s) at %s]%n", chunk, addr);
            }
            addr       = addr.add(chunk);
            remaining -= chunk;
        }
    }

    private void emitByteLines(PrintWriter asm, byte[] bytes) {
        emitByteLines(asm, bytes, "");
    }

    /** Emits .byte lines; {@code firstLineComment} is appended to the first line only. */
    private void emitByteLines(PrintWriter asm, byte[] bytes, String firstLineComment) {
        for (int i = 0; i < bytes.length; i += 16) {
            int end = Math.min(i + 16, bytes.length);
            StringBuilder sb = new StringBuilder("    .byte ");
            for (int j = i; j < end; j++) {
                sb.append(String.format("$%02X", bytes[j] & 0xFF));
                if (j < end - 1) sb.append(", ");
            }
            if (i == 0) sb.append(firstLineComment);
            asm.println(sb);
        }
    }

    // -------------------------------------------------------------------------
    // CHR-ROM segment
    // -------------------------------------------------------------------------

    private void writeChrsSegment(PrintWriter asm, byte[] chrData) {
        asm.println();
        asm.println("; ---------------------------------------------------------------------------");
        asm.println("; CHR-ROM  (PPU pattern tables)");
        asm.println("; ---------------------------------------------------------------------------");
        asm.println(".segment \"CHARS\"");
        asm.println();

        if (chrData == null || chrData.length == 0) {
            asm.println("; CHR-ROM data not available.");
            asm.println("; To embed it, set the \"Source .nes file\" option before exporting,");
            asm.println("; or replace this comment with:");
            asm.println(";   .incbin \"original.nes\", <chr_byte_offset>, <chr_byte_size>");
        } else {
            emitByteLines(asm, chrData);
        }
    }
}
