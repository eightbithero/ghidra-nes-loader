package nesloader.exporter;

import java.io.*;
import java.util.*;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

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

    public NesExporter() {
        super("NES ca65 Assembly", "asm", null);
    }

    // -------------------------------------------------------------------------
    // Options
    // -------------------------------------------------------------------------

    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        return List.of(new Option(OPT_SRC_ROM, sourceNesPath));
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

        // Try to read iNES header and CHR-ROM from the original .nes file
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

        // Companion .cfg file (same directory, same base name)
        String baseName = file.getName().replaceAll("\\.[^.]+$", "");
        File cfgFile = new File(file.getParent(), baseName + ".cfg");

        // Write linker config
        try (PrintWriter cfg = new PrintWriter(new FileWriter(cfgFile))) {
            writeCfg(cfg, prgBlocks, chrBanks, chrData != null ? chrData.length : 0);
        }

        // Write assembly source
        try (PrintWriter asm = new PrintWriter(new FileWriter(file))) {
            writeBuildHeader(asm, program, file.getName(), cfgFile.getName());
            writeEquates(asm);
            writeInesHeaderSegment(asm, program, rawInesHeader, mapperNum, prgRomSize);
            writePrgSegments(asm, program, listing, prgBlocks, memory, monitor);
            writeChrsSegment(asm, chrData);
        }

        return true;
    }

    // -------------------------------------------------------------------------
    // PRG block collection and ordering
    // -------------------------------------------------------------------------

    /**
     * Returns PRG memory blocks in file order:
     *  non-overlay blocks sorted ascending by start address (bank 0 before last bank),
     *  overlay blocks (switchable middle banks) sorted by bank number between them.
     *
     * For NROM  : PRG_ROM  or  PRG_ROM_LO, PRG_ROM_HI
     * For MMC1  : PRG_BANK_0, [PRG_BANK_1..N-2 overlays], PRG_BANK_{N-1}
     */
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

        // Interleave: fixed banks at $8000 first, then overlays, then fixed at $C000+
        List<MemoryBlock> ordered = new ArrayList<>();
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
        java.util.regex.Matcher m =
            java.util.regex.Pattern.compile("(\\d+)$").matcher(name);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    // -------------------------------------------------------------------------
    // Source .nes file reading
    // -------------------------------------------------------------------------

    /** Returns [byte[] rawInesHeader (16 bytes), byte[] chrData]. Either may be null. */
    private Object[] readInesData(File src) {
        try (RandomAccessFile raf = new RandomAccessFile(src, "r")) {
            byte[] hdr = new byte[16];
            raf.readFully(hdr);

            if (hdr[0] != 0x4E || hdr[1] != 0x45 || hdr[2] != 0x53 || hdr[3] != 0x1A) {
                log.appendMsg("Not a valid iNES file: " + src.getName());
                return new Object[]{null, null};
            }

            int     prgBanks    = hdr[4] & 0xFF;
            int     chrBanks    = hdr[5] & 0xFF;
            boolean trainer     = (hdr[6] & 0x04) != 0;
            long    chrOffset   = 16L + (trainer ? 512 : 0) + (long) prgBanks * 16384;
            int     chrSize     = chrBanks * 8192;

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
                          int chrBanks, int chrDataLen) {
        cfg.println("MEMORY {");
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

            // Bytes 8–15
            StringBuilder sb = new StringBuilder("    .byte");
            for (int i = 8; i < 16; i++) {
                sb.append(String.format(" $%02X", rawHdr[i] & 0xFF));
                if (i < 15) sb.append(",");
            }
            sb.append("   ; unused / NES 2.0 extension fields");
            asm.println(sb);
        } else {
            // Reconstruct from program options
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
                // Overlay banks are not disassembled by Ghidra; emit raw bytes
                asm.println("; (overlay bank — raw bytes)");
                emitRawBlock(asm, block, memory);
            } else {
                emitCodeUnits(asm, listing, program, memory,
                              new AddressSet(block.getStart(), block.getEnd()), monitor);
            }
        }
    }

    /**
     * Iterates code units over the given address set and emits ca65 assembly.
     * Labels from the symbol table are emitted on their own lines above the unit.
     */
    private void emitCodeUnits(PrintWriter asm, Listing listing, Program program,
                               Memory memory, AddressSetView set,
                               TaskMonitor monitor) throws IOException {

        CodeUnitIterator it = listing.getCodeUnits(set, true);

        while (it.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = it.next();

            // Emit labels for this address
            for (Symbol sym : program.getSymbolTable().getSymbols(cu.getAddress())) {
                asm.printf("%s:%n", sym.getName());
            }

            if (cu instanceof Instruction inst) {
                asm.printf("    %s%n", fixHexPrefix(inst.toString()));
            } else if (cu instanceof Data data) {
                emitDataUnit(asm, data, memory);
            }
        }
    }

    /**
     * Normalises hex literals to ca65 format ($ prefix).
     * ca65 4.2: accepts '$XXXX' or 'XXXXh'; does NOT accept '0x'.
     * Ghidra 6502 module emits '0x' prefix.
     */
    private String fixHexPrefix(String s) {
        // 0x1A2B  →  $1A2B
        s = s.replaceAll("0x([0-9a-fA-F]+)", "\\$$1");
        // 1A2Bh   →  $1A2B  (trailing-h variant, just in case)
        s = s.replaceAll("([0-9][0-9a-fA-F]*)h\\b", "\\$$1");
        return s;
    }

    /**
     * Emits a single Data unit as .byte / .word directive(s).
     */
    private void emitDataUnit(PrintWriter asm, Data data, Memory memory) throws IOException {
        int len = data.getLength();
        if (len == 0) return;

        byte[] bytes = new byte[len];
        try {
            memory.getBytes(data.getAddress(), bytes);
        } catch (MemoryAccessException e) {
            asm.printf("    ; [unreadable %d byte(s) at %s]%n", len, data.getAddress());
            return;
        }

        // Use .word for defined 2-byte data types (pointers / vectors)
        if (len == 2 && isWordType(data)) {
            int lo = bytes[0] & 0xFF;
            int hi = bytes[1] & 0xFF;
            asm.printf("    .word $%04X%n", lo | (hi << 8));
        } else {
            emitByteLines(asm, bytes);
        }
    }

    private boolean isWordType(Data data) {
        String typeName = data.getDataType().getName().toLowerCase();
        return typeName.contains("word") || typeName.contains("pointer")
            || typeName.contains("addr");
    }

    /**
     * Emits a raw memory block as .byte directives (for overlay or unanalyzed blocks).
     */
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

    /**
     * Writes bytes as .byte directives, 16 values per line.
     */
    private void emitByteLines(PrintWriter asm, byte[] bytes) {
        for (int i = 0; i < bytes.length; i += 16) {
            int end = Math.min(i + 16, bytes.length);
            StringBuilder sb = new StringBuilder("    .byte ");
            for (int j = i; j < end; j++) {
                sb.append(String.format("$%02X", bytes[j] & 0xFF));
                if (j < end - 1) sb.append(", ");
            }
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
