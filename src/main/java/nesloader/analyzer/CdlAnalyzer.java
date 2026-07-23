package nesloader.analyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import nesloader.format.CdlFile;

/**
 * Analyzes a Code/Data Logger (CDL) file and applies its hints to the program:
 *
 *   - Bytes flagged as CODE are queued for disassembly.
 *   - Bytes flagged as DATA (and not CODE) are defined as raw bytes.
 *   - Unknown bytes (flag == 0) are left for Ghidra's standard heuristics.
 *
 * The CDL file path must be supplied via the analyzer option panel before
 * running analysis.  The file size must exactly match the PRG-ROM size.
 *
 * CDL format reference: https://fceux.com/web/help/CodeDataLogger.html
 */
public class CdlAnalyzer extends AbstractAnalyzer {

    private static final String NAME        = "NES CDL File Analyzer";
    private static final String DESCRIPTION =
        "Applies Code/Data Logger (CDL) hints from an emulator trace to improve disassembly.";

    private static final String OPTION_CDL_PATH = "CDL File Path";

    private File cdlFile = null;

    public CdlAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS.before().before());
        setDefaultEnablement(false); // requires user-supplied CDL file
    }

    @Override
    public boolean getDefaultEnablement(Program program) { return false; }

    @Override
    public boolean canAnalyze(Program program) {
        Memory mem = program.getMemory();
        return mem.getBlock("PRG_ROM")    != null
            || mem.getBlock("PRG_ROM_LO") != null
            || mem.getBlock("PRG_BANK_0") != null;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPTION_CDL_PATH, OptionType.FILE_TYPE, null, null,
            "CDL file produced by FCEUX or Mesen. File size must match PRG-ROM size.");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        cdlFile = options.getFile(OPTION_CDL_PATH, null);
    }

    @Override
    public boolean added(Program program, AddressSetView set,
                         TaskMonitor monitor, MessageLog log) {

        if (cdlFile == null) {
            log.appendMsg(NAME, "CDL file not set — skipping.");
            return false;
        }

        if (!cdlFile.isFile()) {
            log.appendMsg(NAME, "CDL file not found: " + cdlFile.getAbsolutePath());
            return false;
        }

        List<PrgRange> prgRanges = findPrgRanges(program.getMemory());
        if (prgRanges.isEmpty()) {
            log.appendMsg(NAME, "PRG-ROM memory block not found.");
            return false;
        }

        // Total PRG-ROM size (all banks) is stored by NesLoader in program properties.
        // Fall back to the mapped extent if the property is absent.
        int mappedPrgSize = prgRanges.stream()
                .mapToInt(r -> (int) (r.fileStart() + r.block().getSize()))
                .max().orElse(0);
        int totalPrgSize = program.getOptions("NES ROM")
                                  .getInt("PRG ROM Size", mappedPrgSize);

        CdlFile cdl;
        try (FileInputStream fis = new FileInputStream(cdlFile)) {
            cdl = CdlFile.parse(fis, totalPrgSize);
        } catch (IOException e) {
            log.appendException(e);
            return false;
        }

        log.appendMsg(NAME, "Applying CDL hints from " + cdlFile.getName()
            + " (" + totalPrgSize + " bytes PRG)…");

        applyCdlHints(program, prgRanges, cdl, monitor, log);
        return true;
    }

    // -------------------------------------------------------------------------

    /** A PRG-ROM memory block together with its byte offset inside the PRG-ROM data. */
    private record PrgRange(long fileStart, MemoryBlock block) {}

    private static final Pattern BANK_NAME = Pattern.compile("PRG_BANK_(\\d+)");

    /**
     * Maps each PRG-ROM memory block (including overlay bank blocks) to the range
     * of PRG-ROM file offsets it was loaded from, based on the naming conventions
     * of the mapper implementations.  PRG_ROM_HI (NROM 16 KB mirror) is skipped
     * so hints are not applied twice.
     */
    private List<PrgRange> findPrgRanges(Memory memory) {
        List<PrgRange> ranges = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            String name = block.getName();
            if (name.equals("PRG_ROM") || name.equals("PRG_ROM_LO")) {
                ranges.add(new PrgRange(0, block));
                continue;
            }
            Matcher m = BANK_NAME.matcher(name);
            if (m.matches()) {
                int bank = Integer.parseInt(m.group(1));
                ranges.add(new PrgRange(bank * block.getSize(), block));
            }
        }
        return ranges;
    }

    private void applyCdlHints(Program program, List<PrgRange> prgRanges, CdlFile cdl,
                                TaskMonitor monitor, MessageLog log) {

        Listing listing = program.getListing();

        AddressSet codeSet = new AddressSet();
        int dataCount = 0;

        monitor.setMaximum(cdl.size());
        long processed = 0;

        for (PrgRange range : prgRanges) {
            if (monitor.isCancelled()) break;

            Address blockStart = range.block().getStart();
            long from = range.fileStart();
            long to   = Math.min(from + range.block().getSize(), cdl.size());

            for (long i = from; i < to; i++) {
                if (monitor.isCancelled()) break;
                monitor.setProgress(processed++);

                Address addr = blockStart.add(i - from);

                if (cdl.isCode((int) i)) {
                    codeSet.add(addr);
                } else if (cdl.isData((int) i) && listing.getUndefinedDataAt(addr) != null) {
                    CreateDataCmd cmd = new CreateDataCmd(addr, ByteDataType.dataType);
                    cmd.applyTo(program);
                    dataCount++;
                }
            }
        }

        if (!codeSet.isEmpty()) {
            log.appendMsg(NAME, "Disassembling " + codeSet.getNumAddresses() + " code bytes…");
            DisassembleCommand disCmd = new DisassembleCommand(codeSet, null, true);
            disCmd.applyTo(program, monitor);
        }

        log.appendMsg(NAME, "CDL applied: "
            + codeSet.getNumAddresses() + " code, " + dataCount + " data bytes.");
    }
}
