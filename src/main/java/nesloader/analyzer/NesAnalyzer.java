package nesloader.analyzer;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import nesloader.util.NesMemoryMap;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes NES interrupt vectors (NMI / RESET / IRQ-BRK) and creates entry-point
 * functions at the addresses they point to.
 *
 * This analyzer runs at BLOCK_ANALYSIS priority so that the auto-disassembler
 * picks up the handler functions before the default code-sweep.
 */
public class NesAnalyzer extends AbstractAnalyzer {

    private static final String NAME        = "NES ROM Analyzer";
    private static final String DESCRIPTION =
        "Resolves NMI, RESET, and IRQ/BRK interrupt vectors and creates entry functions.";

    public NesAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
        setDefaultEnablement(true);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return true;
    }

    @Override
    public boolean canAnalyze(Program program) {
        // Run only when a PRG-ROM block is present (set by NesLoader)
        Memory mem = program.getMemory();
        return mem.getBlock("PRG_ROM")    != null
            || mem.getBlock("PRG_ROM_LO") != null
            || mem.getBlock("PRG_BANK_0") != null
            || mem.getBlock("PRG_WINDOW") != null;
    }

    private static final Pattern BANK_NAME = Pattern.compile("PRG_BANK_(\\d+)");

    @Override
    public boolean added(Program program, AddressSetView set,
                         TaskMonitor monitor, MessageLog log) {

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Memory memory      = program.getMemory();

        // Fixed-bank layouts: the vector table lives in an initialized
        // default-space block (NROM, UxROM/71, MMC1, ...).
        MemoryBlock defBlock = memory.getBlock(space.getAddress(NesMemoryMap.VEC_NMI));
        if (defBlock != null && defBlock.isInitialized()) {
            resolveVector(program, memory, space.getAddress(NesMemoryMap.VEC_NMI),     "NMI_Handler", log);
            resolveVector(program, memory, space.getAddress(NesMemoryMap.VEC_RESET),   "RESET",       log);
            resolveVector(program, memory, space.getAddress(NesMemoryMap.VEC_IRQ_BRK), "IRQ_Handler", log);
        }

        // All-switchable layouts (e.g. AxROM): every overlay bank that covers
        // the vector table carries its own vectors — resolve them per bank.
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isOverlay() || !block.isInitialized()) continue;
            if (block.getStart().getOffset() > NesMemoryMap.VEC_NMI
                    || block.getEnd().getOffset() < NesMemoryMap.VEC_IRQ_BRK + 1) continue;

            String suffix    = bankSuffix(block.getName());
            AddressSpace ovl = block.getStart().getAddressSpace();
            resolveVector(program, memory, ovl.getAddress(NesMemoryMap.VEC_NMI),     "NMI_Handler" + suffix, log);
            resolveVector(program, memory, ovl.getAddress(NesMemoryMap.VEC_RESET),   "RESET" + suffix,       log);
            resolveVector(program, memory, ovl.getAddress(NesMemoryMap.VEC_IRQ_BRK), "IRQ_Handler" + suffix, log);
        }

        return true;
    }

    /** "PRG_BANK_3" → "_BANK3"; any other block name is used verbatim. */
    private String bankSuffix(String blockName) {
        Matcher m = BANK_NAME.matcher(blockName);
        return m.matches() ? "_BANK" + m.group(1) : "_" + blockName;
    }

    private void resolveVector(Program program, Memory memory, Address vecAddr,
                               String handlerName, MessageLog log) {
        try {
            int lo = Byte.toUnsignedInt(memory.getByte(vecAddr));
            int hi = Byte.toUnsignedInt(memory.getByte(vecAddr.add(1)));
            long target = (hi << 8) | lo;

            // A vector read from an overlay bank resolves into that bank's own
            // space when the target falls inside the bank; otherwise (RAM stub,
            // fixed-bank layouts) it resolves into the default space.
            AddressSpace vecSpace = vecAddr.getAddressSpace();
            MemoryBlock vecBlock  = memory.getBlock(vecAddr);
            Address handlerAddr;
            if (vecSpace.isOverlaySpace() && vecBlock != null
                    && target >= vecBlock.getStart().getOffset()
                    && target <= vecBlock.getEnd().getOffset()) {
                handlerAddr = vecSpace.getAddress(target);
            } else {
                handlerAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(target);
            }

            SymbolTable symbols = program.getSymbolTable();
            symbols.createLabel(handlerAddr, handlerName, SourceType.ANALYSIS);

            program.getSymbolTable().addExternalEntryPoint(handlerAddr);

            // A vector pointing into the switchable window (uninitialized
            // PRG_WINDOW) has a bank-dependent target — label it, but do not
            // create a function over memory that has no bytes.
            MemoryBlock targetBlock = memory.getBlock(handlerAddr);
            if (targetBlock == null || !targetBlock.isInitialized()) {
                log.appendMsg(NAME, handlerName + " vector targets switchable bank"
                    + " window at " + handlerAddr + " — handler is bank-dependent.");
                return;
            }

            if (program.getFunctionManager().getFunctionAt(handlerAddr) == null) {
                program.getFunctionManager().createFunction(
                    handlerName, handlerAddr,
                    new AddressSet(handlerAddr), SourceType.ANALYSIS);
            }

        } catch (MemoryAccessException e) {
            log.appendMsg(NAME, "Vector at " + vecAddr
                + " not accessible — PRG-ROM may not cover $FFFA-$FFFF.");
        } catch (Exception e) {
            log.appendMsg(NAME, "Error resolving " + handlerName + ": " + e.getMessage());
        }
    }

    @Override
    public void registerOptions(Options options, Program program) {}

    @Override
    public void optionsChanged(Options options, Program program) {}
}
