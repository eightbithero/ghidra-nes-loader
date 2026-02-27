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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import nesloader.util.NesMemoryMap;

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
        return mem.getBlock("PRG_ROM")       != null
            || mem.getBlock("PRG_ROM_LO")    != null
            || mem.getBlock("PRG_BANK_0")    != null
            || mem.getBlock("PRG_BANK_LAST") != null;
    }

    @Override
    public boolean added(Program program, AddressSetView set,
                         TaskMonitor monitor, MessageLog log) {

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Memory memory      = program.getMemory();

        resolveVector(program, memory, space, NesMemoryMap.VEC_NMI,     "NMI_Handler", log);
        resolveVector(program, memory, space, NesMemoryMap.VEC_RESET,   "RESET",        log);
        resolveVector(program, memory, space, NesMemoryMap.VEC_IRQ_BRK, "IRQ_Handler",  log);

        return true;
    }

    private void resolveVector(Program program, Memory memory, AddressSpace space,
                               long vectorAddr, String handlerName, MessageLog log) {
        try {
            Address vecAddr = space.getAddress(vectorAddr);
            int lo = Byte.toUnsignedInt(memory.getByte(vecAddr));
            int hi = Byte.toUnsignedInt(memory.getByte(vecAddr.add(1)));
            Address handlerAddr = space.getAddress((hi << 8) | lo);

            SymbolTable symbols = program.getSymbolTable();
            symbols.createLabel(handlerAddr, handlerName, SourceType.ANALYSIS);

            program.getSymbolTable().addExternalEntryPoint(handlerAddr);

            program.getFunctionManager().createFunction(
                handlerName, handlerAddr,
                new AddressSet(handlerAddr), SourceType.ANALYSIS);

        } catch (MemoryAccessException e) {
            log.appendMsg(NAME, "Vector at 0x" + Long.toHexString(vectorAddr)
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
