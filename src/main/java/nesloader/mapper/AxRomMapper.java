package nesloader.mapper;

import java.io.IOException;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.util.task.TaskMonitor;
import nesloader.format.INesHeader;

/**
 * AxROM — mapper 7.
 *
 * The whole $8000-$FFFF range is a single switchable 32 KB bank; there is
 * no fixed bank and the power-on bank register state is undefined.  The
 * last bank is loaded as the primary (non-overlay) block, since startup
 * code and the "real" interrupt vectors usually live there; all other
 * banks are loaded as overlay blocks at $8000.
 *
 * Bank selection is done by writing to $8000-$FFFF; single-screen
 * mirroring control does not affect the CPU address layout.
 *
 * Reference: https://www.nesdev.org/wiki/AxROM
 */
public class AxRomMapper implements Mapper {

    /** AxROM switches 32 KB at a time — two iNES 16 KB PRG units per bank. */
    private static final int BANK_SIZE = 2 * INesHeader.PRG_BANK_SIZE;

    @Override
    public int getMapperNumber() { return 7; }

    @Override
    public void mapMemory(Program program, ByteProvider provider, INesHeader header,
                          TaskMonitor monitor, MessageLog log)
            throws IOException, AddressOverflowException {

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        int prgOffset      = header.getPrgRomOffset();
        int prgUnits       = header.getPrgRomBanks();

        if (prgUnits % 2 != 0) {
            log.appendMsg("AxRomMapper", String.format(
                "PRG-ROM size (%d x 16 KB) is not a multiple of 32 KB; "
                + "trailing 16 KB is ignored.", prgUnits));
        }

        int numBanks = prgUnits / 2;
        if (numBanks == 0) {
            log.appendMsg("AxRomMapper", "PRG-ROM smaller than one 32 KB bank; nothing mapped.");
            return;
        }

        Address addr8000 = space.getAddress(0x8000);

        // Primary block: last bank — startup code and vectors usually live here
        int lastBank = numBanks - 1;
        MemoryBlockUtils.createInitializedBlock(program, false,
            String.format("PRG_BANK_%d", lastBank), addr8000,
            provider.getInputStream(prgOffset + (long) lastBank * BANK_SIZE), BANK_SIZE,
            "PRG-ROM last bank (switchable, default)", "NES Loader",
            true, false, true, log, monitor);

        // Remaining switchable banks as overlays at $8000
        for (int i = 0; i < lastBank; i++) {
            if (monitor.isCancelled()) break;
            long offset    = prgOffset + (long) i * BANK_SIZE;
            String name    = String.format("PRG_BANK_%d", i);
            String comment = String.format("PRG-ROM bank %d (switchable, overlay)", i);

            MemoryBlockUtils.createInitializedBlock(program, true, name, addr8000,
                provider.getInputStream(offset), BANK_SIZE,
                comment, "NES Loader", true, false, true, log, monitor);
        }
    }
}
