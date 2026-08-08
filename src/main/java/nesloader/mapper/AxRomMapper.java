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
 * The whole $8000-$FFFF range is a single switchable 32 KB window; there
 * is no fixed bank and the power-on bank register state is undefined, so
 * no bank lives in the default address space.  Every bank — including the
 * last one — is an equal overlay block based at $8000; the default space
 * above $8000 stays unmapped (RAM and hardware registers only).  Interrupt
 * vectors are resolved per bank by the analyzer.
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

        // All banks are equal switchable overlays at $8000 — AxROM has no
        // fixed bank, so nothing is mapped into the default address space.
        for (int i = 0; i < numBanks; i++) {
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
