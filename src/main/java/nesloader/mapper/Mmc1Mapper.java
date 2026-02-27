package nesloader.mapper;

import java.io.IOException;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import nesloader.format.INesHeader;

/**
 * MMC1 — mapper 1.
 *
 * Power-on state: bank 0 is fixed at $8000, last bank is fixed at $C000.
 * Switchable banks (1 .. N-2) are loaded as overlay blocks so that all
 * code is accessible for static analysis regardless of runtime bank state.
 *
 * Reference: https://www.nesdev.org/wiki/MMC1
 */
public class Mmc1Mapper implements Mapper {

    @Override
    public int getMapperNumber() { return 1; }

    @Override
    public void mapMemory(Program program, ByteProvider provider, INesHeader header,
                          TaskMonitor monitor, MessageLog log)
            throws IOException, CancelledException {

        AddressSpace space   = program.getAddressFactory().getDefaultAddressSpace();
        int prgOffset        = header.getPrgRomOffset();
        int bankSize         = INesHeader.PRG_BANK_SIZE;
        int numBanks         = header.getPrgRomBanks();

        // Fixed low bank (bank 0) at $8000
        Address addr8000 = space.getAddress(0x8000);
        MemoryBlockUtils.createInitializedBlock(program, false, "PRG_BANK_0", addr8000,
            provider.getInputStream(prgOffset), bankSize,
            "PRG-ROM bank 0 (switchable, default)", "NES Loader",
            true, false, true, log, monitor);

        // Fixed high bank (last) at $C000
        int lastBankOffset = prgOffset + (numBanks - 1) * bankSize;
        Address addrC000 = space.getAddress(0xC000);
        MemoryBlockUtils.createInitializedBlock(program, false,
            String.format("PRG_BANK_%d", numBanks - 1), addrC000,
            provider.getInputStream(lastBankOffset), bankSize,
            "PRG-ROM last bank (fixed)", "NES Loader",
            true, false, true, log, monitor);

        // Remaining switchable banks as overlays at $8000
        for (int i = 1; i < numBanks - 1; i++) {
            if (monitor.isCancelled()) break;
            long offset    = prgOffset + (long) i * bankSize;
            String name    = String.format("PRG_BANK_%d", i);
            String comment = String.format("PRG-ROM bank %d (switchable, overlay)", i);

            MemoryBlockUtils.createInitializedBlock(program, true, name, addr8000,
                provider.getInputStream(offset), bankSize,
                comment, "NES Loader", true, false, true, log, monitor);
        }
    }
}
