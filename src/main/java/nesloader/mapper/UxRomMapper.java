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
 * UxROM — mapper 2, and its Camerica clone — mapper 71.
 *
 * Switchable 16 KB bank at $8000 (bank 0 selected here by default),
 * last bank fixed at $C000.  Remaining switchable banks are loaded as
 * overlay blocks so that all code is accessible for static analysis
 * regardless of runtime bank state.
 *
 * Mapper 71 differs from UxROM only in the bank-select register range and
 * mirroring control; the CPU address layout is identical.
 *
 * References:
 *   https://www.nesdev.org/wiki/UxROM
 *   https://www.nesdev.org/wiki/INES_Mapper_071
 */
public class UxRomMapper implements Mapper {

    private final int mapperNumber;

    public UxRomMapper(int mapperNumber) {
        this.mapperNumber = mapperNumber;
    }

    @Override
    public int getMapperNumber() { return mapperNumber; }

    @Override
    public void mapMemory(Program program, ByteProvider provider, INesHeader header,
                          TaskMonitor monitor, MessageLog log)
            throws IOException, AddressOverflowException {

        AddressSpace space   = program.getAddressFactory().getDefaultAddressSpace();
        int prgOffset        = header.getPrgRomOffset();
        int bankSize         = INesHeader.PRG_BANK_SIZE;
        int numBanks         = header.getPrgRomBanks();

        // Switchable low bank (bank 0 by default) at $8000
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
