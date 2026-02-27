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
 * NROM — mapper 0.
 *
 * 16 KB variant: PRG-ROM is mirrored at $8000 and $C000.
 * 32 KB variant: PRG-ROM is mapped linearly from $8000 to $FFFF.
 *
 * Reference: https://www.nesdev.org/wiki/NROM
 */
public class NromMapper implements Mapper {

    @Override
    public int getMapperNumber() { return 0; }

    @Override
    public void mapMemory(Program program, ByteProvider provider, INesHeader header,
                          TaskMonitor monitor, MessageLog log)
            throws IOException, CancelledException {

        AddressSpace space   = program.getAddressFactory().getDefaultAddressSpace();
        int prgOffset        = header.getPrgRomOffset();
        int prgSize          = header.getPrgRomSize();
        int bankSize         = INesHeader.PRG_BANK_SIZE;

        if (prgSize == bankSize) {
            // 16 KB: mirror at $8000 and $C000
            Address addr8000 = space.getAddress(0x8000);
            Address addrC000 = space.getAddress(0xC000);

            MemoryBlockUtils.createInitializedBlock(program, false, "PRG_ROM_LO", addr8000,
                provider.getInputStream(prgOffset), bankSize,
                "PRG-ROM low bank", "NES Loader", true, false, true, log, monitor);

            MemoryBlockUtils.createInitializedBlock(program, false, "PRG_ROM_HI", addrC000,
                provider.getInputStream(prgOffset), bankSize,
                "PRG-ROM high bank (mirror of low)", "NES Loader", true, false, true, log, monitor);
        } else {
            // 32 KB: mapped linearly
            Address addr8000 = space.getAddress(0x8000);
            MemoryBlockUtils.createInitializedBlock(program, false, "PRG_ROM", addr8000,
                provider.getInputStream(prgOffset), prgSize,
                "PRG-ROM", "NES Loader", true, false, true, log, monitor);
        }
    }
}
