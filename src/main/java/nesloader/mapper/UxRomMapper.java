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
 * UxROM — mapper 2, and its Camerica clone (BF9093) — mapper 71.
 *
 * Last 16 KB bank is hardwired at $C000; $8000-$BFFF is a switchable
 * window whose power-on bank state is undefined on real hardware, so no
 * bank is mapped there in the default address space.  Instead the window
 * is an uninitialized PRG_WINDOW block (addresses stay valid, but there
 * are no bytes for auto-analysis to misinterpret), and every switchable
 * bank — including bank 0 — is loaded as an overlay block based at $8000.
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

        // Switchable window at $8000: power-on bank state is undefined, so no
        // default bank — an uninitialized block keeps the addresses valid
        // without giving auto-analysis bytes to misinterpret.
        Address addr8000 = space.getAddress(0x8000);
        MemoryBlockUtils.createUninitializedBlock(program, false, "PRG_WINDOW", addr8000,
            bankSize,
            "PRG-ROM switchable window $8000-$BFFF (no default bank — power-on state undefined)",
            "NES Loader", true, false, true, log);

        // Fixed high bank (last) at $C000
        int lastBankOffset = prgOffset + (numBanks - 1) * bankSize;
        Address addrC000 = space.getAddress(0xC000);
        MemoryBlockUtils.createInitializedBlock(program, false,
            String.format("PRG_BANK_%d", numBanks - 1), addrC000,
            provider.getInputStream(lastBankOffset), bankSize,
            "PRG-ROM last bank (fixed)", "NES Loader",
            true, false, true, log, monitor);

        // All switchable banks (including bank 0) as overlays at $8000
        for (int i = 0; i < numBanks - 1; i++) {
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
