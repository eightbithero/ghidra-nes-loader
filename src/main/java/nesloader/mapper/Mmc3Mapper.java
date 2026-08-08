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
 * MMC3 (TxROM) — mapper 4.
 *
 * PRG is switched in 8 KB banks across four windows.  Only $E000-$FFFF is
 * hardwired (last bank — interrupt vectors live there).  The second-to-last
 * bank is always resident, but its position ($8000 or $C000) depends on a
 * runtime mode bit, so it is NOT placed in the default address space: only
 * unconditionally fixed banks are.  $8000-$DFFF is an uninitialized
 * PRG_WINDOW block (addresses stay valid, no bytes to misinterpret), and
 * every switchable bank — including the second-to-last — is an overlay
 * block based at $8000.  The $8000 base is a convention (a bank may run at
 * $8000, $A000 or $C000; refine per game via Mesen / bank_windows).
 *
 * Reference: https://www.nesdev.org/wiki/MMC3
 */
public class Mmc3Mapper implements Mapper {

    /** MMC3 switches 8 KB at a time — half an iNES 16 KB PRG unit. */
    private static final int BANK_SIZE = INesHeader.PRG_BANK_SIZE / 2;

    @Override
    public int getMapperNumber() { return 4; }

    @Override
    public void mapMemory(Program program, ByteProvider provider, INesHeader header,
                          TaskMonitor monitor, MessageLog log)
            throws IOException, AddressOverflowException {

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        int prgOffset      = header.getPrgRomOffset();
        int numBanks       = header.getPrgRomBanks() * 2;

        if (numBanks == 0) {
            log.appendMsg("Mmc3Mapper", "PRG-ROM smaller than one 8 KB bank; nothing mapped.");
            return;
        }

        // Switchable windows $8000/$A000/$C000: which bank sits where depends
        // on runtime register state, so no default bank — an uninitialized
        // block keeps the addresses valid without giving auto-analysis bytes
        // to misinterpret.
        Address addr8000 = space.getAddress(0x8000);
        MemoryBlockUtils.createUninitializedBlock(program, false, "PRG_WINDOW", addr8000,
            3 * BANK_SIZE,
            "PRG-ROM switchable windows $8000-$DFFF (no default banks — runtime-dependent)",
            "NES Loader", true, false, true, log);

        // Hardwired last bank at $E000
        int lastBank = numBanks - 1;
        Address addrE000 = space.getAddress(0xE000);
        MemoryBlockUtils.createInitializedBlock(program, false,
            String.format("PRG_BANK_%d", lastBank), addrE000,
            provider.getInputStream(prgOffset + (long) lastBank * BANK_SIZE), BANK_SIZE,
            "PRG-ROM last bank (fixed at $E000)", "NES Loader",
            true, false, true, log, monitor);

        // All switchable banks (including the second-to-last) as overlays at $8000
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
