package nesloader.mapper;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import nesloader.format.INesHeader;

/**
 * Strategy interface for NES memory mappers.
 *
 * Each mapper is responsible for mapping PRG-ROM banks into the CPU address
 * space ($8000-$FFFF) at load time.  Because mappers switch banks at runtime,
 * loaders that support them should create overlay blocks for each switchable
 * bank so the analyst can inspect all banks without running the emulator.
 */
public interface Mapper {

    /** Returns the iNES mapper number this implementation handles. */
    int getMapperNumber();

    /**
     * Creates Ghidra memory blocks for all PRG-ROM (and optionally CHR-ROM)
     * banks described by {@code header}, reading raw bytes from {@code provider}.
     */
    void mapMemory(Program program, ByteProvider provider, INesHeader header,
                   TaskMonitor monitor, MessageLog log)
            throws IOException, CancelledException;
}
