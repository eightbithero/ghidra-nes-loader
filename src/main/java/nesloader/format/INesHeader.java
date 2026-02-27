package nesloader.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * Parser for the iNES ROM header format.
 * Reference: https://www.nesdev.org/wiki/INES
 */
public class INesHeader {

    /** Magic bytes: "NES" + MS-DOS EOF marker */
    private static final byte[] MAGIC = { 0x4E, 0x45, 0x53, 0x1A };

    public static final int HEADER_SIZE  = 16;
    public static final int TRAINER_SIZE = 512;
    public static final int PRG_BANK_SIZE = 16 * 1024;  // 16 KB
    public static final int CHR_BANK_SIZE =  8 * 1024;  //  8 KB

    private final int prgRomBanks;       // number of 16 KB PRG-ROM banks
    private final int chrRomBanks;       // number of 8 KB CHR-ROM banks (0 = CHR-RAM)
    private final int mapperNumber;
    private final boolean hasTrainer;
    private final boolean hasBattery;
    private final boolean verticalMirroring;
    private final boolean fourScreenVram;

    private INesHeader(int prgRomBanks, int chrRomBanks, int mapperNumber,
                       boolean hasTrainer, boolean hasBattery,
                       boolean verticalMirroring, boolean fourScreenVram) {
        this.prgRomBanks     = prgRomBanks;
        this.chrRomBanks     = chrRomBanks;
        this.mapperNumber    = mapperNumber;
        this.hasTrainer      = hasTrainer;
        this.hasBattery      = hasBattery;
        this.verticalMirroring = verticalMirroring;
        this.fourScreenVram  = fourScreenVram;
    }

    /** Returns true if the provider contains a valid iNES magic header. */
    public static boolean isValid(BinaryReader reader) throws IOException {
        if (reader.length() < HEADER_SIZE) return false;
        byte[] magic = reader.readByteArray(0, 4);
        return magic[0] == MAGIC[0] && magic[1] == MAGIC[1]
            && magic[2] == MAGIC[2] && magic[3] == MAGIC[3];
    }

    /** Parses the 16-byte iNES header from the reader. */
    public static INesHeader parse(BinaryReader reader) throws IOException {
        reader.setPointerIndex(4);
        int prgRomBanks = reader.readNextUnsignedByte();
        int chrRomBanks = reader.readNextUnsignedByte();
        int flags6      = reader.readNextUnsignedByte();
        int flags7      = reader.readNextUnsignedByte();

        int mapperNumber      = ((flags6 >> 4) & 0x0F) | (flags7 & 0xF0);
        boolean hasTrainer    = (flags6 & 0x04) != 0;
        boolean hasBattery    = (flags6 & 0x02) != 0;
        boolean vertMirroring = (flags6 & 0x01) != 0;
        boolean fourScreen    = (flags6 & 0x08) != 0;

        return new INesHeader(prgRomBanks, chrRomBanks, mapperNumber,
                              hasTrainer, hasBattery, vertMirroring, fourScreen);
    }

    public int  getPrgRomBanks()       { return prgRomBanks; }
    public int  getChrRomBanks()       { return chrRomBanks; }
    public int  getMapperNumber()      { return mapperNumber; }
    public boolean hasTrainer()        { return hasTrainer; }
    public boolean hasBattery()        { return hasBattery; }
    public boolean isVerticalMirroring() { return verticalMirroring; }
    public boolean isFourScreenVram()  { return fourScreenVram; }

    public int getPrgRomSize() { return prgRomBanks * PRG_BANK_SIZE; }
    public int getChrRomSize() { return chrRomBanks * CHR_BANK_SIZE; }

    /** File offset where PRG-ROM data begins. */
    public int getPrgRomOffset() {
        return HEADER_SIZE + (hasTrainer ? TRAINER_SIZE : 0);
    }

    /** File offset where CHR-ROM data begins. */
    public int getChrRomOffset() {
        return getPrgRomOffset() + getPrgRomSize();
    }

    @Override
    public String toString() {
        return String.format("iNES[prg=%dK chrRom=%dK mapper=%d trainer=%b battery=%b]",
            getPrgRomSize() / 1024, getChrRomSize() / 1024,
            mapperNumber, hasTrainer, hasBattery);
    }
}
