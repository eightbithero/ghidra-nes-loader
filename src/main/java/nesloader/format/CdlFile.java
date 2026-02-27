package nesloader.format;

import java.io.IOException;
import java.io.InputStream;

/**
 * Parser for Code/Data Logger (CDL) files.
 *
 * CDL files are produced by NES emulators (FCEUX, Mesen) and record, for each
 * byte of PRG-ROM, whether it was executed as code or accessed as data during
 * a gameplay session. One CDL byte corresponds to one PRG-ROM byte.
 *
 * Bit layout (FCEUX compatible):
 *   bit 0 - CODE      : byte was fetched as an opcode
 *   bit 1 - DATA      : byte was read as operand/data
 *   bit 2 - PCM_AUDIO : byte was streamed via DMC
 *   bit 3 - INDIRECT  : data referenced indirectly by code
 *   bits 6-7 - BANK   : which 16 KB bank was mapped when the access occurred
 */
public class CdlFile {

    public static final int FLAG_CODE      = 0x01;
    public static final int FLAG_DATA      = 0x02;
    public static final int FLAG_PCM_AUDIO = 0x04;
    public static final int FLAG_INDIRECT  = 0x08;
    public static final int FLAG_BANK_MASK = 0xC0;
    public static final int FLAG_BANK_SHIFT = 6;

    private final byte[] data;

    private CdlFile(byte[] data) {
        this.data = data;
    }

    /**
     * Reads a CDL file from the given stream.
     *
     * @param is           input stream of the CDL file
     * @param expectedSize expected byte count (must equal PRG-ROM size)
     * @throws IOException if the file cannot be read or its size is wrong
     */
    public static CdlFile parse(InputStream is, int expectedSize) throws IOException {
        byte[] data = is.readAllBytes();
        if (data.length != expectedSize) {
            throw new IOException(String.format(
                "CDL size mismatch: expected %d bytes, got %d", expectedSize, data.length));
        }
        return new CdlFile(data);
    }

    public boolean isCode(int offset)     { return check(offset, FLAG_CODE); }
    public boolean isData(int offset)     { return check(offset, FLAG_DATA); }
    public boolean isPcmAudio(int offset) { return check(offset, FLAG_PCM_AUDIO); }
    public boolean isIndirect(int offset) { return check(offset, FLAG_INDIRECT); }
    public boolean isUnknown(int offset)  { return offset < data.length && data[offset] == 0; }

    /** Returns the bank index (0-3) recorded for this byte, or -1 if out of range. */
    public int getBank(int offset) {
        if (offset >= data.length) return -1;
        return (data[offset] & FLAG_BANK_MASK) >> FLAG_BANK_SHIFT;
    }

    public byte getFlags(int offset) {
        if (offset >= data.length) return 0;
        return data[offset];
    }

    public int size() { return data.length; }

    private boolean check(int offset, int flag) {
        return offset < data.length && (data[offset] & flag) != 0;
    }
}
