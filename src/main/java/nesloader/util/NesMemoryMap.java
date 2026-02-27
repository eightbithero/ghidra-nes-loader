package nesloader.util;

/**
 * NES CPU address-space constants.
 *
 * References:
 *   PPU registers : https://www.nesdev.org/wiki/PPU_registers
 *   APU registers : https://www.nesdev.org/wiki/APU_registers
 *   2A03          : https://www.nesdev.org/wiki/2A03
 */
public final class NesMemoryMap {

    private NesMemoryMap() {}

    // -------------------------------------------------------------------------
    // CPU address ranges
    // -------------------------------------------------------------------------
    public static final long RAM_START           = 0x0000;
    public static final long RAM_END             = 0x07FF;
    public static final int  RAM_SIZE            = 0x0800; // 2 KB

    public static final long PPU_REG_START       = 0x2000;
    public static final long PPU_REG_END         = 0x2007;
    public static final int  PPU_REG_SIZE        = 8;

    public static final long APU_IO_START        = 0x4000;
    public static final long APU_IO_END          = 0x4017;
    public static final int  APU_IO_SIZE         = 0x18;

    public static final long CART_EXPANSION_START = 0x4020;
    public static final long SRAM_START          = 0x6000;
    public static final long SRAM_END            = 0x7FFF;
    public static final int  SRAM_SIZE           = 0x2000; // 8 KB

    public static final long PRG_ROM_START       = 0x8000;
    public static final long PRG_ROM_END         = 0xFFFF;

    // -------------------------------------------------------------------------
    // Interrupt vectors  (little-endian 16-bit pointers)
    // -------------------------------------------------------------------------
    public static final long VEC_NMI             = 0xFFFA; // Non-Maskable Interrupt
    public static final long VEC_RESET           = 0xFFFC; // Reset
    public static final long VEC_IRQ_BRK         = 0xFFFE; // IRQ / BRK

    // -------------------------------------------------------------------------
    // PPU registers  ($2000-$2007)
    // -------------------------------------------------------------------------
    public static final long PPUCTRL             = 0x2000;
    public static final long PPUMASK             = 0x2001;
    public static final long PPUSTATUS           = 0x2002;
    public static final long OAMADDR             = 0x2003;
    public static final long OAMDATA             = 0x2004;
    public static final long PPUSCROLL           = 0x2005;
    public static final long PPUADDR             = 0x2006;
    public static final long PPUDATA             = 0x2007;

    // -------------------------------------------------------------------------
    // APU registers  ($4000-$4017)
    // -------------------------------------------------------------------------
    public static final long SQ1_VOL             = 0x4000; // Pulse 1 volume/duty
    public static final long SQ1_SWEEP           = 0x4001;
    public static final long SQ1_LO              = 0x4002;
    public static final long SQ1_HI              = 0x4003;
    public static final long SQ2_VOL             = 0x4004; // Pulse 2
    public static final long SQ2_SWEEP           = 0x4005;
    public static final long SQ2_LO              = 0x4006;
    public static final long SQ2_HI              = 0x4007;
    public static final long TRI_LINEAR          = 0x4008; // Triangle
    public static final long TRI_LO              = 0x400A;
    public static final long TRI_HI              = 0x400B;
    public static final long NOISE_VOL           = 0x400C; // Noise
    public static final long NOISE_LO            = 0x400E;
    public static final long NOISE_HI            = 0x400F;
    public static final long DMC_FREQ            = 0x4010; // Delta Modulation Channel
    public static final long DMC_RAW             = 0x4011;
    public static final long DMC_START           = 0x4012;
    public static final long DMC_LEN             = 0x4013;
    public static final long OAM_DMA             = 0x4014; // Sprite DMA
    public static final long APU_STATUS          = 0x4015;
    public static final long JOY1                = 0x4016; // Controller 1
    public static final long JOY2                = 0x4017; // Controller 2 / APU frame counter
}
