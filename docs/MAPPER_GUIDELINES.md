# Mapper development guidelines (bank-switching PRG)

Design rules for adding loader support for a new iNES mapper. Distilled from the
UxROM/71, MMC1 and AxROM reworks (2026-08); the goal is that static analysis
never sees code that is not statically guaranteed to be there.

## Principles

1. **Model the hardware, not a convenient default.** Power-on bank register
   state is undefined on most boards. A "default bank" resident in the default
   address space is a fiction: static references from fixed code resolve into
   it, auto-analysis disassembles another bank's data as code and builds a
   false call graph. An unresolved reference is more honest than a false one.

2. **Only hardwired banks live in the default address space.** A bank goes
   into the default space as an initialized non-overlay block *iff* the
   hardware maps it there unconditionally (UxROM/71 and fix-last MMC1: last
   16 KB bank at `$C000`). Vectors are then readable statically. Fixed windows
   may be two, zero, or at the bottom — this knowledge belongs to the mapper's
   `mapMemory`, nowhere else.

3. **Every switchable bank — including bank 0 — is an overlay block** based at
   the window address, all identical: `PRG_BANK_<n>`, contents = file slice
   `prgOffset + n * bankSize`. No bank is privileged.

4. **The switchable window in the default space:**
   - If fixed code exists that references window addresses (UxROM, MMC1):
     create an **uninitialized** non-overlay block (`PRG_WINDOW`) covering the
     window. Addresses stay valid (references don't dangle), but there are no
     bytes for auto-analysis to misinterpret.
   - If the entire `$8000-$FFFF` switches and nothing fixed remains (AxROM):
     create **nothing** above the RAM/register blocks. A bare 16-bit address
     must not silently resolve into anybody's code.

5. **Block naming is a contract.** `PRG_BANK_<n>` (and `PRG_WINDOW`) are
   relied upon by:
   - `CdlAnalyzer` — file offset is computed as `n * block.getSize()`; this
     assumes uniform bank size equal to the block size;
   - `NesExporter` — segment/MEMORY names, `PRG_` prefix selection;
   - the ai-assisted-reverse workflow — `bank_prefix` in `project.json` and
     canonical `PRG_BANK_3::9a2f` addresses in decision journals.
   Do not invent new naming schemes per mapper.

## What the shared code already handles (do not duplicate in mappers)

- **Vectors** (`NesAnalyzer`): mapper-agnostic. Default-space pass runs only
  when an initialized block covers `$FFFA`. Additionally, *every* overlay
  block whose offset range covers `$FFFA-$FFFF` gets its own per-bank pass:
  handlers named `RESET_BANK<n>` / `NMI_Handler_BANK<n>` / `IRQ_Handler_BANK<n>`,
  created in the bank's own overlay space; a target outside the bank's range
  (e.g. an NMI stub in RAM) resolves to the default space. A vector pointing
  into uninitialized memory gets a label + entry point but **no function**.
- **Vector labels** (`NesLoader.labelVectors`): `VEC_*` are placed in every
  space that actually maps the table — skip-if-unmapped is already there.
- **Exporter** (`NesExporter`):
  - uninitialized `PRG_` blocks are excluded from `.cfg` (a fill region would
    inject phantom bytes into the rebuilt ROM);
  - symbols living in the window and synthetic `LAB_` flow targets pointing
    there are emitted as `name := $addr` equates;
  - ROM byte order = `collectPrgBlocks` order: non-overlay blocks below
    `$C000`, then overlays sorted by trailing number, then non-overlay blocks
    at `$C000+`. A new mapper's layout must reproduce the original file order
    under this rule — verify with the byte-identity check below;
  - raw bank emission iterates by offset from block start (a bank ending at
    `$FFFF` sits on the address-space boundary; `addr.add()` past it throws).

## Checklist for a new mapper

Answer first (nesdev wiki + `ai-assisted-reverse/reference/08-nes-platform.md` §3):
window size/count and bank count; which windows are hardwired and where;
CHR ROM or RAM; bus conflicts (affects how bank-switch code looks, not layout).

Then:
1. Mapper class in `nesloader/mapper/` implementing `Mapper.mapMemory` per the
   principles above; register the iNES number in `NesLoader.getMapper`.
2. If bank size ≠ block size or windows are non-uniform, check the
   `CdlAnalyzer` offset formula and `collectPrgBlocks` ordering still hold —
   extend them, don't fork the naming. Worked example: `Mmc3Mapper` — 8 KB
   banks, a single 24 KB `PRG_WINDOW` over the three switchable windows
   `$8000/$A000/$C000`, only the hardwired last bank at `$E000` in the
   default space; the always-resident second-to-last bank stays an overlay
   because its position depends on a runtime mode bit.
3. Verify (headless recipe below): block map, per-bank vectors, zero
   instructions in the default-space window, export round-trip byte-identical.

## Verification recipe (headless)

```sh
gradle buildExtension
rm -rf ~/Library/ghidra/ghidra_11.4.2_PUBLIC/Extensions/ghidra-nes-loader
unzip -q dist/ghidra_11.4.2_PUBLIC_*_ghidra-nes-loader.zip \
      -d ~/Library/ghidra/ghidra_11.4.2_PUBLIC/Extensions/
# support/launch.properties has a JDWP agent on port 5005; while the Ghidra
# GUI is running, headless fails to bind — comment the VMARGS line for the
# run and RESTORE it afterwards.
support/analyzeHeadless <proj> <name> -import game.nes -loader NesLoader \
      -postScript DumpLayout.java -scriptPath <dir>
```

Checks: overlay-space count equals bank count (`get_address_spaces` via
ghidra-mcp shows the same); the window block (if any) is uninitialized; no
disassembled instructions in the default space inside the window; vectors
resolved in the fixed bank and/or per overlay bank. Then export via the
`NesExporter` (options: source `.nes` path for CHR), assemble with
`ca65/ld65 -C <name>.cfg` (2.18, `/opt/homebrew/bin`) and `cmp` against the
original ROM — must be byte-identical.

Reference ROMs used so far: mapper 1 — `snkrnr.nes.nes` (repo root, 2 banks),
mapper 71 — Micro Machines (16 banks), mapper 7 — Solar Jetman (8 banks),
both in `~/workbench/sj_decomp/`; mapper 4 — Kirby's Adventure
(`~/workbench/ka_decomp/`, 64 × 8 KB banks, NES 2.0 header, battery SRAM).
