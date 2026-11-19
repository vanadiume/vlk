# Roadmap

What the library has to do, in the order it is being built. A release is done
when its paragraphs are true, not when its list is checked off.

## 0.0.x: the repository and the model

Done. The documents, the manifest, the gate, `unit/` moved out of vcc's
`image/` module, `target/` filled by the caller, and the entry a caller is
written against.

## 0.1.0: the split

The library links. What is left is vcc linking through it.

Done:

- `symbols/`, `place/`, `reloc/` and `output/` moved in from vcc's `linking/`,
  with the merge's tests.
- `object/`: a relocatable object file read into a unit.
- `archive/`: `ar` archives, read for the members that answer a name.
- `elf/`: the container and the writer that turns a merged program into bytes.
- `library/` and `input/`: what a `-l` name comes to, and the paths of a link
  read into units.
- `vlk.merge`, `vlk.link` and `vlk.link_files`: the three depths a caller
  picks from.
- `elf.Kind.pie`: a position-independent executable whose addresses are offsets,
  with `PT_PHDR`, `DF_1_PIE`, and the relative relocations a loader applies.
- A field that holds a symbol's absolute address, in a pie or a shared object, is
  written as the symbol's place in the image beside an `R_X86_64_RELATIVE` entry,
  with an undefined weak name left as zero and a four-byte field refused by name.
  An entry over the code sets `DF_TEXTREL`.

Left:

- vcc builds `vlk.Options` and calls `vlk.link`, its `codegen/` imports `unit`,
  and its `linking/` and `image/` directories are gone.
- vcc's `vlk_kind` gains the `.pie` arm and `-fPIE`/`-fpie` stop being ignored,
  so a C link can ask for the kind this library writes.
- Images byte for byte identical to the ones vcc's own linker wrote before the
  move, checked across vcc's corpora, with the programs run.
- Link time for vcc's V self-build measured against lld, with the numbers in the
  README.

## 0.2.0: a linker another tree can use

- Shared objects as inputs: a name resolved out of one, and the loader entry the
  image records for it.
- Sections dropped when nothing reaches them, and identical sections folded,
  each behind a flag that is off by default.
- Errors that name the input file, the symbol, and the two places that disagree,
  because that is what a link failure is about.
- Response files and the part of a linker script that says where a section goes.

## Later

- A second machine, aarch64 Linux, behind `target/`.
- A second container, so the image writer is not a single branch.
- LTO, if a front end asks for it and the unit model can carry what it needs.
- Threads across the passes that scan units, with a measurement that says what
  they bought and what they cost in peak memory.
