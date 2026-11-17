# Roadmap

What the library has to do, in the order it is being built. A release is done
when its paragraphs are true, not when its list is checked off.

## 0.0.x: the repository and the model

- The documents, the manifest and the gate.
- `unit/`: the model of one input, moved out of vcc's `image/` module.
- `target/`: the machine and system facts a link needs, filled by the caller.
- `vlk.link`: the entry a caller is written against, refusing until there is an
  implementation behind it.

## 0.1.0: the split

vcc links through vlk and keeps no linker of its own.

- `symbols/`, `place/`, `reloc/` and `output/` moved in from vcc's `linking/`.
- `object/`: a relocatable object file read into a unit.
- `archive/`: `ar` archives, read for the members that answer a name.
- `elf/`: the container and the writer that turns a merged program into bytes.
- Images byte for byte identical to the ones vcc's own linker wrote before the
  move, checked across vcc's corpora, with the programs run.
- Link time for vcc's V self-build measured against lld, with the numbers in the
  README.
- vcc's `linking/` deleted, and its `AGENTS.md` pointing at this library.

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
