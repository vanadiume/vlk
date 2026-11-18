# Changelog

Changes a caller can see. The library follows Semantic Versioning, and a version
number moves when a released tag does.

## Unreleased

### Added

- The repository: the manifest `vpm` reads, the licence, and the documents that
  say what the library is, how a change is checked, and what the tree is working
  toward.
- `unit/`: the model of one input to a link, moved from vcc's `image/` module.
- `vlk.Target` and `vlk.Options`: the machine and system facts a link is for, and
  the request a caller makes of one.
- `tools/gate.vsh`: formatting, the pure-V rule, the suite both with and
  without a garbage collector, and the relative links in the documents, in one
  command.
- `symbols/`, `place/` and `reloc/`: the merge's three passes, public and taking
  the state they read.
- `vlk.merge`: one link without the library check and without the container,
  answering the merged program and the names a library has to answer.
- `target/`: the machine and system facts a link reads, the instruction encoders
  a container writes with, and `host()` for the machine the library runs on.
  `vlk.Target` is an alias for it.
- `archive/`: `ar` archives, read for their members and the index that answers a
  name.
- `object/`: a relocatable object file read into a unit.
- `elf/`: the container, the image writer, and the relocatable writer.
- `output/`: the seam a merged program is wrapped through.
- `library/`: the `-l` search, GNU ld scripts, sonames, and the dynamic symbol
  reader that says whether a library defines a name.
- `input/`: the paths of a link, read into units, with an archive's members
  pulled for the names nothing defines yet.
- `vlk.link`: units in, the bytes of the image out.
- `vlk.link_files`: paths in, an executable written, and a report of what the
  link took.
- The suite writes images and runs them: the container's tests run two programs
  and read their exit statuses, and a link of a hand-built unit, an object file
  and an archive member are each executed after they are written.
- No garbage collector: the library is built the way its consumers are, and the
  gate runs the suite under `-gc none` as well as the default.
