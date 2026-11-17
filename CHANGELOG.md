# Changelog

Changes a caller can see. The library follows Semantic Versioning, and a version
number moves when a released tag does.

## Unreleased

### Added

- The repository: the manifest `vpm` reads, the licence, and the documents that
  say what the library is, how a change is checked, and what the tree is working
  toward.
- `unit/`: the model of one input to a link, moved from vcc's `image/` module.
- `vlk.Target`, `vlk.Options` and `vlk.link`, the entry a caller is written
  against. `link` refuses until the implementation moves.
