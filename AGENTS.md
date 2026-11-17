# AGENTS.md

Instructions for coding agents working in this repository. They are the rules a
person follows, written where a tool will read them. `CONTRIBUTING.md` is the
human-facing version.

## What this repository is

vlk is a linker library written in V. The inputs of one link go in, the image
that link produces comes out, and the caller is a compiler or a command line
tool that drives one. The code here is being moved out of vcc's `linking/`
module and out of the parts of vcc's `backend/` that only a link reads. While
that move is in progress the same file exists in both trees, and the copy here is
the one that changes first.

A library, not a program: there is no `main`, the root package is `module vlk`,
and the command line tool that drives the library is a separate project (VVD).
It is published to vpm with a `v.mod` at the root, so the module layout is not
free: `vlk` at the root, one directory per submodule, each declaring the
directory's own name. The registry entry is `vanadiume.vlk`, which installs under
`~/.vmodules/vanadiume/vlk` and is imported as `vanadiume.vlk`; the tree's own
imports are the flat ones (`import unit`), and a program in this tree writes
`vlk.link` because the module is the root of the package.

## The two constraints

1. **Pure V.** No C source, no `#include`, no `#flag`, no `C.`, and no outside
   linker invoked to do the work. This is the rule vcc is held to, and a
   compiler that keeps it cannot link through a library that does not. A test
   that needs a relocatable object as input writes it at test time into a
   scratch directory and commits none of it. The one exception is a corpus that
   is a link's input rather than the library's source, and it does not exist
   yet.

2. **Link time is part of the product, and it is measured.** The workload is a
   link of what vcc emits for V's own build: hundreds of units, megabytes of
   machine code. Wall time and peak memory both count, and the reference is lld
   on the same inputs. Never claim a change is faster or slower from the shape
   of the code; run it and print the number.

## Commands

```sh
v test .                  # the suite; a test sits beside the module it tests
v run tools/gate.vsh      # formatting, pure V, the suite, links between documents
v fmt -w .                # format before committing
```

The gate is what a pull request has to pass. Run it before claiming a change is
done rather than after CI says otherwise. Compiling or testing a tree you did
not just write: cap the compiler, so a parse loop cannot take the machine down.

```sh
systemd-run --user --scope -p MemoryMax=4G -p MemorySwapMax=0 v test .
```

## Where things go

| Path | Rule |
|---|---|
| `vlk.v` | the entry a caller is written against: `Target`, `Options`, `link`. Nothing else belongs here, because this is the file a caller's code is compiled against. |
| `unit/` | the model of one input: text, data, the names defined and needed, and the references left to settle. Holds no target facts and reads no file. |
| `object/` | a relocatable object file in, a unit out. The only place that reads ELF as input. |
| `archive/` | an `ar` archive: its members, and the index that says which member answers a name. |
| `elf/` | the container format: constants, headers, sections, the dynamic table, and the code that writes an image. |
| `symbols/` | names across units: what each means, which one wins, and where it is. Never scans a list where a map answers. |
| `place/` | the layout: where each unit's code, data and tables land. Decides no reference. |
| `reloc/` | the references: fixups inside instructions, relocations inside data, filled in once the places are known. |
| `output/` | the image: one program wrapped for the system it runs on. |
| `target/` | the machine and system facts a link needs: word size, machine number, page size, load base, loader. Filled by the caller, so a link is never written against one system's constants. |
| `tools/` | the gate. Not part of the library and not imported by it. |

Tests sit beside their module as `*_test.v`. A test that needs an input file
generates it, so the repository holds no binary fixture.

## What this is working toward

The split: vcc calls `vlk.link` and keeps no linker of its own. The move is done
when vcc's `linking/` directory is gone, its `image/` module is `vlk.unit`, the
gate of both trees is green, and the images vcc produces are byte for byte the
ones it produced before the move. A change is judged by whether it moves a link
toward that, or toward a linker that is correct on input neither tree has
written yet.

## Verification

- Run the artifact, do not infer it. A link is verified by reading the bytes it
  wrote and running the program they describe.
- Compare against something that did not come from this tree. The move is
  checked byte for byte against the images vcc's own linker wrote; a new
  feature is checked against lld's output for the same inputs, or against the
  format's definition when lld disagrees with the definition.
- An error is part of the interface. An input the library cannot handle exits
  with the input and the reason; a silently written image with a reference left
  at zero is the worst outcome available and is treated as a bug.
- V caches aggressively. `-nocache` on a probe run, and remember that a binary
  built before an edit reports the previous source's problems.
- Long and malformed input are both test cases. A link reads files other
  programs wrote, so a length field and an offset from an input are read through
  bounds and not through trust.

## Agent working state

Anything written for one agent run lives in `.omh/`, which is git-ignored: plans,
probes, captured matrices, review notes and scratch. None of it is committed, and
no harness, lane checklist or golden generator written to check a single change
belongs in this tree. A repository keeps the tests its maintainers will run.

## Prose

Comments, commit bodies, pull request text and the markdown here are read by
people. Write them the way you would say them out loud: plain sentences,
specific claims. This binds text an agent writes as much as text a person
writes.

- No em dashes. A comma, a colon, or a full stop is usually what was meant.
- No "serves as", "stands as", or the vocabulary that inflates what code does
  into what it means.
- No three-item list assembled to sound thorough, and no synonym carousel where
  one thing is first a layer, then a stage, then a component.
- No bolded label at the start of every bullet, no signposting before the
  point, and no upbeat close.
- When the claim is a measurement, print the number and the command that
  produced it. An adjective is not evidence.

## Commits

`area: what changed`, lowercase, no trailing period, and a body that says why.
One logical change per commit, each one building on its own. Areas in use:
`vlk`, `unit`, `object`, `archive`, `elf`, `symbols`, `place`, `reloc`,
`output`, `target`, `tools`, `tree`, `docs`.

## Do not

- Add a dependency to `v.mod` without raising it first. Empty dependencies is a
  feature here.
- Reformat or refactor files the change does not touch.
- Weaken a test, an assertion, or a diagnostic to make a change land.
- Commit a binary fixture, or a generator written to check one change.
