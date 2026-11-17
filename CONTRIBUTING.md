# Contributing to vlk

Thanks for wanting to help. This file says what a change has to bring with it,
how the tree is written, and the two rules that come before the rest.

- The library is pure V. No C source, no `#include`, no `#flag`, no `C.`, and no
  outside linker invoked to do the work. A test that needs a relocatable object
  writes one at test time; nothing binary is committed.
- A link's speed is part of what it is. The workload is a link of what vcc emits
  for V's own build, and the reference is lld on the same inputs. A change that
  costs time says so and says what it bought.

## Getting set up

You need V from master. The tests are the toolchain: there is no build script,
because a library has nothing to build until something imports it.

```sh
git clone https://github.com/vanadiume/vlk
cd vlk
v test .
v run tools/gate.vsh
```

`v install vanadiume.vlk` puts a copy in `~/.vmodules` under the author's name,
where it is imported as `vanadiume.vlk` and `vanadiume.vlk.unit`. While you are
working on the library, point `~/.vmodules/vlk` at your checkout instead, which
is the flat spelling a program in this tree uses:

```sh
ln -sfn "$PWD" ~/.vmodules/vlk
```

## The gate

`v run tools/gate.vsh` is what a pull request has to pass: the formatting check,
the pure-V rule, the suite, and the links between the documents at the root. A
partial run is not the gate. Run the whole thing before asking for review,
rather than after someone tells you it is red.

## Adding an input format

A reader goes in its own directory, one module per format, and answers with a
`unit.Program`: the code, the data, the names defined and needed, and the
references the link still has to settle. It reads no target beyond the one it is
handed, and it writes nothing.

1. Read the format's own definition and say in the commit body which document
   you followed when the format has one.
2. Reject what you cannot represent by name. A field you skipped silently is a
   link that produces a wrong image and says nothing.
3. Generate the input at test time. A 200-byte object built by the test is worth
   more than a fixture nobody dares change.
4. Test it twice: once as the reader sees it, and once through a link that
   produces a program, runs it, and compares the output with what the input
   promised.

## Changing the entry

`vlk.v` holds the types a caller is written against. A change to `Options`,
`Target` or `link` is a change to every caller, so it comes with the reason in
the commit body and with the caller updated in the same series, not in a later
one.

## Adding a test

Tests sit beside the module as `*_test.v`. A test has to fail when the code is
wrong: compare against something that did not come from this tree, meaning the
container's own tooling, the format's definition, or a program that was written
before it. A second copy of the algorithm proves only that the copy agrees.

Never weaken a test, an assertion, or a diagnostic to make a change land. If the
behaviour change was intended, say so in the commit body and change the
expectation there.

## Prose and commits

`area: what changed`, lowercase, no trailing period, and a body that says why.
One logical change per commit, each one building on its own. Areas in use:
`vlk`, `unit`, `object`, `archive`, `elf`, `symbols`, `place`, `reloc`,
`output`, `target`, `tools`, `tree`, `docs`.

Comments, commit bodies, pull request text and the markdown here are read by
people. Write plain sentences with specific claims. No em dashes, no "serves
as", no bolded label at the start of every bullet, and no close that tells the
reader how to feel. When the claim is a measurement, print the number and the
command that produced it.
