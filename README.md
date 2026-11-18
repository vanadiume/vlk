# vlk

VLink is a linker library written in V. One link goes in and one image comes
out: the units a compiler emitted, or relocatable object files and archives
named on a command line, are merged into a single ELF executable or shared
object, and the bytes of that image are what the caller gets back.

It is a library first. A compiler links through it by calling `vlk.link`. A
command line tool that drives the same function, VVD, is a separate project, and
neither owns the linker's internals.

## Status

The library links. `link_files` takes the paths of a link's inputs and writes an
executable, `link` takes units and answers the bytes, and `merge` is the same
link without the library check and without the container. The suite writes
images and runs them, so the exit status the kernel hands back is part of what
says a link worked.

What has not happened yet is vcc switching to it. vcc still links through its own
`linking/` module, and the move is done when it does not: when its `linking/` is
gone, its `image/` module is `unit/` here, and the images it produces are byte
for byte the ones it produced before the move, with the programs running the way
their tests expect.

## Shape

| Path | What lives there |
|---|---|
| `vlk.v` | the entry a caller is written against: `Target`, `Options`, `link` |
| `unit/` | one input to a link: machine code, the data it reads, the names it defines and needs, and the references left for the link to settle |
| `object/` | a relocatable object file read into a unit |
| `archive/` | an `ar` archive: its members and the index that answers a name |
| `library/` | a shared object as an input: the `-l` search, the ld scripts, and the names it defines |
| `input/` | the paths of a link, read into units |
| `elf/` | the container: header and section constants, the dynamic table, the writer |
| `symbols/` | the names across units: what each one means and where it is |
| `place/` | where each unit's code, data and tables land in the image |
| `reloc/` | the references, filled in once the places are known |
| `output/` | the image, wrapped for the system it runs on |
| `target/` | the machine and system facts a link cannot be written without |

## Using it

There are three depths, and a caller takes the one it wants.

```v
import vanadiume.vlk

// A path in, a file out. Each input is read as an object, an archive or a
// shared object, and the image is written where `output` names.
report := vlk.link_files(['start.o', 'main.o', 'libhelper.a'], vlk.Options{
	entry: 'main'
	target: vlk.Target{ /* the machine and system facts */ }
	output: 'prog'
})!
```

```v
// Units in, bytes out: the same link for a caller that already has the units or
// keeps the image somewhere else.
bytes := vlk.link(units, vlk.Options{
	entry: 'main'
	target: vlk.Target{}
})!
```

```v
// One step down: the names, the layout and the references, and the names a
// library still has to answer. No file is read here.
merged := vlk.merge(units, vlk.Options{
	entry: 'main'
})!
```

Under those, the passes are public and take the state they read, for a caller
with a layout or a reference policy of its own: `symbols.collect`,
`place.lay` and `reloc`.

The import path is the name the package is published under; the identifiers a
program writes are the module names, `vlk` and `unit`. A checkout linked into
`~/.vmodules/vlk` rather than installed through the registry is imported as
plain `vlk` and `vlk.unit`, which is what a program in this tree uses.

## Building and testing

```sh
v test .                    # the suite
v -gc none test .           # the same with no collector, which is how a consumer is built
v run tools/gate.vsh        # formatting, pure V, both suites, links in the documents
v fmt -w .                  # before committing
```

The library uses no garbage collector. It is compiled into programs that are
built with `-gc none`, so nothing here may depend on a collection running, and
the gate runs the suite both ways.

The tree is built and tested with V master. Anything older than the release the
README names is not checked, and V 0.5.2 in particular cannot build the compiler
that consumes this library.

## Install

```sh
v install vanadiume.vlk
```

The registry name carries the author's name and is what `v install` takes; the
repository is https://github.com/vanadiume/vlk. `v install vanadiume/vlk` is not
the same name and the registry answers that it does not exist.

To work on the library against a consumer in the same checkout, install it as a
link rather than a copy:

```sh
ln -sfn ~/vanadium/vlk ~/.vmodules/vlk
```

## Related

- [vcc](https://github.com/vanadiume/vcc) is the C compiler that links through
  this library.
- [libvcc](https://github.com/vanadiume/libvcc) is vcc's runtime library.

## Licence

BSD 3-Clause. See [LICENSE](LICENSE).
