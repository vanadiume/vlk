# vlk

VLink is a linker library written in V. One link goes in and one image comes
out: the units a compiler emitted, or relocatable object files and archives
named on a command line, are merged into a single ELF executable or shared
object, and the bytes of that image are what the caller gets back.

It is a library first. A compiler links through it by calling `vlk.link`. A
command line tool that drives the same function, VVD, is a separate project, and
neither owns the linker's internals.

## Status

Under construction. The implementation lives in
[vcc](https://github.com/vanadiume/vcc) today, in `linking/` and in the parts of
`backend/` that only a link reads, and it is being moved here a module at a
time. Until that move finishes, `vlk.link` returns an error that says the linker
is not here yet.

Release 0.1.0 is the release that makes this a linker: vcc links through vlk and
produces images byte for byte identical to the ones its own linker produced
before the move, with the programs still running the way their tests expect.

## Shape

| Path | What lives there |
|---|---|
| `vlk.v` | the entry a caller is written against: `Target`, `Options`, `link` |
| `unit/` | one input to a link: machine code, the data it reads, the names it defines and needs, and the references left for the link to settle |
| `object/` | a relocatable object file read into a unit |
| `archive/` | an `ar` archive: its members and the index that answers a name |
| `elf/` | the container: header and section constants, the dynamic table, the writer |
| `symbols/` | the names across units: what each one means and where it is |
| `place/` | where each unit's code, data and tables land in the image |
| `reloc/` | the references, filled in once the places are known |
| `output/` | the image, wrapped for the system it runs on |
| `target/` | the machine and system facts a link cannot be written without |

## Using it

```v
import vlk

merged := vlk.link(units, vlk.Options{
	entry: 'main'
	target: vlk.Target{
		word_size: 8
		elf_machine: 62 // EM_X86_64, the number an ELF64 header carries
		page_size: 0x1000
		load_base: 0x400000
		interpreter: '/lib64/ld-linux-x86-64.so.2'
	}
	libraries: ['libc.so.6']
})!
```

`link` answers with the merged program and not with a file. Wrapping the program
in the container the system runs is `output`'s work, and the caller decides
where those bytes go. That is what lets a test read the merged image and a tool
write an executable from one result.

## Building and testing

```sh
v test .                    # the suite
v run tools/gate.vsh        # formatting, pure V, the suite, links in the documents
v fmt -w .                  # before committing
```

The tree is built and tested with V master. Anything older than the release the
README names is not checked, and V 0.5.2 in particular cannot build the compiler
that consumes this library.

## Install

```sh
v install vanadiume/vlk
```

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
