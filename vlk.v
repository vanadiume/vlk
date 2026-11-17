module vlk

import unit

// vlk is a linker library. The inputs of one link go in, the single program that
// link produces comes out, and the bytes of that program are written by `output`
// for the container the system runs.
//
// The entry is deliberately small: a caller says what the target is, where the
// output starts, and which names it records as needed, and it does not reach into
// the merge, the layout or the relocation pass to make a link happen. A compiler
// calls this function, and a command line tool calls the same function.

// Target is what a link cannot be written without knowing about the machine it
// runs on and the system it runs under. A caller fills one, so this library never
// carries a second copy of another tree's target description and a link for a
// second machine is a value rather than a branch.
//
// The fields are the ones a link reads. The instruction encoders a compiler needs
// to write code are not here: a linker places code somebody else wrote, and the
// process stub a program starts in is a unit like any other.
pub struct Target {
pub:
	// word_size is the width of a register on the machine, in bytes.
	word_size int
	// elf_machine is the number an ELF64 header carries for this machine.
	elf_machine u16
	// page_size is the unit the loader maps the image in.
	page_size u64
	// load_base is the lowest address a non-position-independent image is loaded
	// at. A shared object is placed from zero and does not use it.
	load_base u64
	// interpreter is the dynamic loader a dynamically linked image names, as a
	// path. An empty value says the caller wants an image that names none.
	interpreter string
	// base_library is the C library the image names as needed when it names one,
	// as the loader knows it rather than as a file name: `libc.so.6` on Linux.
	// Empty means the system has no such library, which is what a freestanding
	// target is.
	base_library string
	// library_dirs are the directories this system's own libraries live in, in
	// search order. The directories the command line added are Options.library_dirs
	// and are searched before these.
	library_dirs []string
}

// Options is what a caller asks a link for. The zero value is a link of what the
// units say, with the entry the caller names and no library named by the caller.
pub struct Options {
pub:
	// entry is the name of the function the process stub calls. A link none of
	// whose units defines it is refused, and that refusal is the only thing this
	// field is used for.
	entry string
	// target is the machine and system the link is for.
	target Target
	// libraries are the names the image records as shared libraries it needs, in
	// order, already resolved: the caller turned `-lm` into the name the loader
	// knows and passes that. Resolving a name to a file is the caller's work
	// because the file is read by the caller's system, not by this library.
	libraries []string
	// library_dirs are the `-L` directories the command line gave, in order.
	library_dirs []string
	// no_default_libraries says the link names no default library: no C library
	// and no runtime archive. An import nothing in the link answers is then left
	// to the loader instead of being refused.
	no_default_libraries bool
}

// link merges the units of one link into a single program. units[0] is the
// process stub, so the entry point is the first byte of its code, and every unit
// was emitted for a link rather than for a file of its own.
//
// This is the function a caller is written against, and it is the only one it
// needs: the merge, the layout, the references and the container are this
// library's business.
pub fn link(units []unit.Program, options Options) !unit.Program {
	_ = units
	_ = options
	return error('vlk has no linker yet: the merge, the layout, the references and the container are still in vcc and are moving here')
}
