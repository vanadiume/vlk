module vlk

import target
import unit

// vlk is a linker library. The inputs of one link go in, the single program that
// link produces comes out, and the bytes of that program are written by `output`
// for the container the system runs.
//
// The entry is deliberately small: a caller says what the target is, where the
// output starts, and which names it records as needed, and it does not reach into
// the merge, the layout or the relocation pass to make a link happen. A compiler
// calls this function, and a command line tool calls the same function.

// Target is the machine and the system a link is for, and the one definition of
// it is `target.Target`: this library never carries a second copy of another
// tree's target description, and a link for a second machine is a value rather
// than a branch. A caller writes `vlk.Target` and fills the fields the link
// reads, because the name a caller's code is compiled against belongs here.
pub type Target = target.Target

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
