module target

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
	// name spells the machine and the system the way a command line does, and
	// is what an error names when an input was built for another one.
	name string
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
	// registers and float_registers are the machine's two register files. A
	// container reads a register's spelling in one of them to learn the number an
	// instruction encoding uses, and the tables are the machine's rather than the
	// linker's, so a second machine fills its own.
	registers       []Register
	float_registers []Register
	// encoders are the instructions a container writes: the stub it makes for a
	// library call, and the replacement it puts over a reference the code left as
	// a field. `check_encoders` says which ones a target is missing.
	encoders Encoders
}
