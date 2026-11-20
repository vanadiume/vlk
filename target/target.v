module target

// Format is the container an image is written in. It is the one fact a link
// reads to decide which writer runs, and it is a field rather than a second kind
// of Target so that the register files, the library search and the page size are
// written once.
//
// The zero value is ELF, deliberately: a caller that builds a Target with the
// fields it was compiled against keeps the meaning it had, and a link for a
// second container is a value a caller sets rather than something every writer
// has to guess.
pub enum Format {
	elf
	pe
}

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
	// format is the container this target's images are written in. The zero
	// value is ELF, so a target built before this field existed keeps its
	// meaning and a PE link is a value rather than a branch in a writer.
	format Format = .elf
	// word_size is the width of a register on the machine, in bytes.
	word_size int
	// elf_machine is the number an ELF64 header carries for this machine, and
	// zero for a machine whose images are not ELF.
	elf_machine u16
	// coff_machine is the number a COFF header carries for this machine, and
	// zero for a machine whose objects are not COFF.
	coff_machine u16
	// file_alignment is where a PE section's bytes start in the file, and zero
	// for a container whose sections are not aligned in the file.
	file_alignment u32
	// subsystem is what a PE image tells the loader it is: a console program,
	// a windowed one, or a library the loader maps for another image. Zero for
	// a container without one.
	subsystem u16
	// dll_characteristics is the PE header's word of loader hints: whether the
	// image moves from its preferred base, whether it opts into high entropy
	// addresses, and whether its stack may be made non-executable. Zero for a
	// container without one.
	dll_characteristics u16
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
	// relocation_call, relocation_pc_relative and relocation_got_pc_relative are
	// the numbers this machine gives a reference it leaves to a link: a call to a
	// name the object does not define, a distance the code computes, and a
	// reference to an object through the global offset table. The writer of a
	// relocatable object is the one that needs them; an image written from units
	// that settled their own references carries none.
	relocation_call            u32
	relocation_pc_relative     u32
	relocation_got_pc_relative u32
	// encoders are the instructions a container writes: the stub it makes for a
	// library call, and the replacement it puts over a reference the code left as
	// a field. `check_encoders` says which ones a target is missing.
	encoders Encoders
}
