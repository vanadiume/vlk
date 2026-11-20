module target

// The Windows target: the machine is the one this library already describes, and
// what differs is the container. A PE image is loaded at an address the header
// names and is aligned in the file as well as in memory, so the fields the ELF
// target fills with a loader path and a C library name are filled with the
// alignment and the loader hints instead.
//
// The library search is the caller's: there is no directory on this machine that
// holds a Windows system's import libraries, so `library_dirs` is empty and a
// `-L` the command line gives is the only one a link reads.

// The machine number a COFF header carries for the AMD64 instruction set.
pub const coff_machine_amd64 = u16(0x8664)

// The subsystem values an image header carries. A console program is what a
// command line tool is, and a windowed program is what everything else that is
// started rather than loaded is.
pub const subsystem_windows_gui = u16(2)
pub const subsystem_windows_cui = u16(3)

// The loader hints a default image asks for. DYNAMIC_BASE is what makes the
// loader free to place the image somewhere other than ImageBase, which is only
// allowed when the image carries base relocations; HIGH_ENTROPY_VA is the wider
// address range for that choice; NX_COMPAT lets the loader make the stack and
// heap non-executable.
pub const dll_high_entropy_va = u16(0x0020)
pub const dll_dynamic_base = u16(0x0040)
pub const dll_nx_compat = u16(0x0100)

// windows_x86_64 is the target of an image that runs on 64-bit Windows. It is a
// function rather than a lookup because there is nothing to look up: the machine
// is fixed, and every value here is the format's rather than a system's.
pub fn windows_x86_64() Target {
	return Target{
		name:                'x86_64-windows'
		format:              .pe
		word_size:           8
		page_size:           0x1000
		load_base:           0x140000000
		coff_machine:        coff_machine_amd64
		file_alignment:      0x200
		subsystem:           subsystem_windows_cui
		dll_characteristics: dll_high_entropy_va | dll_dynamic_base | dll_nx_compat
		registers:           registers()
		float_registers:     float_registers()
		encoders:            encoders()
	}
}
