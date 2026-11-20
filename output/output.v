module output

import vanadiume.vlk.elf
import vanadiume.vlk.pe
import vanadiume.vlk.target
import vanadiume.vlk.unit

// Wrapping a merged program as the bytes of an output file. It is a seam and
// deliberately thin: the container in `elf/` writes the shape the kind asks for,
// and `kind` is which one the caller named, so a program, a static program and a
// shared object reach the container from here rather than through a second path.
//
// The kind and the options a caller writes are this module's names, so a caller
// that only ever wraps an image does not have to import the container to ask for
// one.
pub type Kind = elf.Kind
pub type Options = elf.Options

// image is the bytes of the program, wrapped for the system the target describes.
// The program is the merge's answer and the target is the caller's, and nothing
// here decides what the image holds: the layout, the tables and every reference
// were settled before this call.
//
// Which writer runs is the target's answer. It is a dispatch here rather than a
// branch inside either writer, because the two containers share nothing below
// this line: an ELF image is segments and a PE image is sections, and a writer
// that held both would be the worst file in the tree to read.
pub fn image(program unit.Program, machine target.Target, kind Kind, options Options) ![]u8 {
	return match machine.format {
		.elf { elf.write_options(program, machine, kind, options) }
		.pe { pe.write(program, machine, pe_kind(kind)) }
	}
}

// pe_kind is the depth a caller asked for, as the PE container names it. A
// position-independent executable is an executable whose header says the loader
// may move it, which is what the Windows target already asks for, and a static
// program is an executable whose import directory is empty, which is a fact
// about the program rather than another kind of header.
fn pe_kind(kind Kind) pe.Kind {
	return match kind {
		.program, .static_program, .pie { pe.Kind.executable }
		.shared { pe.Kind.dll }
	}
}
