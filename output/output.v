module output

import elf
import target
import unit

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
pub fn image(program unit.Program, machine target.Target, kind Kind, options Options) ![]u8 {
	return elf.write_options(program, machine, kind, options)
}
