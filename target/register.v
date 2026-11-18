module target

// Register is one entry of a machine's register file, as a name and as the
// number an instruction encoding uses for it. The emitter that wrote the code
// named a register by its spelling, and a container that has to write an
// instruction around a reference looks the spelling up here.
//
// A machine lists both spellings of a register whose wide and narrow forms are
// the same register at different widths: x86-64 writes `eax` in a 32-bit
// encoding and `rax` in a 64-bit one, and a caller asking for either means the
// same number. `width` is what a spelling is worth in bytes, which is what tells
// a floating-point constant's move whether the register it names is one of the
// eight that move can reach.
pub struct Register {
pub:
	name      string
	wide_name string
	// code is the register number used in instruction encodings.
	code u8
	// width is in bytes: 4 for the 32-bit name, 8 for the wide one, and 16 for
	// a floating-point register.
	width int
}

// reg answers the register a spelling names in the general file. Both spellings
// of a register answer, because a caller that wrote `eax` and one that wrote
// `rax` mean the same number.
pub fn (t &Target) reg(name string) ?Register {
	for r in t.registers {
		if r.name == name || r.wide_name == name {
			return r
		}
	}
	return none
}

// float_reg is the same lookup in the floating-point file.
pub fn (t &Target) float_reg(name string) ?Register {
	for r in t.float_registers {
		if r.name == name || r.wide_name == name {
			return r
		}
	}
	return none
}
