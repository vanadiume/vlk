module target

// The x86-64 machinery a container asks for: the register file's two tables and
// the ten encoders of `Encoders`. A linker places code somebody else wrote, so
// what it needs is the handful of instructions that carry a reference, not an
// instruction set to compile with.
//
// Every encoding here is the one the program counter relative forms use: mod 00
// with the r/m field naming the next instruction, which is how the machine
// spells a displacement from where the instruction ends.

// registers is the general register file. A container looks a name up to learn
// the number an encoding uses, and both spellings of a register are listed so
// that either one answers.
pub fn registers() []Register {
	return [
		Register{
			name:      'eax'
			wide_name: 'rax'
			code:      0
			width:     4
		},
		Register{
			name:      'ecx'
			wide_name: 'rcx'
			code:      1
			width:     4
		},
		Register{
			name:      'edx'
			wide_name: 'rdx'
			code:      2
			width:     4
		},
		Register{
			name:      'ebx'
			wide_name: 'rbx'
			code:      3
			width:     4
		},
		Register{
			name:      'esp'
			wide_name: 'rsp'
			code:      4
			width:     4
		},
		Register{
			name:      'ebp'
			wide_name: 'rbp'
			code:      5
			width:     4
		},
		Register{
			name:      'esi'
			wide_name: 'rsi'
			code:      6
			width:     4
		},
		Register{
			name:      'edi'
			wide_name: 'rdi'
			code:      7
			width:     4
		},
		Register{
			name:      'r8d'
			wide_name: 'r8'
			code:      8
			width:     4
		},
		Register{
			name:      'r9d'
			wide_name: 'r9'
			code:      9
			width:     4
		},
		Register{
			name:      'r10d'
			wide_name: 'r10'
			code:      10
			width:     4
		},
		Register{
			name:      'r11d'
			wide_name: 'r11'
			code:      11
			width:     4
		},
		Register{
			name:      'r12d'
			wide_name: 'r12'
			code:      12
			width:     4
		},
		Register{
			name:      'r13d'
			wide_name: 'r13'
			code:      13
			width:     4
		},
		Register{
			name:      'r14d'
			wide_name: 'r14'
			code:      14
			width:     4
		},
		Register{
			name:      'r15d'
			wide_name: 'r15'
			code:      15
			width:     4
		},
	]
}

// float_registers is the second file, the one a double is read and written in.
// The eight that a constant's move can name are the eight listed: the encoding
// has room for a register field of three bits.
pub fn float_registers() []Register {
	return [
		Register{
			name:      'xmm0'
			wide_name: 'xmm0'
			code:      0
			width:     16
		},
		Register{
			name:      'xmm1'
			wide_name: 'xmm1'
			code:      1
			width:     16
		},
		Register{
			name:      'xmm2'
			wide_name: 'xmm2'
			code:      2
			width:     16
		},
		Register{
			name:      'xmm3'
			wide_name: 'xmm3'
			code:      3
			width:     16
		},
		Register{
			name:      'xmm4'
			wide_name: 'xmm4'
			code:      4
			width:     16
		},
		Register{
			name:      'xmm5'
			wide_name: 'xmm5'
			code:      5
			width:     16
		},
		Register{
			name:      'xmm6'
			wide_name: 'xmm6'
			code:      6
			width:     16
		},
		Register{
			name:      'xmm7'
			wide_name: 'xmm7'
			code:      7
			width:     16
		},
	]
}

// encoders is the instruction set a container reads from this machine. Each
// field names the encoder by its own name rather than by the method that
// dispatches to it: this module also declares `Target.call_near` and its
// siblings, and a bare name here would be ambiguous between the two.
pub fn encoders() Encoders {
	return Encoders{
		call_near:            encode_call_near
		call_slot:            encode_call_slot
		jump:                 encode_jump
		jump_slot:            encode_jump_slot
		jump_if_zero:         encode_jump_if_zero
		jump_if_not_zero:     encode_jump_if_not_zero
		address_of:           encode_address_of
		load_slot_value:      encode_load_slot_value
		load_double_constant: encode_load_double_constant
		load_float_constant:  encode_load_float_constant
	}
}

// bytes_with_displacement is an instruction's opcode bytes with the reference's
// four-byte distance after them. Every instruction a container writes has that
// shape, so the distance is written in one place.
fn bytes_with_displacement(opcode []u8, disp i32) []u8 {
	mut out := []u8{cap: opcode.len + 4}
	out << opcode
	out << displacement(disp)
	return out
}

fn displacement(value i32) []u8 {
	bits := u32(value)
	return [u8(bits & 0xff), u8((bits >> 8) & 0xff), u8((bits >> 16) & 0xff), u8((bits >> 24) & 0xff)]
}

fn encode_call_near(disp i32) []u8 {
	return bytes_with_displacement([u8(0xe8)], disp)
}

fn encode_call_slot(disp i32) []u8 {
	return bytes_with_displacement([u8(0xff), u8(0x15)], disp)
}

fn encode_jump_slot(disp i32) []u8 {
	return bytes_with_displacement([u8(0xff), u8(0x25)], disp)
}

fn encode_jump(disp i32) []u8 {
	return bytes_with_displacement([u8(0xe9)], disp)
}

// jump_if_zero and jump_if_not_zero are `je` and `jne` at their five-byte form:
// a two-byte opcode and the same four-byte distance. The short form would not
// reach a reference's distance, and its length would depend on where it points.
fn encode_jump_if_zero(disp i32) []u8 {
	return bytes_with_displacement([u8(0x0f), u8(0x84)], disp)
}

fn encode_jump_if_not_zero(disp i32) []u8 {
	return bytes_with_displacement([u8(0x0f), u8(0x85)], disp)
}

// address_of is `lea reg, [rip + disp]`: the address of a byte in the image.
fn encode_address_of(reg Register, disp i32) []u8 {
	mut rex := u8(0x48) // REX.W: the address is a wide register
	if reg.code >= 8 {
		rex |= 0x04 // REX.R reaches registers the low three bits cannot name
	}
	return bytes_with_displacement([rex, u8(0x8d), u8(((reg.code & 0x07) << 3) | 0x05)], disp)
}

// load_slot_value is `mov reg, [rip + disp]`: the value a slot holds.
fn encode_load_slot_value(reg Register, disp i32) []u8 {
	mut rex := u8(0x48) // REX.W: the value is a wide register
	if reg.code >= 8 {
		rex |= 0x04 // REX.R reaches registers the low three bits cannot name
	}
	return bytes_with_displacement([rex, u8(0x8b), u8(((reg.code & 0x07) << 3) | 0x05)], disp)
}

// load_double_constant and load_float_constant read a constant out of the image
// with the scalar moves: `movsd` and `movss`, with the two-byte 0f prefix the
// machine gives an instruction in the second opcode map.
fn encode_load_double_constant(reg Register, disp i32) ![]u8 {
	return scalar_rip_move(0xf2, reg, disp)
}

fn encode_load_float_constant(reg Register, disp i32) ![]u8 {
	return scalar_rip_move(0xf3, reg, disp)
}

fn scalar_rip_move(prefix u8, reg Register, disp i32) ![]u8 {
	if reg.width != 16 || reg.code >= 8 {
		return error('a floating constant is loaded into one of the first eight floating-point registers, and ${reg.name} is not one')
	}
	return bytes_with_displacement([prefix, u8(0x0f), u8(0x10), u8(((reg.code & 0x07) << 3) | 0x05)], disp)
}
