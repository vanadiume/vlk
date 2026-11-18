module target

// Encoders is the instruction set a container needs and no more: the ten
// instructions that put a reference into an image and the two lookups that turn
// a register's spelling into its number.
//
// The emitter that wrote the code already chose its instructions, so a link
// reads almost none of the machine. What it does read is the handful below: a
// stub it writes for a library call, and the replacement it writes over a
// reference the code left as a field. Each takes the displacement the reference
// settled to, so the length of an instruction never depends on where it points.
//
// A target fills this. `target/x86_64.v` is one machine's answer, and a second
// machine is another value here rather than a branch in the container.
pub struct Encoders {
pub:
	// call_near is a call to a function in the same image, at a distance from
	// the end of the call.
	call_near fn (i32) []u8 = unsafe { nil }
	// call_slot calls the address a quadword holds, found through a
	// displacement from the instruction. It is how a call reaches a library
	// function the loader places.
	call_slot fn (i32) []u8 = unsafe { nil }
	// jump is an unconditional jump and jump_slot is the same jump through a
	// slot, which is the whole of a call stub.
	jump      fn (i32) []u8 = unsafe { nil }
	jump_slot fn (i32) []u8 = unsafe { nil }
	// jump_if_zero and jump_if_not_zero are the two conditional jumps a compiler
	// emits for a comparison, at a distance from the end of the jump.
	jump_if_zero     fn (i32) []u8 = unsafe { nil }
	jump_if_not_zero fn (i32) []u8 = unsafe { nil }
	// address_of computes the address of a byte in the image into a register,
	// and load_slot_value reads the value a slot holds into one.
	address_of      fn (Register, i32) []u8 = unsafe { nil }
	load_slot_value fn (Register, i32) []u8 = unsafe { nil }
	// load_double_constant and load_float_constant read an eight- and a
	// four-byte floating constant out of the read-only data into a register.
	load_double_constant fn (Register, i32) ![]u8 = unsafe { nil }
	load_float_constant  fn (Register, i32) ![]u8 = unsafe { nil }
}

// check_encoders refuses a target whose instruction set is not filled in. A
// container cannot write an image without these, and a call through a nil field
// would take the process down instead of naming what the target is missing,
// which is the one outcome this library does not allow.
pub fn (t &Target) check_encoders() ! {
	mut missing := []string{}
	if t.encoders.call_near == unsafe { nil } {
		missing << 'call_near'
	}
	if t.encoders.call_slot == unsafe { nil } {
		missing << 'call_slot'
	}
	if t.encoders.jump == unsafe { nil } {
		missing << 'jump'
	}
	if t.encoders.jump_slot == unsafe { nil } {
		missing << 'jump_slot'
	}
	if t.encoders.jump_if_zero == unsafe { nil } {
		missing << 'jump_if_zero'
	}
	if t.encoders.jump_if_not_zero == unsafe { nil } {
		missing << 'jump_if_not_zero'
	}
	if t.encoders.address_of == unsafe { nil } {
		missing << 'address_of'
	}
	if t.encoders.load_slot_value == unsafe { nil } {
		missing << 'load_slot_value'
	}
	if t.encoders.load_double_constant == unsafe { nil } {
		missing << 'load_double_constant'
	}
	if t.encoders.load_float_constant == unsafe { nil } {
		missing << 'load_float_constant'
	}
	if missing.len > 0 {
		return error('the target ${t.name} carries no instruction encoder for ${missing.join(', ')}')
	}
}
