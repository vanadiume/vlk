module target

// A target is a value the caller fills, so the two things worth pinning are that
// the host's target is filled and that an empty one is refused by name rather
// than taken down by a call through nothing.

fn test_the_host_target_carries_its_register_files_and_encoders() {
	host := host() or { panic('the tests need the host target') }
	assert host.name == 'x86_64-linux'
	host.check_encoders() or { panic('the host target is missing an encoder: ${err.msg()}') }
	// Both spellings of a register answer with the number an encoding uses.
	wide := host.reg('rax') or { panic('rax is not in the register file') }
	narrow := host.reg('eax') or { panic('eax is not in the register file') }
	assert wide.code == 0
	assert narrow.code == 0
	float := host.float_reg('xmm1') or { panic('xmm1 is not in the floating-point file') }
	assert float.code == 1
	assert host.float_reg('st0') == none
}

fn test_a_target_with_no_encoders_is_refused_by_name() {
	bare := Target{}
	bare.check_encoders() or {
		assert err.msg().contains('call_near')
		assert err.msg().contains('load_float_constant')
		return
	}
	assert false, 'a target with no encoders answered'
}

// The instructions themselves, byte for byte, because a container that patched a
// reference with the wrong bytes would write an image that runs off the rails
// with nothing to say why.
fn test_the_encodings_a_container_writes() {
	e := encoders()
	assert e.call_near(0) == [u8(0xe8), 0, 0, 0, 0]
	assert e.call_near(-4) == [u8(0xe8), 0xfc, 0xff, 0xff, 0xff]
	assert e.call_slot(8) == [u8(0xff), 0x15, 8, 0, 0, 0]
	assert e.jump_slot(8) == [u8(0xff), 0x25, 8, 0, 0, 0]
	assert e.jump(8) == [u8(0xe9), 8, 0, 0, 0]
	assert e.jump_if_zero(8) == [u8(0x0f), 0x84, 8, 0, 0, 0]
	assert e.jump_if_not_zero(8) == [u8(0x0f), 0x85, 8, 0, 0, 0]
	// `lea rax, [rip + 8]`, and the same form for a register that needs REX.R.
	rax := Register{
		name: 'rax'
		code: 0
	}
	assert e.address_of(rax, 8) == [u8(0x48), 0x8d, 0x05, 8, 0, 0, 0]
	r11 := Register{
		name: 'r11'
		code: 11
	}
	assert e.address_of(r11, 0) == [u8(0x4c), 0x8d, 0x1d, 0, 0, 0, 0]
	assert e.load_slot_value(rax, 0) == [u8(0x48), 0x8b, 0x05, 0, 0, 0, 0]
	xmm0 := Register{
		name:  'xmm0'
		code:  0
		width: 16
	}
	assert e.load_double_constant(xmm0, 0) or { panic(err.msg()) } == [u8(0xf2), 0x0f, 0x10, 0x05,
		0, 0, 0, 0]
	assert e.load_float_constant(xmm0, 0) or { panic(err.msg()) } == [u8(0xf3), 0x0f, 0x10, 0x05,
		0, 0, 0, 0]
	// A floating constant cannot reach past the eighth register, and the refusal
	// names the register rather than writing an encoding that names a different one.
	xmm9 := Register{
		name:  'xmm9'
		code:  9
		width: 16
	}
	e.load_double_constant(xmm9, 0) or {
		assert err.msg().contains('xmm9')
		return
	}
	assert false, 'a constant was loaded into a register the encoding cannot name'
}
