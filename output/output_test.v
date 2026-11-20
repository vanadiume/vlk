module output

import vanadiume.vlk.target
import vanadiume.vlk.unit

// The seam is checked on its own: which writer a target's format sends a
// program to, and what a kind the container cannot produce answers with. The
// images themselves are checked in the container's own tests, where running them
// is the point.

fn one_return() unit.Program {
	mut part := unit.Program{}
	part.text = [u8(0xc3)]
	part.labels['main'] = 0
	part.defined['main'] = true
	part.entry_place = 0
	return part
}

fn test_a_pe_target_is_written_as_a_pe_image() {
	windows := target.windows_x86_64()
	bytes := image(one_return(), windows, .program, Options{})!
	assert bytes[0] == u8(`M`)
	assert bytes[1] == u8(`Z`)
	// The signature's offset is the field a DOS header keeps where a DOS
	// program keeps its relocation table, and the four bytes there are what
	// tells a loader the file is a PE image.
	offset := int(u32_at(bytes, 0x3c))
	assert bytes[offset..offset + 4] == [u8(`P`), u8(`E`), u8(0), u8(0)]
	assert u16_at(bytes, offset + 4) == target.coff_machine_amd64
}

fn test_a_shared_link_on_a_pe_target_is_refused_by_name() {
	if _ := image(one_return(), target.windows_x86_64(), .shared, Options{}) {
		assert false, 'a PE shared object is a DLL and this writer builds no export table'
	} else {
		assert err.msg().contains('DLL')
	}
}

fn test_an_elf_target_still_reaches_the_elf_writer() {
	host := target.host() or {
		eprintln('skipping: this machine has no host target')
		return
	}
	bytes := image(one_return(), host, .program, Options{})!
	assert bytes[0..4] == [u8(0x7f), u8(`E`), u8(`L`), u8(`F`)]
}

fn u16_at(bytes []u8, at int) u16 {
	return u16(bytes[at]) | (u16(bytes[at + 1]) << 8)
}

fn u32_at(bytes []u8, at int) u32 {
	mut value := u32(0)
	for i in 0 .. 4 {
		value |= u32(bytes[at + i]) << (8 * i)
	}
	return value
}
