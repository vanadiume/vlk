module pe

// The debug directory is checked by reading its bytes back, the way a debugger
// reads them: the entry's fields against the numbers it was built from, and the
// record behind it against the CodeView struct. The records are built here, so
// no PDB and no image is needed to check the shape.

fn cv_u16_at(bytes []u8, at int) u16 {
	return u16(bytes[at]) | (u16(bytes[at + 1]) << 8)
}

fn cv_u32_at(bytes []u8, at int) u32 {
	mut value := u32(0)
	for i in 0 .. 4 {
		value |= u32(bytes[at + i]) << (8 * i)
	}
	return value
}

fn cv_bytes_at(bytes []u8, at int, len int) []u8 {
	mut out := []u8{len: len}
	for i in 0 .. len {
		out[i] = bytes[at + i]
	}
	return out
}

fn test_the_entry_describes_the_record_it_was_placed_with() {
	view := CodeView{
		pdb_path: 'C:\\build\\hello.pdb'
		guid:     [16]u8{}
		age:      1
	}
	dir := codeview_directory(view, 0x3000, 0x600) or { panic(err) }
	assert dir.entry_size == 28
	assert dir.record_size == 4 + 16 + 4 + view.pdb_path.len + 1
	assert dir.data.len == dir.entry_size + dir.record_size
	assert cv_u32_at(dir.data, 0) == 0 // Characteristics
	assert cv_u32_at(dir.data, 4) == 0 // TimeDateStamp
	assert cv_u16_at(dir.data, 8) == 0 // MajorVersion
	assert cv_u16_at(dir.data, 10) == 0 // MinorVersion
	assert cv_u32_at(dir.data, 12) == 2 // IMAGE_DEBUG_TYPE_CODEVIEW
	assert int(cv_u32_at(dir.data, 16)) == dir.record_size // SizeOfData
	assert cv_u32_at(dir.data, 20) == 0x3000 + 28 // AddressOfRawData
	assert cv_u32_at(dir.data, 24) == 0x600 + 28 // PointerToRawData
}

fn test_the_record_copies_the_guid_in_the_order_given() {
	guid := [
		u8(0xde),
		0xad,
		0xbe,
		0xef,
		0x01,
		0x23,
		0x45,
		0x67,
		0x89,
		0xab,
		0xcd,
		0xef,
		0x0f,
		0x1e,
		0x2d,
		0x3c,
	]!
	view := CodeView{
		pdb_path: 'x.pdb'
		guid:     guid
		age:      0x1234
	}
	dir := codeview_directory(view, 0x1000, 0x200) or { panic(err) }
	assert cv_bytes_at(dir.data, 28, 4) == 'RSDS'.bytes()
	assert cv_bytes_at(dir.data, 32, 16) == guid[..]
	assert cv_u32_at(dir.data, 48) == 0x1234
	assert cv_bytes_at(dir.data, 52, 'x.pdb'.len) == 'x.pdb'.bytes()
	assert dir.data[52 + 'x.pdb'.len] == 0
	assert dir.data.len == 52 + 'x.pdb'.len + 1
}

fn test_the_oldest_age_the_field_holds_survives_the_round_trip() {
	view := CodeView{
		pdb_path: 'a.pdb'
		guid:     [16]u8{}
		age:      max_size_of_data
	}
	dir := codeview_directory(view, 0x1000, 0x200) or { panic(err) }
	assert cv_u32_at(dir.data, 48) == max_size_of_data
}

fn test_an_empty_path_is_refused() {
	view := CodeView{
		pdb_path: ''
		guid:     [16]u8{}
		age:      1
	}
	codeview_directory(view, 0x1000, 0x200) or {
		assert err.msg().contains('PDB path')
		return
	}
	assert false, 'an empty PDB path was accepted'
}

fn test_a_path_whose_record_its_size_field_cannot_state_is_refused() {
	largest := max_size_of_data - codeview_fixed_size - 1
	size := codeview_record_size(largest) or { panic(err) }
	assert size == max_size_of_data
	codeview_record_size(largest + 1) or {
		assert err.msg().contains('32 bits')
		return
	}
	assert false, 'a record longer than its size field was accepted'
}

fn test_an_rva_the_address_field_cannot_hold_is_refused() {
	view := CodeView{
		pdb_path: 'a.pdb'
		guid:     [16]u8{}
		age:      1
	}
	// The last address the field holds is the last rva plus the entry.
	dir := codeview_directory(view, max_size_of_data - 28, 0x200) or { panic(err) }
	assert cv_u32_at(dir.data, 20) == max_size_of_data
	codeview_directory(view, max_size_of_data - 27, 0x200) or {
		assert err.msg().contains('AddressOfRawData')
		return
	}
	assert false, 'an rva past the end of a 32-bit field was accepted'
}

fn test_a_negative_rva_is_refused() {
	view := CodeView{
		pdb_path: 'a.pdb'
		guid:     [16]u8{}
		age:      1
	}
	codeview_directory(view, -1, 0x200) or {
		assert err.msg().contains('unsigned')
		return
	}
	assert false, 'a negative rva was accepted'
}

fn test_a_file_offset_the_pointer_field_cannot_hold_is_refused() {
	view := CodeView{
		pdb_path: 'a.pdb'
		guid:     [16]u8{}
		age:      1
	}
	dir := codeview_directory(view, 0x1000, max_size_of_data - 28) or { panic(err) }
	assert cv_u32_at(dir.data, 24) == max_size_of_data
	codeview_directory(view, 0x1000, max_size_of_data - 27) or {
		assert err.msg().contains('PointerToRawData')
		return
	}
	assert false, 'a file offset past the end of a 32-bit field was accepted'
}

fn test_a_negative_file_offset_is_refused() {
	view := CodeView{
		pdb_path: 'a.pdb'
		guid:     [16]u8{}
		age:      1
	}
	codeview_directory(view, 0x1000, -1) or {
		assert err.msg().contains('unsigned')
		return
	}
	assert false, 'a negative file offset was accepted'
}
