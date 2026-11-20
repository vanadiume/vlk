module pe

// The export builder is checked by reading its bytes back: the directory
// record, the three tables its addresses name, and the strings those tables
// point at. Nothing here reads a field of the builder's own struct, so a table
// that points where it says is the only thing that makes these pass.

fn et_u16(bytes []u8, at int) u16 {
	return u16(bytes[at]) | (u16(bytes[at + 1]) << 8)
}

fn et_u32(bytes []u8, at int) u32 {
	mut value := u32(0)
	for i in 0 .. 4 {
		value |= u32(bytes[at + i]) << (8 * i)
	}
	return value
}

fn et_text(bytes []u8, at int) string {
	mut end := at
	for end < bytes.len && bytes[end] != 0 {
		end++
	}
	return bytes[at..end].bytestr()
}

// et_name is the name pointer table's entry index, followed to its string.
fn et_name(d []u8, base int, index int) string {
	names := int(et_u32(d, 32)) - base
	rva := int(et_u32(d, names + index * 4))
	return et_text(d, rva - base)
}

// et_slot is the ordinal table's entry index, which is the address table slot
// the name at that index means.
fn et_slot(d []u8, base int, index int) int {
	ordinals := int(et_u32(d, 36)) - base
	return int(et_u16(d, ordinals + index * 2))
}

// et_eat is the address table's slot, read as an RVA.
fn et_eat(d []u8, base int, slot int) u32 {
	functions := int(et_u32(d, 28)) - base
	return et_u32(d, functions + slot * 4)
}

// et_refusal answers the message a refused table gave, or '' when it was built.
fn et_refusal(dll_name string, exports []Export, base int) string {
	export_table(dll_name, exports, base) or { return err.msg() }
	return ''
}

fn test_the_directory_names_the_dll_and_states_its_tables() {
	table := export_table('demo.dll', [
		Export{
			name:    'one'
			rva:     0x1010
			ordinal: 1
		},
	], 0x1000) or { panic(err) }
	assert table.size == 40
	assert table.data.len > 40
	d := table.data
	assert et_u32(d, 0) == 0 // reserved
	assert et_u32(d, 4) == 0 // no timestamp, so two links can agree
	assert et_u16(d, 8) == 0
	assert et_u16(d, 10) == 0
	assert et_u32(d, 16) == 1 // the base ordinal
	assert et_u32(d, 20) == 1 // address table entries
	assert et_u32(d, 24) == 1 // name pointers
	name := int(et_u32(d, 12)) - 0x1000
	assert et_text(d, name) == 'demo.dll'
	assert int(et_u32(d, 28)) - 0x1000 == 40
	assert int(et_u32(d, 32)) - 0x1000 == 44
	assert int(et_u32(d, 36)) - 0x1000 == 48
	assert et_name(d, 0x1000, 0) == 'one'
	assert et_slot(d, 0x1000, 0) == 0
	assert et_eat(d, 0x1000, 0) == 0x1010
}

fn test_the_names_are_sorted_and_each_one_names_its_address_table_slot() {
	table := export_table('demo.dll', [
		Export{
			name:    'beta'
			rva:     0x2000
			ordinal: 2
		},
		Export{
			name:    'alpha'
			rva:     0x1000
			ordinal: 3
		},
		Export{
			name: 'gamma'
			rva:  0x3000
		},
	], 0x1000) or { panic(err) }
	d := table.data
	assert et_u32(d, 16) == 2 // the first export is number 2, so the table starts there
	assert et_u32(d, 20) == 3 // gamma took 4, so the table runs 2 to 4
	assert et_u32(d, 24) == 3
	assert et_name(d, 0x1000, 0) == 'alpha'
	assert et_name(d, 0x1000, 1) == 'beta'
	assert et_name(d, 0x1000, 2) == 'gamma'
	// The names are in byte order, and the ordinal table beside them sends the
	// loader to the slot that holds each name's address.
	assert et_slot(d, 0x1000, 0) == 1
	assert et_slot(d, 0x1000, 1) == 0
	assert et_slot(d, 0x1000, 2) == 2
	assert et_eat(d, 0x1000, 0) == 0x2000 // ordinal 2
	assert et_eat(d, 0x1000, 1) == 0x1000 // ordinal 3
	assert et_eat(d, 0x1000, 2) == 0x3000 // ordinal 4
	assert et_eat(d, 0x1000, et_slot(d, 0x1000, 0)) == 0x1000
	assert et_eat(d, 0x1000, et_slot(d, 0x1000, 1)) == 0x2000
	assert et_eat(d, 0x1000, et_slot(d, 0x1000, 2)) == 0x3000
}

fn test_a_number_no_export_answers_is_a_zero_in_the_address_table() {
	table := export_table('gap.dll', [
		Export{
			name:    'early'
			rva:     0x1000
			ordinal: 1
		},
		Export{
			name:    'late'
			rva:     0x1234
			ordinal: 4
		},
	], 1) or { panic(err) }
	d := table.data
	assert et_u32(d, 16) == 1
	assert et_u32(d, 20) == 4
	assert et_u32(d, 24) == 2
	assert et_eat(d, 1, 0) == 0x1000
	assert et_eat(d, 1, 1) == 0
	assert et_eat(d, 1, 2) == 0
	assert et_eat(d, 1, 3) == 0x1234
	assert et_name(d, 1, 0) == 'early'
	assert et_name(d, 1, 1) == 'late'
	assert et_slot(d, 1, 0) == 0
	assert et_slot(d, 1, 1) == 3
	assert et_eat(d, 1, et_slot(d, 1, 0)) == 0x1000
	assert et_eat(d, 1, et_slot(d, 1, 1)) == 0x1234
}

fn test_exports_without_an_ordinal_follow_the_highest_stated_one() {
	table := export_table('ordinals.dll', [
		Export{
			name: 'x'
			rva:  0x100
		},
		Export{
			name:    'y'
			rva:     0x200
			ordinal: 10
		},
		Export{
			name: 'z'
			rva:  0x300
		},
	], 1) or { panic(err) }
	d := table.data
	assert et_u32(d, 16) == 10 // y is the first export the table answers
	assert et_u32(d, 20) == 3 // y took 10, x and z take 11 and 12
	assert et_u32(d, 24) == 3
	assert et_name(d, 1, 0) == 'x'
	assert et_name(d, 1, 1) == 'y'
	assert et_name(d, 1, 2) == 'z'
	assert et_slot(d, 1, 0) == 1
	assert et_slot(d, 1, 1) == 0
	assert et_slot(d, 1, 2) == 2
	assert et_eat(d, 1, 0) == 0x200
	assert et_eat(d, 1, 1) == 0x100
	assert et_eat(d, 1, 2) == 0x300
}

fn test_the_same_input_gives_the_same_bytes_and_the_base_moves_the_tables() {
	exports := [
		Export{
			name: 'a'
			rva:  0x10
		},
		Export{
			name:    'b'
			rva:     0x20
			ordinal: 2
		},
	]
	first := export_table('same.dll', exports, 0x2000) or { panic(err) }
	second := export_table('same.dll', exports, 0x2000) or { panic(err) }
	assert first.data.len == second.data.len
	for i in 0 .. first.data.len {
		assert first.data[i] == second.data[i]
	}
	lower := export_table('same.dll', exports, 0x1000) or { panic(err) }
	assert lower.data.len == first.data.len
	assert et_u32(first.data, 12) == et_u32(lower.data, 12) + 0x1000
	assert et_u32(first.data, 28) == et_u32(lower.data, 28) + 0x1000
	assert et_u32(first.data, 32) == et_u32(lower.data, 32) + 0x1000
	assert et_u32(first.data, 36) == et_u32(lower.data, 36) + 0x1000
	// The addresses in the address table are the image's, not the section's, so
	// they do not move with the base.
	assert et_eat(first.data, 0x2000, 0) == et_eat(lower.data, 0x1000, 0)
	assert et_eat(first.data, 0x2000, 1) == et_eat(lower.data, 0x1000, 1)
}

fn test_an_empty_dll_name_is_refused() {
	message := et_refusal('', [
		Export{
			name: 'one'
			rva:  1
		},
	], 1)
	assert message.contains('names no DLL')
}

fn test_an_empty_export_name_is_refused() {
	message := et_refusal('demo.dll', [
		Export{
			name: ''
			rva:  1
		},
	], 1)
	assert message.contains('has no name')
}

fn test_a_name_exported_twice_is_refused() {
	message := et_refusal('demo.dll', [
		Export{
			name: 'same'
			rva:  1
		},
		Export{
			name: 'same'
			rva:  2
		},
	], 1)
	assert message.contains('exported more than once')
}

fn test_an_ordinal_asked_for_twice_is_refused() {
	message := et_refusal('demo.dll', [
		Export{
			name:    'one'
			rva:     1
			ordinal: 2
		},
		Export{
			name:    'two'
			rva:     2
			ordinal: 2
		},
	], 1)
	assert message.contains('more than one export')
}

fn test_a_negative_ordinal_is_refused() {
	message := et_refusal('demo.dll', [
		Export{
			name:    'one'
			rva:     1
			ordinal: -1
		},
	], 1)
	assert message.contains('is not negative')
}

fn test_an_ordinal_above_the_sixteen_bit_table_is_refused() {
	message := et_refusal('demo.dll', [
		Export{
			name:    'one'
			rva:     1
			ordinal: 0x10000
		},
	], 1)
	assert message.contains('above the 65535')
}

fn test_a_negative_address_is_refused() {
	message := et_refusal('demo.dll', [
		Export{
			name: 'one'
			rva:  -1
		},
	], 1)
	assert message.contains('not an RVA')
}
