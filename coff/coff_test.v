module coff

import os

// The reader is checked against objects built here and against one a compiler
// wrote, because the two catch different mistakes. An object assembled by this
// file is exact: every offset and every name is known, so a reader that misses a
// field disagrees with a number the test wrote down. A compiler's object is what
// a link will actually be given, so it catches the spelling a format allows and
// this tree would not think to write.

// TestSection is one section an object built here holds.
struct TestSection {
	name            string
	data            []u8
	characteristics u32
}

// build_object assembles a COFF object out of the sections it is given. The
// parts stand in the order a compiler writes them: the header, the section
// table, the section data, the relocations, the symbol table, the string table.
fn build_object(sections []TestSection) []u8 {
	// The string table first, because a long section name in the section
	// table is an offset into it and that offset has to be known before the
	// table is written.
	mut strings := []u8{len: 4}
	mut name_offsets := map[string]int{}
	for section in sections {
		if section.name.len > 8 && section.name !in name_offsets {
			name_offsets[section.name] = strings.len
			strings << section.name.bytes()
			strings << u8(0)
		}
	}
	for i in 0 .. 4 {
		strings[i] = u8((u32(strings.len) >> (8 * i)) & 0xff)
	}
	mut data_size := 0
	for section in sections {
		data_size += section.data.len
	}
	total := coff_header_size + sections.len * section_header_size + data_size + strings.len
	mut bytes := []u8{len: total, init: u8(0)}
	// The header. SymbolCount stays zero, so the string table is read as
	// absent by a reader that decides from the pointer, and this builder's
	// sections carry no long name of their own in that case.
	put_u16(mut bytes, 0, image_file_machine_amd64)
	put_u16(mut bytes, 2, u16(sections.len))
	put_u16(mut bytes, 16, 0)
	mut at := coff_header_size + sections.len * section_header_size
	mut offsets := []int{cap: sections.len}
	for section in sections {
		offsets << at
		at += section.data.len
	}
	for i, section in sections {
		header := coff_header_size + i * section_header_size
		write_name(mut bytes, header, section.name, name_offsets)
		put_u32(mut bytes, header + 16, u32(section.data.len))
		put_u32(mut bytes, header + 20, u32(offsets[i]))
		put_u32(mut bytes, header + 36, section.characteristics)
		for j, byte in section.data {
			bytes[offsets[i] + j] = byte
		}
	}
	return bytes
}

// write_name writes an eight-byte name field: the text when it fits, and a slash
// and the string table offset when it does not.
fn write_name(mut bytes []u8, at int, name string, offsets map[string]int) {
	if name.len > 8 {
		text := '/${offsets[name]}'
		for i, byte in text.bytes() {
			bytes[at + i] = byte
		}
		return
	}
	for i, byte in name.bytes() {
		bytes[at + i] = byte
	}
}

fn put_u16(mut bytes []u8, at int, value u16) {
	bytes[at] = u8(value & 0xff)
	bytes[at + 1] = u8((value >> 8) & 0xff)
}

fn put_u32(mut bytes []u8, at int, value u32) {
	for i in 0 .. 4 {
		bytes[at + i] = u8((value >> (8 * i)) & 0xff)
	}
}

fn text_section(name string) TestSection {
	return TestSection{
		name:            name
		data:            [u8(0x90), u8(0x90), u8(0xc3)]
		characteristics: scn_cnt_code | scn_mem_execute | scn_mem_read | u32(0x00500000)
	}
}

fn test_a_section_is_read_with_its_name_and_bytes() {
	object := build_object([text_section('.text')])
	file := read(object)!
	assert file.machine == image_file_machine_amd64
	assert file.sections.len == 1
	section := file.sections[0]
	assert section.number == 1
	assert section.name == '.text'
	assert section.raw_size == 3
	assert file.data(section) == [u8(0x90), u8(0x90), u8(0xc3)]
	assert section.alignment() == 16
	assert !section.is_comdat()
	assert !section.discardable()
}

fn test_a_name_that_fills_all_eight_bytes_is_read_whole() {
	object := build_object([
		TestSection{
			name:            '.debug$S'
			data:            [u8(0), u8(1)]
			characteristics: scn_cnt_initialized_data | scn_mem_discardable | scn_lnk_info
		},
		text_section('.text'),
	])
	file := read(object)!
	assert file.sections.len == 2
	assert file.sections[0].name == '.debug$S'
	assert file.sections[0].discardable()
	assert file.sections[1].name == '.text'
	assert file.sections[1].characteristics & scn_mem_execute != 0
}

fn test_a_section_with_no_bytes_has_none() {
	object := build_object([
		TestSection{
			name:            '.bss'
			data:            []u8{}
			characteristics: scn_cnt_uninitialized_data | scn_mem_read | scn_mem_write
		},
	])
	file := read(object)!
	assert file.sections[0].raw_size == 0
	assert file.data(file.sections[0]).len == 0
}

fn test_a_truncated_file_is_refused() {
	if _ := read([]u8{len: 10}) {
		assert false, 'ten bytes is not a COFF header'
	} else {
		assert err.msg().contains('truncated')
	}
	object := build_object([text_section('.text')])
	if _ := read(object[..30]) {
		assert false, 'a cut section table is not a readable object'
	} else {
		assert err.msg().contains('section table ends at')
	}
}

fn test_a_file_that_is_not_an_object_is_refused_by_what_it_is() {
	mut image := build_object([text_section('.text')])
	image[0] = u8(0x4c)
	image[1] = u8(0x01)
	if _ := read(image) {
		assert false, 'an i386 object is not an amd64 one'
	} else {
		assert err.msg().contains('i386')
	}
	mut with_header := build_object([text_section('.text')])
	put_u16(mut with_header, 16, 224)
	if _ := read(with_header) {
		assert false, 'an image carries an optional header and is not an object'
	} else {
		assert err.msg().contains('optional header')
	}
}

fn test_an_object_a_compiler_wrote_is_read() {
	clang := '/usr/bin/clang'
	if !os.exists(clang) {
		eprintln('skipping: no clang on this machine to write a COFF object with')
		return
	}
	dir := os.join_path(os.temp_dir(), 'vlk_coff_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer {
		os.rmdir_all(dir) or {}
	}
	source := os.join_path(dir, 'unit.c')
	os.write_file(source, 'int answer = 42;\nint add(int a, int b) { return a + b + answer; }\n') or {
		panic(err)
	}
	object := os.join_path(dir, 'unit.obj')
	result := os.exec([clang, '--target=x86_64-pc-windows-msvc', '-c', source, '-o', object])
	if result.exit_code != 0 {
		eprintln('skipping: clang could not write a COFF object: ${result.output}')
		return
	}
	bytes := os.read_bytes(object) or { panic(err) }
	file := read(bytes)!
	mut names := []string{}
	for section in file.sections {
		names << section.name
	}
	assert '.text' in names
	assert '.data' in names
	for section in file.sections {
		if section.name == '.text' {
			assert file.data(section).len > 0
			assert section.characteristics & scn_mem_execute != 0
		}
	}
}
