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
	relocs          []TestReloc = []
	// overflow asks the builder to write the extended relocation count: the
	// header saturates at 0xffff and the true count goes in a placeholder
	// entry at the front of the array.
	overflow bool
}

// TestReloc is one relocation entry a section carries.
struct TestReloc {
	offset u32
	symbol u32
	kind   u16
}

// TestSymbol is one symbol table entry and the auxiliary records that belong to
// it. aux is raw, because which record it is depends on the symbol.
struct TestSymbol {
	name    string
	value   u32
	section i16
	kind    u16
	class   u8
	aux     []u8
}

// build_object assembles a COFF object out of the sections and symbols it is
// given. The parts stand in the order a compiler writes them: the header, the
// section table, the section data, the relocations, the symbol table, the string
// table.
fn build_object(sections []TestSection, symbols []TestSymbol) []u8 {
	// The string table first, because a long name in the section table or in
	// the symbol table is an offset into it and that offset has to be known
	// before either table is written.
	mut strings := []u8{len: 4}
	mut name_offsets := map[string]int{}
	for section in sections {
		if section.name.len > 8 && section.name !in name_offsets {
			name_offsets[section.name] = strings.len
			strings << section.name.bytes()
			strings << u8(0)
		}
	}
	for symbol in symbols {
		if symbol.name.len > 8 && symbol.name !in name_offsets {
			name_offsets[symbol.name] = strings.len
			strings << symbol.name.bytes()
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
	mut aux_size := 0
	for symbol in symbols {
		aux_size += symbol.aux.len
	}
	mut reloc_size := 0
	for section in sections {
		if section.relocs.len > 0 {
			reloc_size += section.relocs.len * relocation_entry_size
			if section.overflow {
				reloc_size += relocation_entry_size
			}
		}
	}
	symbol_entries := symbols.len + aux_size / symbol_entry_size
	reloc_start := coff_header_size + sections.len * section_header_size + data_size
	symbol_offset := reloc_start + reloc_size
	string_offset := symbol_offset + symbol_entries * symbol_entry_size
	total := string_offset + strings.len
	mut bytes := []u8{len: total, init: u8(0)}
	put_u16(mut bytes, 0, image_file_machine_amd64)
	put_u16(mut bytes, 2, u16(sections.len))
	if symbol_entries > 0 {
		put_u32(mut bytes, 8, u32(symbol_offset))
		put_u32(mut bytes, 12, u32(symbol_entries))
	}
	put_u16(mut bytes, 16, 0)
	mut offsets := []int{cap: sections.len}
	at := coff_header_size + sections.len * section_header_size
	mut next := at
	for section in sections {
		offsets << next
		next += section.data.len
	}
	mut reloc_offsets := []int{cap: sections.len}
	mut reloc_at := reloc_start
	for section in sections {
		reloc_offsets << reloc_at
		if section.relocs.len > 0 {
			reloc_at += section.relocs.len * relocation_entry_size
			if section.overflow {
				reloc_at += relocation_entry_size
			}
		}
	}
	for i, section in sections {
		header := coff_header_size + i * section_header_size
		write_name(mut bytes, header, section.name, name_offsets)
		put_u32(mut bytes, header + 16, u32(section.data.len))
		put_u32(mut bytes, header + 20, u32(offsets[i]))
		mut characteristics := section.characteristics
		if section.relocs.len > 0 {
			put_u32(mut bytes, header + 24, u32(reloc_offsets[i]))
			if section.overflow {
				put_u16(mut bytes, header + 32, relocation_overflow_count)
				characteristics |= scn_lnk_nreloc_ovfl
			} else {
				put_u16(mut bytes, header + 32, u16(section.relocs.len))
			}
		}
		put_u32(mut bytes, header + 36, characteristics)
		for j, byte in section.data {
			bytes[offsets[i] + j] = byte
		}
	}
	for i, section in sections {
		if section.relocs.len == 0 {
			continue
		}
		mut at2 := reloc_offsets[i]
		if section.overflow {
			put_u32(mut bytes, at2, u32(section.relocs.len + 1))
			at2 += relocation_entry_size
		}
		for reloc in section.relocs {
			put_u32(mut bytes, at2, reloc.offset)
			put_u32(mut bytes, at2 + 4, reloc.symbol)
			put_u16(mut bytes, at2 + 8, reloc.kind)
			at2 += relocation_entry_size
		}
	}
	mut symbol_at := symbol_offset
	for symbol in symbols {
		write_symbol_name(mut bytes, symbol_at, symbol.name, name_offsets)
		put_u32(mut bytes, symbol_at + 8, symbol.value)
		put_u16(mut bytes, symbol_at + 12, u16(i32(symbol.section) & 0xffff))
		put_u16(mut bytes, symbol_at + 14, symbol.kind)
		bytes[symbol_at + 16] = symbol.class
		bytes[symbol_at + 17] = u8(symbol.aux.len / symbol_entry_size)
		for j, byte in symbol.aux {
			bytes[symbol_at + symbol_entry_size + j] = byte
		}
		symbol_at += symbol_entry_size + symbol.aux.len
	}
	for j, byte in strings {
		bytes[string_offset + j] = byte
	}
	return bytes
}

// write_name writes an eight-byte section name field: the text when it fits, and
// a slash and the string table offset when it does not.
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

// write_symbol_name writes an eight-byte symbol name field: the text when it
// fits, and four zero bytes and the string table offset when it does not.
fn write_symbol_name(mut bytes []u8, at int, name string, offsets map[string]int) {
	if name.len > 8 {
		put_u32(mut bytes, at + 4, u32(offsets[name]))
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

// section_symbol is the static symbol every section carries at value zero. Its
// auxiliary record is where a COMDAT group's selection is written.
fn section_symbol(name string, section int, selection u8, number int) TestSymbol {
	mut aux := []u8{len: symbol_entry_size}
	put_u32(mut aux, 0, 3)
	put_u16(mut aux, 12, u16(number))
	aux[14] = selection
	return TestSymbol{
		name:    name
		value:   0
		section: i16(section)
		kind:    0
		class:   sym_class_static
		aux:     aux
	}
}

fn test_a_section_is_read_with_its_name_and_bytes() {
	object := build_object([text_section('.text')], [])
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
	], [])
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
	], [])
	file := read(object)!
	assert file.sections[0].raw_size == 0
	assert file.data(file.sections[0]).len == 0
}

fn test_symbols_are_read_with_their_sections_and_classes() {
	object := build_object([
		text_section('.text'),
		TestSection{
			name:            '.data'
			data:            [u8(0), u8(0), u8(0), u8(0)]
			characteristics: scn_cnt_initialized_data | scn_mem_read | scn_mem_write
		},
	], [
		section_symbol('.text', 1, comdat_none, 1),
		TestSymbol{
			name:    'main'
			value:   0
			section: 1
			kind:    sym_type_function
			class:   sym_class_external
			aux:     []u8{}
		},
		TestSymbol{
			name:    'counter'
			value:   8
			section: 2
			kind:    0
			class:   sym_class_external
			aux:     []u8{}
		},
		TestSymbol{
			name:    'puts'
			value:   0
			section: 0
			kind:    sym_type_function
			class:   sym_class_external
			aux:     []u8{}
		},
	])
	file := read(object)!
	assert file.symbols.len == 4
	assert file.symbols[0].name == '.text'
	assert file.symbols[0].is_section_symbol()
	assert !file.symbols[0].is_undefined()
	assert file.symbols[1].name == 'main'
	assert file.symbols[1].is_function()
	assert file.symbols[1].section == 1
	assert file.symbols[1].storage_class == sym_class_external
	assert file.symbols[2].name == 'counter'
	assert !file.symbols[2].is_function()
	assert file.symbols[3].name == 'puts'
	assert file.symbols[3].is_undefined()
	assert !file.symbols[3].is_common()
}

fn test_an_auxiliary_record_belongs_to_the_symbol_before_it() {
	object := build_object([
		TestSection{
			name:            '.rdata'
			data:            [u8(1), u8(2), u8(3)]
			characteristics: scn_cnt_initialized_data | scn_mem_read | scn_lnk_comdat
		},
	], [
		section_symbol('.rdata', 1, comdat_any, 1),
		TestSymbol{
			name:    '??_C@_03@abc@'
			value:   0
			section: 1
			kind:    0
			class:   sym_class_external
			aux:     []u8{}
		},
	])
	file := read(object)!
	// The section symbol's auxiliary record is not a symbol of its own, so
	// the table holds the section symbol and the COMDAT symbol, no more.
	assert file.symbols.len == 2
	assert file.symbols[0].aux_count == 1
	assert file.symbols[1].index == 2
	definition := file.symbols[0].section_definition() or {
		assert false, 'the section symbol carries its auxiliary record'
		return
	}
	assert definition.selection == comdat_any
	assert definition.number == 1
	assert file.sections[0].comdat_selection == comdat_any
	assert file.sections[0].is_comdat()
}

fn test_an_associative_section_names_the_one_it_follows() {
	object := build_object([
		TestSection{
			name:            '.text$mn'
			data:            [u8(0x90)]
			characteristics: scn_cnt_code | scn_mem_execute | scn_lnk_comdat
		},
		TestSection{
			name:            '.text$unlikely'
			data:            [u8(0xc3)]
			characteristics: scn_cnt_code | scn_mem_execute | scn_lnk_comdat
		},
	], [
		section_symbol('.text$mn', 1, comdat_any, 1),
		section_symbol('.text$unlikely', 2, comdat_associative, 1),
	])
	file := read(object)!
	assert file.sections[0].comdat_selection == comdat_any
	assert file.sections[1].comdat_selection == comdat_associative
	assert file.sections[1].associative == 1
}

fn test_a_long_name_is_read_out_of_the_string_table() {
	object := build_object([
		TestSection{
			name:            '.llvm_addrsig'
			data:            [u8(0)]
			characteristics: scn_lnk_remove
		},
	], [
		TestSymbol{
			name:    'a_very_long_symbol_name'
			value:   0
			section: 1
			kind:    0
			class:   sym_class_external
			aux:     []u8{}
		},
	])
	file := read(object)!
	assert file.sections[0].name == '.llvm_addrsig'
	assert file.symbols[0].name == 'a_very_long_symbol_name'
}

fn test_a_common_symbol_is_told_apart_from_an_undefined_one() {
	object := build_object([text_section('.text')], [
		TestSymbol{
			name:    'shared'
			value:   16
			section: 0
			kind:    0
			class:   sym_class_external
			aux:     []u8{}
		},
		TestSymbol{
			name:    'wanted'
			value:   0
			section: 0
			kind:    sym_type_function
			class:   sym_class_external
			aux:     []u8{}
		},
	])
	file := read(object)!
	assert file.symbols[0].is_common()
	assert !file.symbols[0].is_undefined()
	assert file.symbols[1].is_undefined()
	assert !file.symbols[1].is_common()
}

fn test_a_weak_external_names_the_symbol_it_falls_back_to() {
	mut aux := []u8{len: symbol_entry_size}
	put_u32(mut aux, 0, 7)
	put_u32(mut aux, 4, weak_extern_alias)
	object := build_object([text_section('.text')], [
		TestSymbol{
			name:    'optional'
			value:   0
			section: 0
			kind:    0
			class:   sym_class_weak_external
			aux:     aux
		},
	])
	file := read(object)!
	assert file.symbols.len == 1
	assert file.symbols[0].storage_class == sym_class_weak_external
	weak := file.symbols[0].weak_external() or {
		assert false, 'a weak external carries its fallback record'
		return
	}
	assert weak.tag_index == 7
	assert weak.characteristics == weak_extern_alias
}

fn test_relocations_are_read_with_the_symbol_each_names() {
	object := build_object([
		TestSection{
			name:            '.text'
			data:            [u8(0xe8), 0, 0, 0, 0]
			characteristics: scn_cnt_code | scn_mem_execute
			relocs:          [TestReloc{ offset: 1, symbol: 2, kind: rel_amd64_rel32 }]
		},
		TestSection{
			name:            '.pdata'
			data:            [u8(0), 0, 0, 0, 0, 0, 0, 0]
			characteristics: scn_cnt_initialized_data | scn_mem_read
			relocs:          [
				TestReloc{ offset: 0, symbol: 0, kind: rel_amd64_addr32nb },
				TestReloc{ offset: 4, symbol: 2, kind: rel_amd64_addr32nb },
			]
		},
	], [
		section_symbol('.text', 1, comdat_none, 1),
		section_symbol('.pdata', 2, comdat_none, 2),
		TestSymbol{
			name:    'func'
			value:   0
			section: 1
			kind:    sym_type_function
			class:   sym_class_external
			aux:     []u8{}
		},
	])
	file := read(object)!
	assert file.relocations.len == 3
	text := file.relocations_of(1)
	assert text.len == 1
	assert text[0].offset == 1
	assert text[0].kind == rel_amd64_rel32
	text_symbol := file.symbol_for(text[0].symbol) or { panic('the relocation names a symbol') }
	assert text_symbol.name == '.pdata'
	pdata := file.relocations_of(2)
	assert pdata.len == 2
	assert pdata[0].offset == 0
	assert pdata[0].kind == rel_amd64_addr32nb
	first := file.symbol_for(pdata[0].symbol) or { panic('the relocation names a symbol') }
	second := file.symbol_for(pdata[1].symbol) or { panic('the relocation names a symbol') }
	assert first.name == '.text'
	assert second.name == '.pdata'
	assert file.relocations_of(3).len == 0
}

fn test_the_extended_relocation_count_is_read_past_its_placeholder() {
	object := build_object([
		TestSection{
			name:            '.text'
			data:            [u8(0xe8), 0, 0, 0, 0]
			characteristics: scn_cnt_code | scn_mem_execute
			relocs:          [TestReloc{ offset: 1, symbol: 2, kind: rel_amd64_rel32 }]
			overflow:        true
		},
	], [
		section_symbol('.text', 1, comdat_none, 1),
		TestSymbol{
			name:    'func'
			value:   0
			section: 1
			kind:    sym_type_function
			class:   sym_class_external
			aux:     []u8{}
		},
	])
	file := read(object)!
	assert file.sections[0].reloc_count == 1
	assert file.relocations.len == 1
	assert file.relocations[0].offset == 1
	target := file.symbol_for(file.relocations[0].symbol) or { panic('the relocation names a symbol') }
	assert target.name == 'func'
}

fn test_a_relocation_that_names_an_auxiliary_record_is_refused() {
	object := build_object([
		TestSection{
			name:            '.text'
			data:            [u8(0xe8), 0, 0, 0, 0]
			characteristics: scn_cnt_code | scn_mem_execute
			relocs:          [TestReloc{ offset: 1, symbol: 1, kind: rel_amd64_rel32 }]
		},
	], [
		section_symbol('.text', 1, comdat_none, 1),
	])
	if _ := read(object) {
		assert false, 'index one holds the section symbol auxiliary record'
	} else {
		assert err.msg().contains('auxiliary record')
	}
}

fn test_a_relocation_type_past_the_machine_s_is_refused() {
	object := build_object([
		TestSection{
			name:            '.text'
			data:            [u8(0xe8), 0, 0, 0, 0]
			characteristics: scn_cnt_code | scn_mem_execute
			relocs:          [TestReloc{ offset: 1, symbol: 0, kind: 0x11 }]
		},
	], [
		section_symbol('.text', 1, comdat_none, 1),
	])
	if _ := read(object) {
		assert false, 'type 0x11 is past the last type the machine defines'
	} else {
		assert err.msg().contains('no type past')
	}
}

fn test_a_truncated_file_is_refused() {
	if _ := read([]u8{len: 10}) {
		assert false, 'ten bytes is not a COFF header'
	} else {
		assert err.msg().contains('truncated')
	}
	object := build_object([text_section('.text')], [])
	if _ := read(object[..30]) {
		assert false, 'a cut section table is not a readable object'
	} else {
		assert err.msg().contains('section table ends at')
	}
	symbols := build_object([text_section('.text')], [
		section_symbol('.text', 1, comdat_none, 1),
	])
	mut lying := symbols.clone()
	put_u32(mut lying, 12, 3)
	if _ := read(lying) {
		assert false, 'a symbol count past the table is not readable'
	} else {
		assert err.msg().contains('truncated')
	}
	mut overrun := build_object([text_section('.text')], [
		TestSymbol{
			name:    'main'
			value:   0
			section: 1
			kind:    sym_type_function
			class:   sym_class_external
			aux:     []u8{}
		},
	])
	// The symbol table starts where the section data ends. The one entry
	// claims an auxiliary record its table does not hold, which is the shape
	// a walk has to refuse rather than step past.
	overrun[coff_header_size + section_header_size + 3 + 17] = u8(1)
	if _ := read(overrun) {
		assert false, 'auxiliary records past the table are not readable'
	} else {
		assert err.msg().contains('auxiliary records')
	}
}

fn test_a_file_that_is_not_an_object_is_refused_by_what_it_is() {
	mut image := build_object([text_section('.text')], [])
	image[0] = u8(0x4c)
	image[1] = u8(0x01)
	if _ := read(image) {
		assert false, 'an i386 object is not an amd64 one'
	} else {
		assert err.msg().contains('i386')
	}
	mut with_header := build_object([text_section('.text')], [])
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
	// Every section the compiler wrote carries its section symbol, whose
	// auxiliary record the walk has to step over. A reader that treated one
	// as a symbol would find more symbols than the file has names for.
	mut defined := map[string]bool{}
	for symbol in file.symbols {
		if symbol.name != '' {
			defined[symbol.name] = true
		}
	}
	assert 'add' in defined
	assert 'answer' in defined
	mut add := Symbol{}
	for symbol in file.symbols {
		if symbol.name == 'add' {
			add = symbol
		}
	}
	assert add.is_function()
	assert add.section > 0
	assert add.value == 0
	// The function adds the global to its arguments, so its code carries a
	// reference the object could not settle. A reader that walked the
	// section's relocation array agrees with that reference by name.
	mut code := 0
	for section in file.sections {
		if section.name == '.text' {
			code = section.number
		}
	}
	assert code > 0
	mut named := []string{}
	for relocation in file.relocations_of(code) {
		if symbol := file.symbol_for(relocation.symbol) {
			named << symbol.name
		}
	}
	assert 'answer' in named
}
