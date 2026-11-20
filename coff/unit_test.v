module coff

import os
import vanadiume.vlk.target

// The conversion is checked against an object a compiler wrote, because that is
// the only way to see what a real COFF object asks a link for: clang states the
// unwind data as its own sections and every reference into it as a
// section-relative address, and a unit built by hand would be this tree's idea
// of an object rather than a compiler's.

fn windows() target.Target {
	return target.windows_x86_64()
}

// compiling writes one C file into a scratch directory and answers the object
// clang wrote for it, or none when this machine has no clang that can target
// Windows.
fn compiling(dir string, name string, source string) ?string {
	clang := '/usr/bin/clang'
	if !os.exists(clang) {
		eprintln('skipping: no clang on this machine to write a COFF object with')
		return none
	}
	source_path := os.join_path(dir, '${name}.c')
	os.write_file(source_path, source) or { panic(err) }
	object_path := os.join_path(dir, '${name}.obj')
	result := os.exec([clang, '--target=x86_64-pc-windows-msvc', '-c', source_path, '-o', object_path])
	if result.exit_code != 0 {
		eprintln('skipping: clang could not write a COFF object: ${result.output}')
		return none
	}
	return object_path
}

fn scratch() string {
	dir := os.join_path(os.temp_dir(), 'vlk_coff_unit_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	return dir
}

fn test_a_compiler_s_object_becomes_a_unit_with_its_sections_and_symbols() {
	dir := scratch()
	path := compiling(dir, 'unit',
		'int answer = 42;\nint add(int a, int b) { return a + b + answer; }\n') or {
		return
	}
	part := read_unit(os.read_bytes(path) or { panic(err) }, windows())!
	// The code and the two data blobs are where the names say.
	assert 'add' in part.labels
	assert 'answer' in part.globals
	assert part.text.len > 0
	assert part.globals_blob.len >= 4
	// The unwind data is not part of any blob: it is a section of its own, and
	// a PE image keeps it under its name.
	mut names := []string{}
	for section in part.sections {
		names << section.name
	}
	assert '.pdata' in names
	assert '.xdata' in names
	mut rva_references := 0
	mut direct_references := 0
	for relocation in part.relocations {
		if relocation.kind == .rva {
			rva_references++
		}
		if relocation.kind == .direct {
			direct_references++
		}
	}
	// The exception entry points at the code and the unwind data with
	// section-relative addresses, and the code refers to the global by a
	// distance.
	assert rva_references >= 2
	assert direct_references >= 1
	// A reference inside .pdata names the section it lies in and its byte
	// inside that section.
	mut named := 0
	for relocation in part.relocations {
		if relocation.place == .section {
			assert relocation.section != ''
			named++
		}
	}
	assert named == rva_references
}

fn test_the_addend_a_field_holds_is_read_back_out_of_it() {
	// The addend of a COFF relocation is in the field, so a reference's addend
	// is the bytes already written plus what the type's formula subtracts. A
	// call's field holds zero and the formula subtracts four, which is the
	// distance from the end of the instruction.
	dir := scratch()
	path := compiling(dir, 'calls', 'int add(int a, int b);\nint call(void) { return add(1, 2); }\n') or {
		return
	}
	part := read_unit(os.read_bytes(path) or { panic(err) }, windows())!
	mut found := false
	for relocation in part.relocations {
		if relocation.name == 'add' {
			found = true
			assert relocation.kind == .direct
			assert relocation.addend == -4, 'a call carries minus four, and this one carried ${relocation.addend}'
		}
	}
	assert found, 'the call to add is a reference the unit has to carry'
}

// A COMDAT group the link already kept is discarded whole on the next read: its
// bytes never reach a blob and its symbol never reaches the merge, because the
// copy the link kept is what another object's reference binds to by name.
fn test_a_comdat_group_already_kept_is_discarded() {
	dir := scratch()
	path := compiling(dir, 'literal', 'const char *message(void) { return "shared literal"; }\n') or {
		return
	}
	bytes := os.read_bytes(path) or { panic(err) }
	mut selected := map[string]bool{}
	first := read_unit_selecting(bytes, windows(), mut selected)!
	second := read_unit_selecting(bytes, windows(), mut selected)!
	assert first.string_blob.len > 0
	assert first.read_only_globals.len > 0
	// The literal was the object's only read-only contribution, so the second
	// read carries none of it and defines no name from it.
	assert second.string_blob.len == 0
	assert second.read_only_globals.len == 0
	// The code is still there, and its reference keeps the literal's name.
	mut named := 0
	for relocation in second.relocations {
		if relocation.name.starts_with('??_C@') {
			named++
		}
	}
	assert named > 0
}

// A relocation in a test object: where the field is, which symbol it names and
// the AMD64 type, which is the part a compiler's own output rarely carries.
struct TestReloc {
	offset u32
	symbol u32
	kind   u16
}

// object_u32 and object_u16 append a little-endian number to a byte array, which
// is how every field of a COFF file is written.
fn object_u32(mut out []u8, value u32) {
	for i in 0 .. 4 {
		out << u8((value >> (8 * i)) & 0xff)
	}
}

fn object_u16(mut out []u8, value u16) {
	for i in 0 .. 2 {
		out << u8((value >> (8 * i)) & 0xff)
	}
}

// object_name writes an eight-byte name, which is all a short name needs and all
// the table holds without a string-table offset.
fn object_name(mut out []u8, name string) {
	mut field := []u8{len: 8, init: u8(0)}
	for i, c in name.bytes() {
		field[i] = c
	}
	out << field
}

// object_section writes one section header.
fn object_section(mut out []u8, name string, size int, at int, relocs_at int, count int, characteristics u32) {
	object_name(mut out, name)
	object_u32(mut out, 0)
	object_u32(mut out, 0)
	object_u32(mut out, u32(size))
	object_u32(mut out, u32(at))
	object_u32(mut out, u32(if count > 0 { relocs_at } else { 0 }))
	object_u32(mut out, 0)
	object_u16(mut out, u16(count))
	object_u16(mut out, 0)
	object_u32(mut out, characteristics)
}

// object_symbol writes one symbol table record: a name, a value, the section it
// is in, its type, and its storage class.
fn object_symbol(mut out []u8, name string, value u32, section u16, kind u16, class u8) {
	object_name(mut out, name)
	object_u32(mut out, value)
	object_u16(mut out, section)
	object_u16(mut out, kind)
	out << class
	out << u8(0)
}

// build_object_with writes the smallest object that carries the relocation
// types under test: two sections, a symbol inside the code, and one relocation
// table per section. The reader's arithmetic is checked against types nothing on
// this machine emits, so the object is written here rather than compiled.
fn build_object_with(text_relocs []TestReloc, rodata_relocs []TestReloc) []u8 {
	text := []u8{len: 16, init: u8(0x90)}
	rodata := []u8{len: 8, init: u8(0xcc)}
	mut out := []u8{}
	text_at := 20 + 2 * 40
	rodata_at := text_at + text.len
	text_reloc_at := rodata_at + rodata.len
	rodata_reloc_at := text_reloc_at + text_relocs.len * 10
	symtab_at := rodata_reloc_at + rodata_relocs.len * 10
	object_u16(mut out, 0x8664)
	object_u16(mut out, 2)
	object_u32(mut out, 0)
	object_u32(mut out, u32(symtab_at))
	object_u32(mut out, 3)
	object_u16(mut out, 0)
	object_u16(mut out, 0)
	object_section(mut out, '.text', text.len, text_at, text_reloc_at, text_relocs.len,
		0x60000020)
	object_section(mut out, '.rdata', rodata.len, rodata_at, rodata_reloc_at,
		rodata_relocs.len, 0x40000040)
	out << text
	out << rodata
	for table in [text_relocs, rodata_relocs] {
		for relocation in table {
			object_u32(mut out, relocation.offset)
			object_u32(mut out, relocation.symbol)
			object_u16(mut out, relocation.kind)
		}
	}
	// Symbol 0 is a name inside the code, and 1 and 2 are the section symbols
	// the reader needs to know where each section went.
	object_symbol(mut out, 'target', 8, 1, 0x20, 2)
	object_symbol(mut out, '.text', 0, 1, 0, 3)
	object_symbol(mut out, '.rdata', 0, 2, 0, 3)
	object_u32(mut out, 4)
	return out
}

// Every type this shell reads is one a link needs and a compiler does not write:
// a section index, a section offset, a seven-bit section offset, and a
// span-dependent displacement with the pair entry that marks it.
fn test_the_section_relative_and_span_types_are_read() {
	bytes := build_object_with([TestReloc{ offset: 0, symbol: 0, kind: 0x0e }], [
		TestReloc{ offset: 0, symbol: 2, kind: 0x0a },
		TestReloc{ offset: 2, symbol: 2, kind: 0x0b },
		TestReloc{ offset: 6, symbol: 2, kind: 0x0c },
	])
	mut selected := map[string]bool{}
	program := read_unit_selecting(bytes, windows(), mut selected) or {
		panic('the reader refused an object carrying the section-relative types: ${err.msg()}')
	}
	assert program.relocations.len == 4, 'a pair entry takes no field and the other four do: ${program.relocations.len}'
	span := program.relocations[0]
	assert span.kind == unit.RelocationKind.span
	assert span.addend == -4
	section_index := program.relocations[1]
	assert section_index.kind == unit.RelocationKind.section_index
	assert section_index.width == unit.RelocationWidth.halfword
	secrel := program.relocations[2]
	assert secrel.kind == unit.RelocationKind.secrel
	assert secrel.width == unit.RelocationWidth.narrow
	secrel7 := program.relocations[3]
	assert secrel7.kind == unit.RelocationKind.secrel7
	assert secrel7.width == unit.RelocationWidth.octet
}

// A pair entry with nothing above it is a file whose relocations were not
// written the way the format says, and it is named rather than ignored.
fn test_a_pair_with_nothing_to_pair_with_is_refused() {
	bytes := build_object_with([TestReloc{ offset: 0, symbol: 0, kind: 0x0f }], [])
	mut selected := map[string]bool{}
	if _ := read_unit_selecting(bytes, windows(), mut selected) {
		assert false, 'the reader accepted a PAIR entry that follows no span-dependent relocation'
	} else {
		assert err.msg().contains('PAIR'), err.msg()
	}
}
