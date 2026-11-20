module coff

import os

// The import member reader is checked against members built here byte for byte,
// because every field of a 20-byte header and every terminator is something the
// test can state and the reader has to agree with. One test reads a library a
// librarian wrote, which is the only way to know the reader agrees with the
// format rather than with this file's idea of it.

// ImportSpec is one import member to build. Every field is written as the spec
// holds it, except SizeOfData, where zero means the length of the two strings,
// so a well formed member needs no count and a wrong one states its own.
struct ImportSpec {
mut:
	symbol  string
	library string
	// exported is the third string a member carries when the DLL exports a
	// name other than the symbol it defines. Empty writes two strings.
	exported     string
	kind         u16
	name_type    u16
	ordinal_hint u16
	version      u16
	machine      u16
	stamp        u32
	sig1         u16
	sig2         u16
	size_of_data u32
}

// named_import is a member an archive writes for one export reached by name.
fn named_import(symbol string, library string, kind u16) ImportSpec {
	return ImportSpec{
		symbol:    symbol
		library:   library
		kind:      kind
		name_type: 1
		machine:   image_file_machine_amd64
		stamp:     0x5f3c2a1b
		sig2:      0xffff
	}
}

// build_import_member writes a member the way an archive holds it: the 20-byte
// header, then the symbol name and the DLL name, each NUL terminated. The bytes
// after the header are the whole string area, so a SizeOfData the test writes
// can disagree with what the member holds.
fn build_import_member(spec ImportSpec) []u8 {
	mut area := []u8{}
	area << spec.symbol.bytes()
	area << u8(0)
	area << spec.library.bytes()
	area << u8(0)
	if spec.exported != '' {
		area << spec.exported.bytes()
		area << u8(0)
	}
	mut size := spec.size_of_data
	if size == 0 {
		size = u32(area.len)
	}
	mut bytes := []u8{len: import_header_size + area.len, init: u8(0)}
	import_put_u16(mut bytes, 0, spec.sig1)
	import_put_u16(mut bytes, 2, spec.sig2)
	import_put_u16(mut bytes, 4, spec.version)
	import_put_u16(mut bytes, 6, spec.machine)
	import_put_u32(mut bytes, 8, spec.stamp)
	import_put_u32(mut bytes, 12, size)
	import_put_u16(mut bytes, 16, spec.ordinal_hint)
	import_put_u16(mut bytes, 18, (spec.name_type << import_name_type_shift) | spec.kind)
	for i, byte in area {
		bytes[import_header_size + i] = byte
	}
	return bytes
}

fn import_put_u16(mut bytes []u8, at int, value u16) {
	bytes[at] = u8(value & 0xff)
	bytes[at + 1] = u8((value >> 8) & 0xff)
}

fn import_put_u32(mut bytes []u8, at int, value u32) {
	for i in 0 .. 4 {
		bytes[at + i] = u8((value >> (8 * i)) & 0xff)
	}
}

// import_reader_error is what a member refused by name says. A refusal that
// names the wrong problem is as bad as a member read wrongly, so every refusal
// test checks the words as well as the failure.
fn import_reader_error(bytes []u8) string {
	member := read_import_member(bytes) or { return err.msg() }
	return 'the member was read as symbol ${member.name} of ${member.library}'
}

fn test_import_a_code_symbol_is_read_by_name() {
	spec := named_import('foo', 'mylib.dll', import_code)
	member := read_import_member(build_import_member(spec))!
	assert member.machine == image_file_machine_amd64
	assert member.time_date_stamp == 0x5f3c2a1b
	assert member.name == 'foo'
	assert member.library == 'mylib.dll'
	assert member.kind == import_code
	assert member.hint == 0
	assert !member.by_ordinal
}

// The archive index names `__imp_foo` for the same export, and a member that
// spells the prefix is not the same name as one that does not. The reader keeps
// the text it was given.
fn test_import_an_imported_pointer_keeps_its_prefix() {
	spec := named_import('__imp_foo', 'mylib.dll', import_code)
	member := read_import_member(build_import_member(spec))!
	assert member.name == '__imp_foo'
	assert member.library == 'mylib.dll'
	assert !member.by_ordinal
}

// A data import by number: the name type is zero, which is the format's
// IMPORT_ORDINAL, and the Ordinal/Hint field holds the export number.
fn test_import_a_data_symbol_by_ordinal_is_read() {
	mut spec := named_import('bar', 'mylib.dll', import_data)
	spec.name_type = 0
	spec.ordinal_hint = 7
	member := read_import_member(build_import_member(spec))!
	assert member.kind == import_data
	assert member.by_ordinal
	assert member.hint == 7
	assert member.name == 'bar'
	assert member.library == 'mylib.dll'
}

// The high bit of the Ordinal/Hint field is the other way a member says it
// imports by number, and a reader that ignored it would report a hint where the
// export number is.
fn test_import_a_member_that_sets_the_ordinal_bit_is_read_by_number() {
	mut spec := named_import('bar', 'mylib.dll', import_data)
	// The name type says by name, which is what every writer checked here
	// uses, so the high bit is the only thing left saying by number.
	spec.name_type = 1
	spec.ordinal_hint = 0x8000 | 7
	member := read_import_member(build_import_member(spec))!
	assert member.by_ordinal
	assert member.hint == 7
}

fn test_import_a_const_import_is_read() {
	spec := named_import('limit', 'mylib.dll', import_const)
	member := read_import_member(build_import_member(spec))!
	assert member.kind == import_const
	assert member.name == 'limit'
}

// A name is not eight bytes in this format, and the two names together are the
// only thing a member's size is made of, so their lengths are what a reader
// gets wrong when it reads a fixed field.
fn test_import_a_long_symbol_and_library_name_are_read() {
	symbol := 'a_symbol_a_linker_has_to_read_whole_' + 'and_then_some_more_of_it'.repeat(4)
	library := 'a_library_with_a_long_file_name_' + 'and_a_long_directory_before_it'.repeat(3) + '.dll'
	assert symbol.len > 100
	assert library.len > 100
	spec := named_import(symbol, library, import_code)
	member := read_import_member(build_import_member(spec))!
	assert member.name == symbol
	assert member.library == library
	assert member.name.len == symbol.len
}

// An object's header begins with the machine, which is never the zero that the
// import signature's first field holds, and an empty member has no signature at
// all. Neither is an import member.
fn test_import_the_signature_is_told_apart_from_an_object_and_from_nothing() {
	assert is_import_member(build_import_member(named_import('foo', 'mylib.dll', import_code)))
	assert !is_import_member([]u8{})
	assert !is_import_member([u8(0), u8(0)])
	// An amd64 COFF object header: the machine, a section count, no optional
	// header, and the characteristics a compiler writes.
	object := [u8(0x64), u8(0x86), u8(0x01), u8(0x00), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		u8(0x00), u8(0x00)]
	assert !is_import_member(object)
	assert import_reader_error(object).contains('rather than the 0 and 0xffff')
	// An archive's first linker member starts with the number of symbols it
	// indexes, so it is not an import member either.
	mut not_an_import := build_import_member(named_import('foo', 'mylib.dll', import_code))
	not_an_import[3] = u8(0xfe)
	assert !is_import_member(not_an_import)
	// The signature is four bytes, so a member cut to them is still answered
	// for: the caller can tell an import from an object before it decides how
	// long the member is.
	assert is_import_member([u8(0), u8(0), u8(0xff), u8(0xff)])
}

// The null import descriptor carries the signature and nothing else. It is the
// member an archive puts in the table so the table has an entry to point the
// last import at, and it is not an import: reading it would hand a link a
// symbol with no name.
fn test_import_the_null_descriptor_is_refused_by_name() {
	mut null_descriptor := []u8{len: import_header_size, init: u8(0)}
	import_put_u16(mut null_descriptor, 2, 0xffff)
	assert is_import_member(null_descriptor)
	message := import_reader_error(null_descriptor)
	assert message.contains('null import descriptor')
}

fn test_import_a_truncated_header_is_refused() {
	full := build_import_member(named_import('foo', 'mylib.dll', import_code))
	message := import_reader_error(full[..10])
	assert message.contains('truncated')
	assert message.contains('10 bytes')
	empty_message := import_reader_error([]u8{})
	assert empty_message.contains('truncated')
}

// SizeOfData counts the strings. A count that reaches past the member cannot be
// trusted for the length of a name, so the member is refused rather than read
// to the end of the slice it happens to sit in.
fn test_import_a_string_area_past_the_member_is_refused() {
	mut spec := named_import('foo', 'mylib.dll', import_code)
	spec.size_of_data = u32(spec.symbol.len + 1 + spec.library.len + 1 + 8)
	member := build_import_member(spec)
	message := import_reader_error(member)
	assert message.contains('string area ends at')
	assert message.contains('truncated')
}

fn test_import_a_symbol_name_without_a_terminator_is_refused() {
	mut spec := named_import('foo', 'mylib.dll', import_code)
	// The area covers the three bytes of the name and stops, so the name has
	// no terminator inside it.
	spec.size_of_data = 3
	member := build_import_member(spec)
	message := import_reader_error(member)
	assert message.contains('symbol name')
	assert message.contains('no terminator')
}

fn test_import_a_library_name_without_a_terminator_is_refused() {
	mut spec := named_import('foo', 'mylib.dll', import_code)
	// The area holds the symbol, its terminator, and three bytes of the DLL
	// name, which is not enough to reach the second terminator.
	spec.size_of_data = 3 + 1 + 3
	member := build_import_member(spec)
	message := import_reader_error(member)
	assert message.contains('DLL name')
	assert message.contains('no terminator')
}

fn test_import_an_empty_symbol_name_is_refused() {
	spec := named_import('', 'mylib.dll', import_code)
	member := build_import_member(spec)
	message := import_reader_error(member)
	assert message.contains('names no symbol')
}

fn test_import_a_type_past_const_is_refused() {
	mut spec := named_import('foo', 'mylib.dll', import_code)
	spec.kind = 3
	member := build_import_member(spec)
	message := import_reader_error(member)
	assert message.contains('type 3')
	assert message.contains('code, data and const')
}

// A library a librarian wrote is the input this reader exists for. It is built
// here rather than committed, and skipped when the machine has no librarian.
fn test_import_a_library_a_librarian_wrote_is_read() {
	dlltool := os.find_abs_path_of_executable('llvm-dlltool') or {
		eprintln('skipping: no llvm-dlltool on this machine to write an import library with')
		return
	}
	dir := os.join_path(os.temp_dir(), 'vlk_import_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer {
		os.rmdir_all(dir) or {}
	}
	// One export by name, one by name with an ordinal as its hint, and one by
	// number only, which is the member that states the name type the reader
	// has to believe.
	os.write_file(os.join_path(dir, 'mylib.def'),
		'LIBRARY mylib.dll\nEXPORTS\n  foo\n  bar @7\n  baz @9 NONAME\n') or {
		panic(err)
	}
	library := os.join_path(dir, 'mylib.lib')
	result := os.exec([dlltool, '-m', 'i386:x86-64', '-d', os.join_path(dir, 'mylib.def'), '-l',
		library])
	if result.exit_code != 0 {
		eprintln('skipping: llvm-dlltool could not write the library: ${result.output}')
		return
	}
	archive := os.read_bytes(library) or { panic(err) }
	// Walk the archive the way its headers describe it: an 8-byte signature,
	// then 60-byte headers whose size is decimal at offset 48, each member
	// padded to an even offset.
	mut at := 8
	mut by_name := map[string]ImportMember{}
	mut members := 0
	for at + 60 <= archive.len {
		size_text := archive[at + 48..at + 58].bytestr().trim_space()
		size := size_text.int()
		if size <= 0 || at + 60 + size > archive.len {
			break
		}
		member := archive[at + 60..at + 60 + size]
		if is_import_member(member) {
			imported := read_import_member(member)!
			by_name[imported.name] = imported
			members++
		}
		at = at + 60 + size
		if at % 2 != 0 {
			at++
		}
	}
	assert members == 3
	// The three members are the three exports, and each names the library it
	// imports from.
	assert by_name.len == 3
	assert 'foo' in by_name
	assert 'bar' in by_name
	assert 'baz' in by_name
	assert by_name['foo'].library == 'mylib.dll'
	assert by_name['foo'].kind == import_code
	assert !by_name['foo'].by_ordinal
	// A member that imports by name carries the ordinal as a hint, and the
	// reader reports it as a hint rather than as the number the export has.
	assert !by_name['bar'].by_ordinal
	assert by_name['bar'].hint == 7
	// The member that states no name type is the by-number one. Nothing in
	// its Ordinal/Hint field marks it, so a reader that looked only at the
	// high bit would report a hint of nine for an import of export nine.
	assert by_name['baz'].by_ordinal
	assert by_name['baz'].hint == 9
	assert by_name['baz'].kind == import_code
}

// A member that defines the slot's spelling while the DLL exports the bare name
// carries a third string saying so. Without it the linker would ask the DLL for
// `__imp_foo`, which no DLL exports.
fn test_import_a_member_names_the_name_the_dll_exports() {
	mut spec := named_import('__imp_foo', 'mylib.dll', import_data)
	spec.exported = 'foo'
	member := read_import_member(build_import_member(spec))!
	assert member.name == '__imp_foo'
	assert member.exported == 'foo'
	assert member.library == 'mylib.dll'
	assert !member.by_ordinal
}

// A member whose two names agree carries two strings, and the export name is
// then the symbol name.
fn test_import_a_member_with_two_strings_exports_its_symbol() {
	member := read_import_member(build_import_member(named_import('foo', 'mylib.dll',
		import_code)))!
	assert member.name == 'foo'
	assert member.exported == ''
}
