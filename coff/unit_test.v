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
