module pe

import os
import vanadiume.vlk.target
import vanadiume.vlk.unit

// The writer is checked the way the tree checks an image: the file is written,
// the system is handed it, and the status it leaves with is read back. Wine is
// not Windows, but it is a loader that reads the same headers and applies the
// same relocations, and an image that runs there is an image whose tables point
// where they say.
//
// `llvm-readobj` is the second opinion. It reads the headers, the sections and
// the import directory without knowing anything this tree does, so what it prints
// is a check on the numbers rather than on the writer's idea of them.

fn scratch_dir() string {
	dir := os.join_path(os.temp_dir(), 'vlk_pe_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	return dir
}

// exiting is a unit that calls ExitProcess with the status 42 and returns. The
// call goes through the import's slot in the address table: `call [rip + d]`,
// where the displacement is filled with the slot's address minus the end of the
// field. Nothing here is a stub, because a PE image does not need one.
fn exiting(status u8) unit.Program {
	mut part := unit.Program{}
	part.text = [
		u8(0x48),
		u8(0x83),
		u8(0xec),
		u8(0x28), // sub rsp, 0x28
		u8(0xb9),
		status,
		u8(0),
		u8(0),
		u8(0), // mov ecx, status
		u8(0xff),
		u8(0x15),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // call [rip + 0]
		u8(0x48),
		u8(0x83),
		u8(0xc4),
		u8(0x28), // add rsp, 0x28
		u8(0xc3), // ret
	]
	part.labels['main'] = 0
	part.defined['main'] = true
	part.entry_place = 0
	part.imports << 'ExitProcess'
	part.imports_by_library << unit.Import{
		name:    'ExitProcess'
		library: 'kernel32.dll'
	}
	part.relocations << unit.Relocation{
		offset: 11
		place:  .text
		kind:   .direct
		name:   'ExitProcess'
		addend: -4
		width:  .narrow
	}
	return part
}

// returning is a unit whose code is one `ret`, for the tests that ask about a
// header or a table rather than about what the program does.
fn returning() unit.Program {
	mut part := unit.Program{}
	part.text = [u8(0xc3)]
	part.labels['main'] = 0
	part.defined['main'] = true
	part.entry_place = 0
	return part
}

fn u32_at(bytes []u8, at int) u32 {
	mut value := u32(0)
	for i in 0 .. 4 {
		value |= u32(bytes[at + i]) << (8 * i)
	}
	return value
}

fn test_an_image_that_calls_exit_process_exits_with_the_status_it_asked_for() {
	windows := target.windows_x86_64()
	image := write(exiting(42), windows, .executable)!
	// The signature is where the DOS header says it is, and the machine is the
	// one a Windows loader has to find.
	lfanew := u32_at(image, 0x3c)
	assert lfanew == pe_header_offset
	assert image[int(lfanew)..int(lfanew) + 4] == [u8(`P`), u8(`E`), u8(0), u8(0)]
	path := os.join_path(scratch_dir(), 'exit.exe')
	os.write_file_array(path, image) or { panic(err) }
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping the run: no wine on this machine')
		return
	}
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', path])
	assert result.exit_code == 42, 'wine left with ${result.exit_code}: ${result.output}'
}

fn test_a_reader_that_knows_nothing_of_this_tree_agrees_on_the_headers() {
	windows := target.windows_x86_64()
	image := write(exiting(42), windows, .executable)!
	path := os.join_path(scratch_dir(), 'headers.exe')
	os.write_file_array(path, image) or { panic(err) }
	reader := '/usr/bin/llvm-readobj'
	if !os.exists(reader) {
		eprintln('skipping: no llvm-readobj on this machine to read the image with')
		return
	}
	result := os.exec([reader, '--file-headers', '--sections', '--coff-imports', path])
	assert result.exit_code == 0, result.output
	output := result.output
	assert output.contains('IMAGE_FILE_MACHINE_AMD64')
	assert output.contains('Magic: 0x20B')
	assert output.contains('AddressOfEntryPoint: 0x1000')
	assert output.contains('ImageBase: 0x140000000')
	assert output.contains('SectionAlignment: 4096')
	assert output.contains('FileAlignment: 512')
	assert output.contains('Subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI')
	assert output.contains('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE')
	assert output.contains('ExitProcess')
	assert output.contains('kernel32.dll')
	assert output.contains('.text')
	assert output.contains('.idata')
}

fn test_the_import_slot_is_where_the_call_says_it_is() {
	windows := target.windows_x86_64()
	image := write(exiting(42), windows, .executable)!
	// The call's field is at offset 11 of the text, and it holds the slot's
	// address minus the end of the field: `call [rip + d]` reaches the slot.
	field := 0x1000 + 11
	slot := first_thunk(image)
	assert slot > 0
	written := i32(u32_at(image, raw_offset(image, field)))
	assert written == i32(slot - (field + 4)), 'the call points at ${written} and the slot is at ${slot - (field + 4)}'
}

// first_thunk is the address table of the first DLL in the import directory,
// read out of the descriptor the optional header points at.
fn first_thunk(image []u8) int {
	directories := pe_header_offset + 4 + 20 + 112
	import_rva := int(u32_at(image, directories + 8))
	if import_rva == 0 {
		return 0
	}
	at := raw_offset(image, import_rva + 16)
	return int(u32_at(image, at))
}

// raw_offset turns an address in an image into an offset in the file, by finding
// the section that holds the address in the section table. A reader of this
// tree's own image would be reading the writer's idea back; this walks the file
// the way any loader does.
fn raw_offset(image []u8, rva int) int {
	sections := u16_at(image, pe_header_offset + 4 + 2)
	table := pe_header_offset + 4 + coff_header_size + int(u16_at(image, pe_header_offset + 4 + 16))
	for i in 0 .. int(sections) {
		at := table + i * section_header_size
		virtual_address := int(u32_at(image, at + 12))
		virtual_size := int(u32_at(image, at + 8))
		if rva >= virtual_address && rva < virtual_address + virtual_size {
			return int(u32_at(image, at + 20)) + (rva - virtual_address)
		}
	}
	return -1
}

fn u16_at(bytes []u8, at int) u16 {
	return u16(bytes[at]) | (u16(bytes[at + 1]) << 8)
}

fn test_a_thread_local_program_is_refused_by_size() {
	mut part := returning()
	part.tls_size = 8
	if _ := write(part, target.windows_x86_64(), .executable) {
		assert false, 'a program with thread-local storage has no image from this writer'
	} else {
		assert err.msg().contains('thread-local storage')
	}
}

fn test_a_program_the_emitter_wrote_is_refused_for_its_fixups() {
	mut part := returning()
	part.fixups << unit.Fixup{
		start:  1
		length: 4
		kind:   .call_import
		name:   'ExitProcess'
	}
	if _ := write(part, target.windows_x86_64(), .executable) {
		assert false, 'a fixup is not a relocation and this writer has no rule for one'
	} else {
		assert err.msg().contains('fixups')
	}
}

fn test_a_dll_is_refused_until_an_export_table_exists() {
	if _ := write(returning(), target.windows_x86_64(), .dll) {
		assert false, 'a DLL needs an export table and this writer builds none'
	} else {
		assert err.msg().contains('DLL')
	}
}

fn test_an_absolute_field_gets_a_base_relocation() {
	mut part := returning()
	// Eight bytes of writable data holding the address of the entry, which is
	// the shape a table of function addresses has.
	part.globals_blob = []u8{len: 8}
	part.globals['handlers'] = unit.GlobalSlot{
		offset: 0
		width:  8
	}
	part.relocations << unit.Relocation{
		offset: 0
		place:  .data
		kind:   .absolute
		name:   'main'
		addend: 0
		width:  .wide
	}
	image := write(part, target.windows_x86_64(), .executable)!
	directories := pe_header_offset + 4 + 20 + 112
	reloc_rva := u32_at(image, directories + 5 * 8)
	assert reloc_rva != 0
	reader := '/usr/bin/llvm-readobj'
	if !os.exists(reader) {
		eprintln('skipping: no llvm-readobj on this machine to read the table with')
		return
	}
	path := os.join_path(scratch_dir(), 'absolute.exe')
	os.write_file_array(path, image) or { panic(err) }
	result := os.exec([reader, '--coff-basereloc', path])
	assert result.exit_code == 0, result.output
	assert result.output.contains('DIR64')
}

// A named section is what a COFF object brings that the three blobs cannot hold:
// `.pdata` and `.xdata` are sections of their own, and their references are
// measured inside the section rather than from a blob's start. The writer places
// them, fills the references with image-relative addresses, and names the
// exception directory the loader reads.
fn test_a_named_section_is_placed_and_its_references_are_image_relative() {
	windows := target.windows_x86_64()
	mut part := returning()
	part.sections << unit.Section{
		name:      '.xdata'
		kind:      .read_only
		alignment: 4
		data:      [u8(0x01), 0, 0, 0]
	}
	part.sections << unit.Section{
		name:      '.pdata'
		kind:      .read_only
		alignment: 4
		data:      []u8{len: 12}
	}
	part.relocations << unit.Relocation{
		offset:  0
		place:   .section
		section: '.pdata'
		kind:    .rva
		name:    'main'
		addend:  0
		width:   .narrow
	}
	part.relocations << unit.Relocation{
		offset:  4
		place:   .section
		section: '.pdata'
		kind:    .rva
		name:    'main'
		addend:  1
		width:   .narrow
	}
	part.relocations << unit.Relocation{
		offset:  8
		place:   .section
		section: '.pdata'
		kind:    .rva
		name:    '.xdata'
		addend:  0
		width:   .narrow
	}
	image := write(part, windows, .executable)!
	directories := pe_header_offset + 4 + 20 + 112
	// The sections go in the order the program carries them, so .xdata is the
	// second section and .pdata the third in this image.
	assert u32_at(image, directories + 3 * 8) == 0x3000
	assert u32_at(image, directories + 3 * 8 + 4) == 12
	entry := raw_offset(image, 0x3000)
	assert entry > 0
	assert u32_at(image, entry) == 0x1000
	assert u32_at(image, entry + 4) == 0x1001
	assert u32_at(image, entry + 8) == 0x2000
}

fn test_the_exception_table_is_sorted_by_the_address_each_entry_starts_at() {
	windows := target.windows_x86_64()
	mut part := returning()
	// Two entries, the later address written first, which is the shape a
	// merge of objects in input order produces.
	mut table := []u8{len: 24}
	put_u32(mut table, 0, 0x1400)
	put_u32(mut table, 12, 0x1000)
	part.sections << unit.Section{
		name:      '.pdata'
		kind:      .read_only
		alignment: 4
		data:      table
	}
	image := write(part, windows, .executable)!
	at := raw_offset(image, 0x2000)
	assert u32_at(image, at) == 0x1000
	assert u32_at(image, at + 12) == 0x1400
}

fn test_a_resource_section_is_placed_and_the_directory_names_it() {
	windows := target.windows_x86_64()
	mut part := returning()
	// A resource directory whose only content is a root node with no entries,
	// which is enough to prove the bytes are carried and the header points at
	// them. A real .rsrc comes from a resource compiler and is copied whole.
	part.sections << unit.Section{
		name:      '.rsrc'
		kind:      .read_only
		alignment: 4
		data:      []u8{len: 16}
	}
	image := write(part, windows, .executable)!
	directories := pe_header_offset + 4 + 20 + 112
	assert u32_at(image, directories + 2 * 8) == 0x2000
	assert u32_at(image, directories + 2 * 8 + 4) == 16
	at := raw_offset(image, 0x2000)
	for i in 0 .. 16 {
		assert image[at + i] == 0
	}
}

fn test_a_named_section_that_takes_a_blob_s_name_is_refused() {
	mut part := returning()
	part.sections << unit.Section{
		name: '.data'
		kind: .data
		data: [u8(1)]
	}
	if _ := write(part, target.windows_x86_64(), .executable) {
		assert false, 'the writer builds .data from the globals blob'
	} else {
		assert err.msg().contains('.data')
	}
}
