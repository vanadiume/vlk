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
		symbol:  '__imp_ExitProcess'
		library: 'kernel32.dll'
	}
	part.relocations << unit.Relocation{
		offset: 11
		place:  .text
		kind:   .direct
		name:   '__imp_ExitProcess'
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

fn test_a_call_through_a_slot_reaches_the_import_address_table() {
	windows := target.windows_x86_64()
	image := write(exiting(42), windows, .executable)!
	// The instruction is `call [rip + disp]`, the shape a compiler writes when
	// it saw `dllimport`, and its displacement points at the address table's
	// first entry: the loader writes the function's address there.
	field := 0x1000 + 11
	written := i32(u32_at(image, raw_offset(image, field)))
	slot := first_thunk(image)
	assert int(field) + 4 + int(written) == slot, 'the call points at ${int(field) + 4 + int(written)} and the slot is at ${slot}'
}

// exit_by_call is a program whose call to the import is direct: `call rel32`,
// which is what a compiler writes without `dllimport`. The callee's address is
// not known until the image is mapped, so the call reaches a thunk at the end of
// the code and the thunk jumps through the slot.
fn exit_by_call(status u8) unit.Program {
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
		u8(0xe8),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // call ExitProcess
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
		offset: 10
		place:  .text
		kind:   .direct
		name:   'ExitProcess'
		addend: -4
		width:  .narrow
	}
	return part
}

fn test_a_direct_call_reaches_a_thunk_that_jumps_through_the_slot() {
	windows := target.windows_x86_64()
	image := write(exit_by_call(42), windows, .executable)!
	// The direct call's field is at offset 10, and it holds the distance to a
	// thunk: six bytes of code that jump through the import's slot.
	field := 0x1000 + 10
	written := i32(u32_at(image, raw_offset(image, field)))
	reached := i32(field + 4) + written
	at := raw_offset(image, int(reached))
	assert at > 0
	assert image[at] == u8(0xff), 'the call points at ${reached}, and a thunk begins with 0xff'
	assert image[at + 1] == u8(0x25), 'the thunk jumps through a slot'
	slot := first_thunk(image)
	thunk_disp := i32(u32_at(image, at + 2))
	assert int(reached) + 6 + thunk_disp == slot, 'the thunk points at ${int(reached) + 6 + thunk_disp} and the slot is at ${slot}'
	path := os.join_path(scratch_dir(), 'thunk.exe')
	os.write_file_array(path, image) or { panic(err) }
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping the run: no wine on this machine')
		return
	}
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', path])
	assert result.exit_code == 42, 'wine left with ${result.exit_code}: ${result.output}'
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

fn u16_at(bytes []u8, at int) u16 {
	return u16(bytes[at]) | (u16(bytes[at + 1]) << 8)
}

// Thread-local storage is the one place a PE image tells the loader to make a
// copy per thread. The image holds the template, a four-byte slot for the index
// the loader hands out, and a directory naming both; the code reads the index,
// walks the thread's own array out of the TEB, and exits with the value it found.
// Running it is the whole check: an index the loader never wrote, or a template
// it never copied, leaves a status that is not the one the template holds.
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

fn test_a_thread_local_value_is_read_out_of_the_thread_s_copy() {
	windows := target.windows_x86_64()
	mut part := unit.Program{}
	part.text = [
		u8(0x8b),
		u8(0x05),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // mov eax, [rip + _tls_index]
		u8(0x65),
		u8(0x48),
		u8(0x8b),
		u8(0x0c),
		u8(0x25),
		u8(0x58),
		u8(0),
		u8(0),
		u8(0), // mov rcx, gs:[0x58]
		u8(0x48),
		u8(0x8b),
		u8(0x0c),
		u8(0xc1), // mov rcx, [rcx + rax*8]
		u8(0x8b),
		u8(0x01), // mov eax, [rcx]
		u8(0x89),
		u8(0xc1), // mov ecx, eax
		u8(0x48),
		u8(0x83),
		u8(0xec),
		u8(0x28), // sub rsp, 0x28
		u8(0xff),
		u8(0x15),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // call [rip + 0]
		u8(0x48),
		u8(0x83),
		u8(0xc4),
		u8(0x28),
		u8(0xc3),
	]
	part.tls_blob = [u8(7), u8(0), u8(0), u8(0)]
	part.tls_size = 4
	part.tls_alignment = 4
	part.labels['main'] = 0
	part.defined['main'] = true
	part.entry_place = 0
	part.imports << 'ExitProcess'
	part.imports_by_library << unit.Import{
		name:    'ExitProcess'
		symbol:  '__imp_ExitProcess'
		library: 'kernel32.dll'
	}
	part.relocations << unit.Relocation{
		offset: 2
		place:  .text
		kind:   .direct
		name:   '_tls_index'
		addend: -4
		width:  .narrow
	}
	part.relocations << unit.Relocation{
		offset: 29
		place:  .text
		kind:   .direct
		name:   '__imp_ExitProcess'
		addend: -4
		width:  .narrow
	}
	image := write(part, windows, .executable)!
	// The directory is the ninth, and its three addresses are the template's
	// start and end and the index slot.
	directories := pe_header_offset + 4 + 20 + 112
	directory_rva := u32_at(image, directories + 9 * 8)
	assert directory_rva != 0
	at := raw_offset(image, int(directory_rva))
	// The four addresses are eight bytes each, so the low halves are what a
	// four-byte read gives and the difference between them is the template's
	// length.
	start := u32_at(image, at)
	end := u32_at(image, at + 8)
	assert end - start == 4
	assert u32_at(image, at + 16) > 0 // the index slot
	assert u32_at(image, at + 24) == 0 // no callbacks
	assert u32_at(image, at + 32) == 0 // the whole template is initialized
	path := os.join_path(scratch_dir(), 'tls.exe')
	os.write_file_array(path, image) or { panic(err) }
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping the run: no wine on this machine')
		return
	}
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', path])
	assert result.exit_code == 7, 'wine left with ${result.exit_code}: ${result.output}'
}

fn test_a_fixup_is_rewritten_into_an_instruction_that_reaches_the_import_slot() {
	windows := target.windows_x86_64()
	mut part := unit.Program{}
	// The shadow space a Windows call needs, the status into the register the
	// callee reads, then the call through the import's slot. The call is the
	// fixup: six bytes, with the register left empty because a call reads
	// nothing into one.
	part.text = [
		u8(0x48),
		u8(0x83),
		u8(0xec),
		u8(0x28), // sub rsp, 0x28
		u8(0xb9),
		u8(42),
		u8(0),
		u8(0),
		u8(0), // mov ecx, 42
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
	part.fixups << unit.Fixup{
		start:  9
		length: 6
		kind:   .call_import
		name:   'ExitProcess'
	}
	image := write(part, windows, .executable)!
	// The slot is the first entry of the address table, and the call's
	// displacement is measured from the end of the instruction.
	slot := first_thunk(image)
	written := i32(u32_at(image, raw_offset(image, 0x1000 + 11)))
	assert written == i32(slot - 0x100f), 'the call points at ${written} and the slot is at ${slot - 0x100f}'
	path := os.join_path(scratch_dir(), 'fixup.exe')
	os.write_file_array(path, image) or { panic(err) }
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping the run: no wine on this machine')
		return
	}
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', path])
	assert result.exit_code == 42, 'wine left with ${result.exit_code}: ${result.output}'
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

fn test_a_data_fixup_writes_the_address_and_records_it_for_the_loader() {
	windows := target.windows_x86_64()
	mut part := returning()
	part.globals_blob = []u8{len: 8}
	part.globals['handler'] = unit.GlobalSlot{
		offset: 0
		width:  8
	}
	part.data_fixups << unit.DataFixup{
		offset: 0
		kind:   .function_address
		name:   'main'
	}
	image := write(part, windows, .executable)!
	directories := pe_header_offset + 4 + 20 + 112
	// The sections are the code and the writable data, so the data is at the
	// second page and the address written is the image's base plus the code's.
	data_rva := 0x2000
	at := raw_offset(image, data_rva)
	// The image's base is 0x140000000, so the address is that plus the code's.
	assert u32_at(image, at) == 0x40001000
	assert u32_at(image, at + 4) == 0x1
	reloc_rva := u32_at(image, directories + 5 * 8)
	assert reloc_rva != 0
	assert u32_at(image, raw_offset(image, int(reloc_rva)) + 8) == 0xA000 | (data_rva & 0xfff)
}

// A DLL is an executable whose exports another image calls, and the name it
// records is the name an import table asks for. The test writes both halves and
// runs the second: a loader that never found the export would stop before the
// status the function returns.
fn answer_dll() unit.Program {
	mut part := unit.Program{}
	part.text = [u8(0xb8), u8(42), u8(0), u8(0), u8(0), u8(0xc3)] // mov eax, 42; ret
	part.labels['answer'] = 0
	part.defined['answer'] = true
	part.entry_place = 0
	part.exports << unit.Export{
		name:     'answer'
		ordinal:  1
		function: true
	}
	return part
}

fn calling_answer() unit.Program {
	mut part := unit.Program{}
	part.text = [
		u8(0x48),
		u8(0x83),
		u8(0xec),
		u8(0x28), // sub rsp, 0x28
		u8(0xff),
		u8(0x15),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // call [rip + answer]
		u8(0x89),
		u8(0xc1), // mov ecx, eax
		u8(0xff),
		u8(0x15),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // call [rip + ExitProcess]
		u8(0x48),
		u8(0x83),
		u8(0xc4),
		u8(0x28),
		u8(0xc3),
	]
	part.labels['main'] = 0
	part.defined['main'] = true
	part.entry_place = 0
	part.imports << 'answer'
	part.imports << 'ExitProcess'
	part.imports_by_library << unit.Import{
		name:    'answer'
		symbol:  '__imp_answer'
		library: 'answer.dll'
	}
	part.imports_by_library << unit.Import{
		name:    'ExitProcess'
		symbol:  '__imp_ExitProcess'
		library: 'kernel32.dll'
	}
	part.relocations << unit.Relocation{
		offset: 6
		place:  .text
		kind:   .direct
		name:   '__imp_answer'
		addend: -4
		width:  .narrow
	}
	// The second call's field begins at 14, and the instruction ends at 18.
	part.relocations << unit.Relocation{
		offset: 14
		place:  .text
		kind:   .direct
		name:   '__imp_ExitProcess'
		addend: -4
		width:  .narrow
	}
	return part
}

fn test_a_dll_exports_a_name_and_an_image_that_imports_it_runs() {
	windows := target.windows_x86_64()
	dll := write_options(answer_dll(), windows, .dll, Options{
		dll_name: 'answer.dll'
	})!
	exe := write(calling_answer(), windows, .executable)!
	dir := scratch_dir()
	dll_path := os.join_path(dir, 'answer.dll')
	exe_path := os.join_path(dir, 'caller.exe')
	os.write_file_array(dll_path, dll) or { panic(err) }
	os.write_file_array(exe_path, exe) or { panic(err) }
	// The headers say what the file is, and the export table names the
	// function at the address its code was placed at.
	directories := pe_header_offset + 4 + 20 + 112
	assert u32_at(dll, directories) != 0
	assert u32_at(dll, directories + 4) == 40
	reader := '/usr/bin/llvm-readobj'
	if os.exists(reader) {
		headers := os.exec([reader, '--file-headers', '--coff-exports', dll_path])
		assert headers.exit_code == 0, headers.output
		assert headers.output.contains('IMAGE_FILE_DLL')
		assert headers.output.contains('answer')
		assert headers.output.contains('ExportTableRVA: ')
	}
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping the run: no wine on this machine')
		return
	}
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', exe_path])
	assert result.exit_code == 42, 'wine left with ${result.exit_code}: ${result.output}'
}

fn test_a_debug_directory_names_the_pdb_and_the_record_beside_it() {
	windows := target.windows_x86_64()
	mut guid := [16]u8{}
	for i in 0 .. 16 {
		guid[i] = u8(i + 1)
	}
	image := write_options(returning(), windows, .executable, Options{
		pdb_path: 'C:\\build\\unit.pdb'
		pdb_guid: guid
		pdb_age:  3
	})!
	directories := pe_header_offset + 4 + 20 + 112
	assert u32_at(image, directories + 6 * 8) != 0
	assert u32_at(image, directories + 6 * 8 + 4) == 28
	path := os.join_path(scratch_dir(), 'debug.exe')
	os.write_file_array(path, image) or { panic(err) }
	reader := '/usr/bin/llvm-readobj'
	if !os.exists(reader) {
		eprintln('skipping the read: no llvm-readobj on this machine')
		return
	}
	result := os.exec([reader, '--coff-debug-directory', '--codeview', path])
	assert result.exit_code == 0, result.output
	// `llvm-readobj` decodes the record rather than printing its four-letter
	// signature, so the check is on the fields it read out.
	assert result.output.contains('unit.pdb')
	assert result.output.contains('PDBSignature: 0x53445352')
	assert result.output.contains('PDBAge: 3')
	assert result.output.contains('Type: CodeView')
}

fn test_a_dll_without_a_name_is_refused() {
	if _ := write_options(answer_dll(), target.windows_x86_64(), .dll, Options{}) {
		assert false, 'a DLL records the name another image imports it by'
	} else {
		assert err.msg().contains('name')
	}
}

fn test_an_export_the_image_does_not_define_is_refused() {
	mut part := answer_dll()
	part.exports << unit.Export{
		name:     'missing'
		function: true
	}
	if _ := write_options(part, target.windows_x86_64(), .dll, Options{
		dll_name: 'answer.dll'
	}) {
		assert false, 'an exported name with no definition is a fault handed to another image'
	} else {
		assert err.msg().contains('missing')
	}
}

// A section-relative field names a place inside a section rather than an address
// in the image, and a span-dependent field holds a displacement the assembler
// left for the link. Neither changes when the image is mapped somewhere else, so
// neither is a base relocation site. The numbers here are read out of the image
// the way a debugger reads them: the section's index, the byte's offset from the
// section's first byte, and the distance to the label.
fn test_section_relative_and_span_fields_are_written_against_their_sections() {
	windows := target.windows_x86_64()
	mut part := unit.Program{}
	part.text = [
		u8(0xe8),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // call inner
		u8(0xc3), // ret, the entry
		u8(0xcc),
		u8(0xcc), // padding to the label
		u8(0xc3), // inner: ret
	]
	part.labels['main'] = 0
	part.labels['inner'] = 8
	part.defined['main'] = true
	part.defined['inner'] = true
	part.entry_place = 0
	part.sections << unit.Section{
		name:      '.rdataf'
		data:      [u8(0), u8(0), u8(0), u8(0), u8(0), u8(0), u8(0x80)]
		alignment: 4
		kind:      .read_only
	}
	part.relocations << unit.Relocation{
		offset: 1
		place:  .text
		kind:   .span
		name:   'inner'
		addend: -4
		width:  .narrow
	}
	part.relocations << unit.Relocation{
		offset:  0
		place:   .section
		section: '.rdataf'
		kind:    .section_index
		name:    'inner'
		width:   .halfword
	}
	part.relocations << unit.Relocation{
		offset:  2
		place:   .section
		section: '.rdataf'
		kind:    .secrel
		name:    'inner'
		width:   .narrow
	}
	part.relocations << unit.Relocation{
		offset:  6
		place:   .section
		section: '.rdataf'
		kind:    .secrel7
		name:    'inner'
		width:   .octet
	}
	image := write(part, windows, .executable)!
	// The code is the first section, so the label at offset 8 is 0x1008 and the
	// field at offset 1 is 0x1001: eight plus the distance from the end of the
	// field is three.
	span := i32(u32_at(image, raw_offset(image, 0x1001)))
	assert span == 3, 'the span field says ${span}'
	// The named section is placed after the blobs, so its address is read from
	// the section table rather than assumed.
	named := section_rva(image, '.rdataf')
	at := raw_offset(image, named)
	assert section_rva(image, '.text') == 0x1000
	assert int(u16_at(image, at)) == 1, 'the section index of the code is 1'
	assert int(u32_at(image, at + 2)) == 8, 'the offset inside the code is 8'
	assert image[at + 6] == u8(0x88), 'the seven-bit offset keeps the byte high bit: ${image[at + 6]}'
}

// section_rva reads one section's address out of the section table, by name.
fn section_rva(image []u8, name string) int {
	sections := u16_at(image, pe_header_offset + 4 + 2)
	table := pe_header_offset + 4 + coff_header_size + int(u16_at(image, pe_header_offset + 4 + 16))
	for i in 0 .. int(sections) {
		at := table + i * section_header_size
		if name_in_row(image, at, name) {
			return int(u32_at(image, at + 12))
		}
	}
	return -1
}

// name_in_row compares a section header's eight-byte name with a string, which is
// how a test finds a section the writer placed.
fn name_in_row(image []u8, at int, name string) bool {
	for i, c in name.bytes() {
		if i >= 8 || image[at + i] != c {
			return false
		}
	}
	return true
}
