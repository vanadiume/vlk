module vlk

import vanadiume.vlk.coff
import vanadiume.vlk.elf
import vanadiume.vlk.input
import vanadiume.vlk.library
import os
import vanadiume.vlk.target
import vanadiume.vlk.unit

// The high entries, checked the only way that settles anything: an image is
// written, the kernel is handed it, and the status it leaves with is read back.
// A header that reads correctly and a program that does not run is the failure
// this file exists to catch.

fn host() target.Target {
	return target.host() or { panic('the link tests need the host target') }
}

// exiting is a unit whose entry stops the process with a status: `mov edi, code`,
// `mov eax, 60`, `syscall`, which is x86-64 Linux's exit call written out.
fn exiting(code u8) unit.Program {
	mut part := unit.Program{}
	part.text = [u8(0xbf), code, u8(0), u8(0), u8(0), u8(0xb8), u8(60), u8(0), u8(0), u8(0), u8(0x0f),
		u8(0x05)]
	part.defined['main'] = true
	part.labels['main'] = 0
	return part
}

fn scratch(name string) string {
	dir := os.join_path(os.temp_dir(), 'vlk_link_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	return os.join_path(dir, name)
}

fn run_image(path string) int {
	os.chmod(path, 0o755) or { panic(err) }
	result := os.exec([path])
	return result.exit_code
}

// le64 reads an eight-byte little-endian field, which is how the ELF header holds
// the two facts a position-independent link is checked against here.
fn le64(bytes []u8, at int) u64 {
	mut value := u64(0)
	for shift in [0, 8, 16, 24, 32, 40, 48, 56] {
		value |= u64(bytes[at + shift / 8]) << shift
	}
	return value
}

fn test_a_link_of_one_unit_answers_bytes_that_run() {
	bytes := link([exiting(42)], Options{
		entry:  'main'
		target: host()
	}) or { panic('the link failed: ${err.msg()}') }
	path := scratch('one')
	os.write_file_array(path, bytes) or { panic(err) }
	assert run_image(path) == 42
}

// A position-independent link is the shared object's container with an entry
// point: the kernel maps it wherever it likes and the loader adds that base to
// every address in the image. The unit here reaches its own code through the
// global offset table, so the status it leaves is the one it was asked for only
// if the loader relocated that slot. The bytes are checked for the header facts
// the kind is, and the image is run, because a header that reads correctly and a
// program that does not run is the failure this file exists to catch.
fn test_a_pie_link_is_dynamic_and_runs_where_the_kernel_put_it() {
	mut part := unit.Program{}
	part.text = [u8(0x48), u8(0x8d), u8(0x05), u8(0), u8(0), u8(0), u8(0), u8(0x48), u8(0x8b),
		u8(0x00), u8(0xff), u8(0xd0), u8(0xbf), u8(33), u8(0), u8(0), u8(0), u8(0xb8), u8(60),
		u8(0), u8(0), u8(0), u8(0x0f), u8(0x05)]
	part.defined['main'] = true
	part.labels['main'] = 0
	part.defined['stop'] = true
	part.labels['stop'] = 12
	part.imports << 'stop'
	part.bound['stop'] = unit.Definition{
		offset:   12
		function: true
	}
	part.fixups << unit.Fixup{
		start:    0
		length:   7
		kind:     .got_address
		name:     'stop'
		register: 'rax'
	}
	bytes := link([part], Options{
		entry:  'main'
		target: host()
		kind:   .pie
	}) or { panic('the link failed: ${err.msg()}') }
	// ET_DYN with a real entry point is the shape: the kernel maps the file at a
	// base it picked and jumps to that base plus e_entry.
	assert u16(bytes[16]) | (u16(bytes[17]) << 8) == u16(3)
	assert le64(bytes, 24) != 0
	path := scratch('pie')
	os.write_file_array(path, bytes) or { panic(err) }
	assert run_image(path) == 33
}

// The same kind with a name the C library answers: the image names libc, the
// loader maps it and writes `exit`'s address into the slot the code calls
// through, and the status the process leaves is the one the code put in edi. A
// pie that could not reach a library function would either refuse the link or die
// here.
fn test_a_pie_link_calls_a_library_function() {
	mut part := unit.Program{}
	part.text = [u8(0xbf), u8(5), u8(0), u8(0), u8(0), u8(0xff), u8(0x15), u8(0), u8(0), u8(0),
		u8(0), u8(0xb8), u8(60), u8(0), u8(0), u8(0), u8(0), u8(0x0f), u8(0x05)]
	part.defined['main'] = true
	part.labels['main'] = 0
	part.imports << 'exit'
	part.fixups << unit.Fixup{
		start:  5
		length: 6
		kind:   .call_import
		name:   'exit'
	}
	bytes := link([part], Options{
		entry:  'main'
		target: host()
		kind:   .pie
	}) or { panic('the link failed: ${err.msg()}') }
	path := scratch('pie_call')
	os.write_file_array(path, bytes) or { panic(err) }
	assert run_image(path) == 5
}

// A pointer in the writable data is a field the link settles, and an image a
// loader places settles it as an offset beside a relative entry: the loader adds
// the base it mapped the image at. The field here is written the way an object
// writes one, as a wide absolute relocation against a name the link defines, and
// the code reads it and calls what it holds. The exit status is the answer: a
// field left as a bare offset would call the first page of the address space.
fn test_a_pie_link_relocates_a_pointer_in_its_data() {
	mut part := unit.Program{}
	part.text = [u8(0x48), u8(0x8d), u8(0x05), u8(0), u8(0), u8(0), u8(0), // lea rax, [rip + held]
	u8(0x48), u8(0x8b), u8(0x00), // mov rax, [rax]
	u8(0xff), u8(0xd0), // call rax
	u8(0xbf), u8(21), u8(0), u8(0), u8(0), u8(0xb8), u8(60), u8(0), u8(0), u8(0), u8(0x0f), u8(0x05)]
	part.globals_blob = []u8{len: 8, init: u8(0)}
	part.globals['held'] = unit.GlobalSlot{
		offset: 0
		width:  8
	}
	part.defined['main'] = true
	part.labels['main'] = 0
	part.defined['stop'] = true
	part.labels['stop'] = 12
	part.relocations << unit.Relocation{
		offset: 0
		place:  .data
		kind:   .absolute
		name:   'stop'
		width:  .wide
	}
	part.fixups << unit.Fixup{
		start:    0
		length:   7
		kind:     .global_address
		name:     'held'
		register: 'rax'
	}
	bytes := link([part], Options{
		entry:  'main'
		target: host()
		kind:   .pie
	}) or { panic('the link failed: ${err.msg()}') }
	path := scratch('pie_data')
	os.write_file_array(path, bytes) or { panic(err) }
	assert run_image(path) == 21
}

fn test_link_files_reads_an_object_and_writes_a_runnable_image() {
	machine := host()
	object_bytes := elf.object(exiting(7), machine) or {
		panic('the object was not written: ${err.msg()}')
	}
	object_path := scratch('seven.o')
	os.write_file_array(object_path, object_bytes) or { panic(err) }
	out := scratch('seven')
	report := link_files([object_path], Options{
		entry:  'main'
		target: machine
		output: out
	}) or { panic('the link failed: ${err.msg()}') }
	assert report.path == out
	assert report.units == 1
	assert report.pulled == 0
	assert report.bytes > 0
	assert os.exists(out)
	// The write gave the file its execute bit, so it runs as it stands.
	assert run_image(out) == 7
}

fn test_a_link_refuses_an_import_no_library_defines() {
	mut part := exiting(0)
	part.imports << 'nosuchname_xyz'
	link([part], Options{
		entry:  'main'
		target: host()
	}) or {
		assert err.msg().contains('undefined reference')
		assert err.msg().contains('nosuchname_xyz')
		return
	}
	assert false, 'a link accepted an import no library defines'
}

fn test_a_name_the_c_library_defines_is_answered() {
	mut part := exiting(0)
	part.imports << 'exit'
	link([part], Options{
		entry:  'main'
		target: host()
	}) or { panic('the C library did not answer `exit`: ${err.msg()}') }
}

// A shared object named as a file is not merged into the image: the loader maps
// it beside the image, so the link takes the names it defines as answers for the
// image's imports and records the name the loader is asked for.
fn test_a_shared_object_named_as_a_file_answers_an_import_and_is_named() {
	dir := os.join_path(os.temp_dir(), 'vlk_link_shared_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer {
		os.rmdir_all(dir) or {}
	}
	mut holder := unit.Program{}
	holder.text = []u8{len: 16, init: u8(0x90)}
	holder.defined['helper'] = true
	holder.labels['helper'] = 0
	bytes := elf.write(holder, host(), .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	path := os.join_path(dir, 'libhelper.so')
	os.write_file_array(path, bytes) or { panic(err) }
	named := library.shared_library(path) or { panic(err) }
	assert named.soname == 'libhelper.so'
	mut part := exiting(0)
	part.imports << 'helper'
	// The link answers with bytes, so nothing reaches the loader: what is checked
	// is that the check passed and the image names the library.
	out := link([part], Options{
		entry:            'main'
		target:           host()
		shared_libraries: [named]
	}) or { panic('the link failed: ${err.msg()}') }
	assert out.len > 0
}

// The same input with a name no library defines is still refused by name, so
// accepting a shared object as an input does not turn the import check off.
fn test_a_shared_object_does_not_answer_a_name_it_does_not_define() {
	dir := os.join_path(os.temp_dir(), 'vlk_link_missing_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer {
		os.rmdir_all(dir) or {}
	}
	mut holder := unit.Program{}
	holder.text = []u8{len: 8, init: u8(0x90)}
	holder.defined['helper'] = true
	holder.labels['helper'] = 0
	bytes := elf.write(holder, host(), .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	path := os.join_path(dir, 'libhelper.so')
	os.write_file_array(path, bytes) or { panic(err) }
	named := library.shared_library(path) or { panic(err) }
	mut part := exiting(0)
	part.imports << 'nowhere'
	link([part], Options{
		entry:            'main'
		target:           host()
		shared_libraries: [named]
	}) or {
		assert err.msg().contains('nowhere')
		return
	}
	assert false, 'the link accepted an import no unit and no library defines'
}

// An archive of one member, written here rather than committed: a GNU symbol
// index stands first, then the member headers, and the index's offsets are file
// offsets of those headers. The test writes the container so that what it checks
// is the link's reading of it and not a fixture nobody can inspect.
fn ar_field(text string, width int) []u8 {
	mut field := text.bytes()
	for field.len < width {
		field << u8(` `)
	}
	return field
}

fn ar_header(name string, size int) []u8 {
	mut header := ar_field(name, 16)
	header << ar_field('0', 12)
	header << ar_field('0', 6)
	header << ar_field('0', 6)
	header << ar_field('0', 8)
	header << ar_field('${size}', 10)
	header << u8(0x60)
	header << u8(0x0a)
	return header
}

fn be32(value u32) []u8 {
	return [u8(value >> 24), u8((value >> 16) & 0xff), u8((value >> 8) & 0xff), u8(value & 0xff)]
}

fn archive_of(name string, member []u8, symbols []string) []u8 {
	mut index_size := 4 + 4 * symbols.len
	for symbol in symbols {
		index_size += symbol.len + 1
	}
	header_at := 8 + 60 + index_size + (index_size & 1)
	mut index := []u8{}
	index << be32(u32(symbols.len))
	for _ in symbols {
		index << be32(u32(header_at))
	}
	for symbol in symbols {
		index << symbol.bytes()
		index << u8(0)
	}
	mut out := '!<arch>\n'.bytes()
	out << ar_header('/', index.len)
	out << index
	if index.len & 1 == 1 {
		out << u8(0x0a)
	}
	out << ar_header('${name}/', member.len)
	out << member
	if member.len & 1 == 1 {
		out << u8(0x0a)
	}
	return out
}

// calling_helper is a program whose entry calls `helper` and then stops with
// zero. The call is a fixup, which is what puts the name in the object file as
// an undefined symbol: a name nothing references is a name no linker is asked
// about.
fn calling_helper() unit.Program {
	mut caller := unit.Program{}
	caller.text = [u8(0xe8), u8(0), u8(0), u8(0), u8(0), u8(0xbf), u8(0), u8(0), u8(0), u8(0),
		u8(0xb8), u8(60), u8(0), u8(0), u8(0), u8(0x0f), u8(0x05)]
	caller.defined['main'] = true
	caller.labels['main'] = 0
	caller.imports << 'helper'
	caller.fixups << unit.Fixup{
		start:  1
		length: 4
		kind:   .call_import
		name:   'helper'
	}
	return caller
}

// exiting_helper defines the name calling_helper imports and stops with a status
// of its own, so the test can tell the member ran rather than the caller's own
// exit.
fn exiting_helper() unit.Program {
	mut helper := unit.Program{}
	helper.text = [u8(0xbf), u8(9), u8(0), u8(0), u8(0), u8(0xb8), u8(60), u8(0), u8(0), u8(0),
		u8(0x0f), u8(0x05)]
	helper.defined['helper'] = true
	helper.labels['helper'] = 0
	return helper
}

// calling_a_from_b defines `b`, calls `a`, and then stops with 9 if the call
// ever returned. The call is a fixup, so `a` is an import the link has to answer.
fn calling_a_from_b() unit.Program {
	mut b := unit.Program{}
	b.text = [u8(0xbf), u8(9), u8(0), u8(0), u8(0), u8(0xe8), u8(0), u8(0), u8(0), u8(0), u8(0xb8),
		u8(60), u8(0), u8(0), u8(0), u8(0x0f), u8(0x05)]
	b.defined['b'] = true
	b.labels['b'] = 0
	b.imports << 'a'
	b.fixups << unit.Fixup{
		start:  6
		length: 4
		kind:   .call_import
		name:   'a'
	}
	return b
}

// exiting_a defines `a` and stops with 7, so an image that leaves with 7 says
// the member of the first archive ran.
fn exiting_a() unit.Program {
	mut a := unit.Program{}
	a.text = [u8(0xbf), u8(7), u8(0), u8(0), u8(0), u8(0xb8), u8(60), u8(0), u8(0), u8(0), u8(0x0f),
		u8(0x05)]
	a.defined['a'] = true
	a.labels['a'] = 0
	return a
}

// calling_b is the program: it calls `b` and then stops with 0.
fn calling_b() unit.Program {
	mut main_unit := unit.Program{}
	main_unit.text = [u8(0xe8), u8(0), u8(0), u8(0), u8(0), u8(0xbf), u8(0), u8(0), u8(0), u8(0),
		u8(0xb8), u8(60), u8(0), u8(0), u8(0), u8(0x0f), u8(0x05)]
	main_unit.defined['main'] = true
	main_unit.labels['main'] = 0
	main_unit.imports << 'b'
	main_unit.fixups << unit.Fixup{
		start:  1
		length: 4
		kind:   .call_import
		name:   'b'
	}
	return main_unit
}

// A group is two or more archives swept together. The program needs `b`, the
// archive that holds it sits after the archive that holds `a`, and `b` needs
// `a`: read once each in order, the earlier archive is passed before the name it
// could answer exists. Inside the markers the sweep comes back for it.
fn test_a_group_lets_an_earlier_archive_answer_a_later_member() {
	machine := host()
	caller_path := scratch('group_caller.o')
	os.write_file_array(caller_path, elf.object(calling_b(), machine) or { panic(err) }) or {
		panic(err)
	}
	a_path := scratch('liba.a')
	os.write_file_array(a_path, archive_of('a.o', elf.object(exiting_a(), machine) or {
		panic(err)
	}, ['a'])) or { panic(err) }
	b_path := scratch('libb.a')
	os.write_file_array(b_path, archive_of('b.o', elf.object(calling_a_from_b(), machine) or {
		panic(err)
	}, ['b'])) or { panic(err) }
	// The same three paths with no markers: the archive that holds `a` is read
	// before anything needs `a`, so the name stays unanswered.
	if _ := link_files([caller_path, a_path, b_path], Options{
		entry:  'main'
		target: machine
		output: scratch('grouped_ungrouped')
	}) {
		assert false, 'the link answered a name the earlier archive was passed over for'
	} else {
		assert err.msg().contains('undefined reference')
		assert err.msg().contains('`a`')
	}
	out := scratch('grouped')
	report := link_files([caller_path], Options{
		entry:  'main'
		target: machine
		groups: [input.Group{
			paths: [a_path, b_path]
		}]
		output: out
	}) or { panic('the grouped link failed: ${err.msg()}') }
	assert report.pulled == 2
	assert run_image(out) == 7
}

fn test_an_archive_member_answers_an_import() {
	machine := host()
	// The program calls `helper` and defines nothing by that name itself, so the
	// only thing that can answer it is a member of the archive.
	caller_bytes := elf.object(calling_helper(), machine) or {
		panic('the object was not written: ${err.msg()}')
	}
	caller_path := scratch('caller.o')
	os.write_file_array(caller_path, caller_bytes) or { panic(err) }
	// The member defines it, and stops with a status of its own so the test can
	// tell the member ran rather than the caller's own exit.
	helper_bytes := elf.object(exiting_helper(), machine) or {
		panic('the object was not written: ${err.msg()}')
	}
	archive_path := scratch('libnine.a')
	os.write_file_array(archive_path, archive_of('nine.o', helper_bytes, ['helper'])) or {
		panic(err)
	}
	// Without the archive the name is unanswered, which is what says the member
	// is what answers it and not something already in the link.
	link_files([caller_path], Options{
		entry:  'main'
		target: machine
		output: scratch('without')
	}) or {
		assert err.msg().contains('undefined reference')
		assert err.msg().contains('helper')
	}
	out := scratch('nine')
	report := link_files([caller_path, archive_path], Options{
		entry:  'main'
		target: machine
		output: out
	}) or { panic('the link failed: ${err.msg()}') }
	assert report.units == 2
	assert report.pulled == 1
	assert run_image(out) == 9
}

// A `-l` name goes through the link's own search, and a name that resolves to a
// static archive brings that archive's members into the link the way a path that
// names it does. The archive is in a directory of its own and the link is never
// handed its path, so nothing but the search can have read it.
fn test_a_library_name_that_resolves_to_an_archive_pulls_its_members() {
	machine := host()
	// The file is named `libnine.a`, which is what the search looks for under
	// `-lnine`.
	dir := os.join_path(os.temp_dir(), 'vlk_link_found_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer {
		os.rmdir_all(dir) or {}
	}
	caller_path := scratch('found_caller.o')
	os.write_file_array(caller_path, elf.object(calling_helper(), machine) or {
		panic('the object was not written: ${err.msg()}')
	}) or { panic(err) }
	os.write_file_array(os.join_path(dir, 'libnine.a'), archive_of('nine.o',
		elf.object(exiting_helper(), machine) or {
			panic('the object was not written: ${err.msg()}')
		}, ['helper'])) or { panic(err) }
	// The same link without the name is still refused, which says the member the
	// search pulled is what answers `helper` and not something already in the
	// link.
	mut refused := false
	link_files([caller_path], Options{
		entry:  'main'
		target: machine
		output: scratch('found_without')
	}) or {
		refused = true
		assert err.msg().contains('undefined reference')
		assert err.msg().contains('helper')
	}
	assert refused, 'a link that named no library pulled a member that defines helper'
	out := scratch('found_nine')
	report := link_files([caller_path], Options{
		entry:        'main'
		target:       machine
		output:       out
		library_dirs: [dir]
		libraries:    ['nine']
	}) or { panic('the link failed: ${err.msg()}') }
	assert report.units == 2
	assert report.pulled == 1
	// The archive is named by the image nowhere: the loader maps no file for it,
	// and the member ran out of the image itself.
	assert report.libraries.len == 0
	assert run_image(out) == 9
}

// A static link resolves a `-l` name to the archive even when a shared object of
// the same name stands beside it: the kind is what asks for that search, because
// a static program carries the code it calls rather than asking a loader for it.
fn test_a_static_link_pulls_the_archive_beside_a_shared_object_of_the_same_name() {
	machine := host()
	dir := os.join_path(os.temp_dir(), 'vlk_link_static_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer {
		os.rmdir_all(dir) or {}
	}
	// The shared object defines something else, so a link that took it would have
	// nothing to answer `helper` with.
	mut holder := unit.Program{}
	holder.text = []u8{len: 8, init: u8(0x90)}
	holder.defined['other'] = true
	holder.labels['other'] = 0
	shared := elf.write(holder, machine, .shared) or { panic('the shared object was not written: ${err.msg()}') }
	os.write_file_array(os.join_path(dir, 'libnine.so'), shared) or { panic(err) }
	os.write_file_array(os.join_path(dir, 'libnine.a'), archive_of('nine.o',
		elf.object(exiting_helper(), machine) or {
			panic('the object was not written: ${err.msg()}')
		}, ['helper'])) or { panic(err) }
	caller_path := scratch('static_caller.o')
	os.write_file_array(caller_path, elf.object(calling_helper(), machine) or {
		panic('the object was not written: ${err.msg()}')
	}) or { panic(err) }
	out := scratch('static_nine')
	report := link_files([caller_path], Options{
		entry:        'main'
		target:       machine
		output:       out
		kind:         .static_program
		library_dirs: [dir]
		libraries:    ['nine']
	}) or { panic('the link failed: ${err.msg()}') }
	assert report.pulled == 1
	assert run_image(out) == 9
}

// A `-l` name can resolve to a GNU ld script, and the script names a library and
// the archives beside it. The archives are where the C library keeps what its
// shared object does not export, so they are read for the names they answer.
// The directory written here is libc's own shape: `libnine.so` is a script,
// `libnine.so.6` is the library the script stands for and defines something
// else, and `libnine_nonshared.a` is the archive that answers `helper`. The link
// is given the name and never a path to the archive.
fn test_a_script_named_by_a_library_pulls_the_archives_it_names() {
	machine := host()
	dir := os.join_path(os.temp_dir(), 'vlk_link_script_${os.getpid()}')
	os.mkdir_all(dir) or { panic(err) }
	defer {
		os.rmdir_all(dir) or {}
	}
	mut holder := unit.Program{}
	holder.text = []u8{len: 8, init: u8(0x90)}
	holder.defined['other'] = true
	holder.labels['other'] = 0
	shared := elf.write(holder, machine, .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	os.write_file_array(os.join_path(dir, 'libnine.so.6'), shared) or { panic(err) }
	// The file a `-l` name finds is text and not an object, which is the shape
	// the search has to read rather than hand to the reader of objects.
	os.write_file(os.join_path(dir, 'libnine.so'),
		'/* GNU ld script\nGROUP ( libnine.so.6  libnine_nonshared.a ) */\n') or { panic(err) }
	os.write_file_array(os.join_path(dir, 'libnine_nonshared.a'), archive_of('nine.o',
		elf.object(exiting_helper(), machine) or {
			panic('the object was not written: ${err.msg()}')
		}, ['helper'])) or { panic(err) }
	caller_path := scratch('script_caller.o')
	os.write_file_array(caller_path, elf.object(calling_helper(), machine) or {
		panic('the object was not written: ${err.msg()}')
	}) or { panic(err) }
	out := scratch('script_nine')
	report := link_files([caller_path], Options{
		entry:        'main'
		target:       machine
		output:       out
		library_dirs: [dir]
		libraries:    ['nine']
	}) or { panic('the link failed: ${err.msg()}') }
	assert report.pulled == 1
	// The script was followed to the library it names, and that is the name the
	// loader is asked for. Only the archive is merged: the library is mapped.
	assert 'libnine.so.6' in report.libraries
	// The image names a library that sits in a scratch directory, and the loader
	// searches its own directories rather than the ones this link read. The
	// variable is what tells it where the file is, and it is put back because
	// the rest of the suite runs in this process too.
	previous := os.getenv_opt('LD_LIBRARY_PATH')
	os.setenv('LD_LIBRARY_PATH', dir, true)
	status := run_image(out)
	if old := previous {
		os.setenv('LD_LIBRARY_PATH', old, true)
	} else {
		os.unsetenv('LD_LIBRARY_PATH')
	}
	assert status == 9
}

// The Windows lane end to end: two COFF objects a compiler wrote, read as units,
// merged, wrapped as a PE image, and run. Nothing here is built by hand, so what
// the test checks is the whole path a Windows build would take: the unwind data
// the compiler wrote as sections of its own, the references inside it, the entry
// the link resolves by name, and the status the program returns.
fn test_two_coff_objects_link_and_run() {
	clang := '/usr/bin/clang'
	if !os.exists(clang) {
		eprintln('skipping: no clang on this machine to write COFF objects with')
		return
	}
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping: no wine on this machine to run a PE image with')
		return
	}
	dir := scratch('coff')
	os.mkdir_all(dir) or { panic(err) }
	first := os.join_path(dir, 'add.c')
	second := os.join_path(dir, 'main.c')
	os.write_file(first, 'int add(int a, int b) { return a + b; }\n') or { panic(err) }
	os.write_file(second, 'int add(int a, int b);\nint main(void) { return add(40, 2); }\n') or {
		panic(err)
	}
	first_object := os.join_path(dir, 'add.obj')
	second_object := os.join_path(dir, 'main.obj')
	for pair in [[first, first_object], [second, second_object]] {
		result := os.exec([clang, '--target=x86_64-pc-windows-msvc', '-c', pair[0], '-o', pair[1]])
		if result.exit_code != 0 {
			eprintln('skipping: clang could not write a COFF object: ${result.output}')
			return
		}
	}
	image := os.join_path(dir, 'coff.exe')
	report := link_files([first_object, second_object], Options{
		entry:  'main'
		target: target.windows_x86_64()
		kind:   .program
		output: image
	})!
	assert report.units == 2
	assert report.bytes > 0
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', image])
	assert result.exit_code == 42, 'wine left with ${result.exit_code}: ${result.output}'
}

// An object that names the machine this reader does not know is refused before a
// byte of it is placed.
fn test_a_coff_object_for_another_machine_is_refused() {
	dir := scratch('coff_machine')
	os.mkdir_all(dir) or { panic(err) }
	object := os.join_path(dir, 'unit.obj')
	mut bytes := []u8{len: 40}
	put_u16_at(mut bytes, 0, u16(0x014c)) // an i386 object
	put_u16_at(mut bytes, 2, 0)
	put_u16_at(mut bytes, 16, 0)
	os.write_file_array(object, bytes) or { panic(err) }
	link_files([object], Options{
		target: target.windows_x86_64()
		kind:   .program
		output: os.join_path(dir, 'out.exe')
	}) or {
		// The input layer refuses it by path, because a COFF object for another
		// machine is not a file this target can read.
		assert err.msg().contains('unit.obj')
		return
	}
	assert false, 'an i386 object has no place in a windows-x86_64 link'
}

fn put_u16_at(mut bytes []u8, at int, value u16) {
	bytes[at] = u8(value & 0xff)
	bytes[at + 1] = u8((value >> 8) & 0xff)
}

// A thread-local variable a compiler declared reaches the image through the same
// path the hand-written test uses: the template in a section, the index the
// loader hands out, and code that reads the TEB. The object leaves `_tls_index`
// undefined because the image is what defines it, so the link supplies the name.
fn test_a_thread_local_from_a_coff_object_is_read_from_the_thread_s_copy() {
	clang := '/usr/bin/clang'
	if !os.exists(clang) {
		eprintln('skipping: no clang on this machine to write a COFF object with')
		return
	}
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping: no wine on this machine to run a PE image with')
		return
	}
	dir := scratch('coff_tls')
	os.mkdir_all(dir) or { panic(err) }
	source := os.join_path(dir, 'tls.c')
	os.write_file(source, '__declspec(thread) int counter = 7;\nint main(void) { return counter; }\n') or {
		panic(err)
	}
	object := os.join_path(dir, 'tls.obj')
	result := os.exec([clang, '--target=x86_64-pc-windows-msvc', '-c', source, '-o', object])
	if result.exit_code != 0 {
		eprintln('skipping: clang could not write the object: ${result.output}')
		return
	}
	image := os.join_path(dir, 'tls.exe')
	link_files([object], Options{
		entry:  'main'
		target: target.windows_x86_64()
		kind:   .program
		output: image
	})!
	os.setenv('WINEDEBUG', '-all', true)
	run := os.exec(['/usr/bin/wine', image])
	assert run.exit_code == 7, 'wine left with ${run.exit_code}: ${run.output}'
}

// CallSite is where one call's displacement lies and the import it reaches.
struct CallSite {
	field int
	name  string
}

// A resource is bytes a resource compiler produced and a directory that indexes
// them; a linker carries both and names the directory, and the loader is what
// finds a resource in it. The test links a `.rsrc` object that a resource
// compiler wrote next to a program that asks the loader for one of its entries
// and exits with the entry's length, so what is checked is the resource being
// found at run time rather than the bytes being present.
fn test_a_resource_a_resource_compiler_wrote_is_found_by_the_loader() {
	windres := '/usr/bin/x86_64-w64-mingw32-windres'
	if !os.exists(windres) {
		eprintln('skipping: no windres on this machine to write a resource object with')
		return
	}
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping: no wine on this machine to run a PE image with')
		return
	}
	dir := scratch('resource')
	os.mkdir_all(dir) or { panic(err) }
	script := os.join_path(dir, 'app.rc')
	// One RCDATA entry under the name 1. A resource compiler writes each number
	// of an RCDATA list as a sixteen-bit word, so the entry is eight bytes and
	// that is the length the program asks the loader for.
	os.write_file(script, '1 RCDATA { 1, 2, 3, 4 }\n') or { panic(err) }
	resource_object := os.join_path(dir, 'app.res.o')
	written := os.exec([windres, script, '-O', 'coff', '-o', resource_object])
	if written.exit_code != 0 {
		eprintln('skipping: windres could not write the resource object: ${written.output}')
		return
	}
	resource := coff.read_unit(os.read_bytes(resource_object) or { panic(err) }, target.windows_x86_64())!
	// The program asks the loader for the resource and exits with its length:
	// FindResourceW(NULL, 1, RT_RCDATA) then SizeofResource(NULL, handle).
	mut part := unit.Program{}
	part.text = [
		u8(0x48),
		u8(0x83),
		u8(0xec),
		u8(0x28), // sub rsp, 0x28
		u8(0x31),
		u8(0xc9), // xor ecx, ecx
		u8(0xba),
		u8(1),
		u8(0),
		u8(0),
		u8(0), // mov edx, 1
		u8(0x41),
		u8(0xb8),
		u8(10),
		u8(0),
		u8(0),
		u8(0), // mov r8d, 10 (RT_RCDATA)
		u8(0xff),
		u8(0x15),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // call [rip + FindResourceW]
		u8(0x48),
		u8(0x89),
		u8(0xc2), // mov rdx, rax
		u8(0x31),
		u8(0xc9), // xor ecx, ecx
		u8(0xff),
		u8(0x15),
		u8(0),
		u8(0),
		u8(0),
		u8(0), // call [rip + SizeofResource]
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
	for name in ['FindResourceW', 'SizeofResource', 'ExitProcess'] {
		part.imports << name
		part.imports_by_library << unit.Import{
			name:    name
			library: 'kernel32.dll'
		}
	}
	for call in [
		CallSite{
			field: 19
			name:  'FindResourceW'
		},
		CallSite{
			field: 30
			name:  'SizeofResource'
		},
		CallSite{
			field: 38
			name:  'ExitProcess'
		},
	] {
		part.relocations << unit.Relocation{
			offset: call.field
			place:  .text
			kind:   .direct
			name:   call.name
			addend: -4
			width:  .narrow
		}
	}
	image := os.join_path(dir, 'resource.exe')
	bytes := link([resource, part], Options{
		entry:  'main'
		target: target.windows_x86_64()
		kind:   .program
	})!
	os.write_file_array(image, bytes) or { panic(err) }
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', image])
	assert result.exit_code == 8, 'wine left with ${result.exit_code}: ${result.output}'
}

// A COMDAT group is one copy of one thing. Both objects here hold the same string
// literal, and clang puts every literal in a group named after its content, so
// the two objects carry the same group and the same symbol name. The link keeps
// the first copy and the second object's reference binds to it, which is what
// makes ordinary C code with a shared literal link at all.
fn test_a_comdat_group_two_objects_carry_is_kept_once() {
	clang := '/usr/bin/clang'
	if !os.exists(clang) {
		eprintln('skipping: no clang on this machine to write COFF objects with')
		return
	}
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping: no wine on this machine to run a PE image with')
		return
	}
	dir := scratch('comdat')
	os.mkdir_all(dir) or { panic(err) }
	first := os.join_path(dir, 'first.c')
	second := os.join_path(dir, 'second.c')
	os.write_file(first, 'const char *first(void) { return "shared literal"; }\n') or {
		panic(err)
	}
	os.write_file(second, 'extern const char *first(void);\nint main(void) {\n    const char *mine = "shared literal";\n    return mine[0] == first()[0] ? 42 : 1;\n}\n') or {
		panic(err)
	}
	first_object := os.join_path(dir, 'first.obj')
	second_object := os.join_path(dir, 'second.obj')
	for pair in [[first, first_object], [second, second_object]] {
		result := os.exec([clang, '--target=x86_64-pc-windows-msvc', '-c', pair[0], '-o', pair[1]])
		if result.exit_code != 0 {
			eprintln('skipping: clang could not write a COFF object: ${result.output}')
			return
		}
	}
	image := os.join_path(dir, 'comdat.exe')
	report := link_files([first_object, second_object], Options{
		entry:  'main'
		target: target.windows_x86_64()
		kind:   .program
		output: image
	})!
	assert report.units == 2
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', image])
	assert result.exit_code == 42, 'wine left with ${result.exit_code}: ${result.output}'
}

fn put_u32_at(mut bytes []u8, at int, value u32) {
	for i in 0 .. 4 {
		bytes[at + i] = u8((value >> (8 * i)) & 0xff)
	}
}

// import_library is an archive holding one short import member, which is how a
// Windows import library says that a name comes from a DLL. The member's symbol
// is the spelling the object uses, `__imp_` and all, and its string area names
// the DLL.
fn import_library(symbol string, dll string, exported string) []u8 {
	// The third string is the DLL's own name for the export, which a member
	// that defines `__imp_foo` needs to say that the DLL answers to `foo`.
	strings := '${symbol}\x00${dll}\x00${exported}\x00'
	mut member := []u8{len: 20}
	put_u16_at(mut member, 0, 0)
	put_u16_at(mut member, 2, u16(0xffff))
	put_u16_at(mut member, 4, 0)
	put_u16_at(mut member, 6, u16(0x8664))
	put_u32_at(mut member, 12, u32(strings.len))
	// Type is code, and NameType is IMPORT_NAME, which is the bits above the
	// low two: a member that named no type would be an import by ordinal.
	put_u16_at(mut member, 18, u16(1) << 2)
	member << strings.bytes()
	return archive_of('imp', member, [symbol])
}

// An object that calls a DLL function says nothing about which DLL answers it; an
// import library is what says so. The test links a `dllimport` object against an
// archive holding one short import member, and the image that comes out imports
// the bare name from the DLL while the object's own spelling reaches the slot.
fn test_an_import_library_names_the_dll_a_coff_object_needs() {
	clang := '/usr/bin/clang'
	if !os.exists(clang) {
		eprintln('skipping: no clang on this machine to write a COFF object with')
		return
	}
	if !os.exists('/usr/bin/wine') {
		eprintln('skipping: no wine on this machine to run a PE image with')
		return
	}
	dir := scratch('import_library')
	os.mkdir_all(dir) or { panic(err) }
	source := os.join_path(dir, 'exit.c')
	os.write_file(source, '__declspec(dllimport) void ExitProcess(unsigned int code);\nint main(void) { ExitProcess(42); return 1; }\n') or {
		panic(err)
	}
	object := os.join_path(dir, 'exit.obj')
	written := os.exec([clang, '--target=x86_64-pc-windows-msvc', '-c', source, '-o', object])
	if written.exit_code != 0 {
		eprintln('skipping: clang could not write the object: ${written.output}')
		return
	}
	imports := os.join_path(dir, 'kernel32.lib')
	os.write_file_array(imports, import_library('__imp_ExitProcess', 'kernel32.dll', 'ExitProcess')) or {
		panic(err)
	}
	image := os.join_path(dir, 'imports.exe')
	report := link_files([object, imports], Options{
		entry:  'main'
		target: target.windows_x86_64()
		kind:   .program
		output: image
	})!
	assert report.units == 1
	os.setenv('WINEDEBUG', '-all', true)
	result := os.exec(['/usr/bin/wine', image])
	assert result.exit_code == 42, 'wine left with ${result.exit_code}: ${result.output}'
}
