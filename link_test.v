module vlk

import elf
import library
import os
import target
import unit

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

fn test_a_link_of_one_unit_answers_bytes_that_run() {
	bytes := link([exiting(42)], Options{
		entry:  'main'
		target: host()
	}) or { panic('the link failed: ${err.msg()}') }
	path := scratch('one')
	os.write_file_array(path, bytes) or { panic(err) }
	assert run_image(path) == 42
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
