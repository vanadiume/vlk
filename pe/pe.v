module pe

import vanadiume.vlk.target
import vanadiume.vlk.unit

// The writer for a PE32+ image: the container a Windows loader maps, and the one
// the objects clang, mingw and MSVC write are linked into.
//
// This module is the only place in the tree that writes PE, the way `elf/` is
// the only place that writes ELF. It reads a merged program and a target and
// answers with the bytes of one file. It decides nothing about a reference the
// program left: a relocation's number comes from the merge, and what this file
// adds is the address the reference was measured from.
//
// What the first version writes is an executable that imports from named DLLs
// and carries base relocations for every absolute field it filled. A DLL with an
// export table, thread-local storage, exception data and resources are refused
// by name, so a link that asks for one is told rather than handed an image that
// stops when it runs.

// Kind is which of the container's shapes a PE image takes. An image that names
// no library is not a different shape: it is an executable whose import
// directory is empty, and the header says nothing about it. A position
// independent executable is an executable whose DllCharacteristics say the image
// may move, which is what the target already asks for.
pub enum Kind {
	executable
	dll
}

// The section alignment is the loader's page, and it is fixed by the format
// rather than by this machine: an image that asked for anything smaller than the
// page would not be mapped.
pub const section_alignment = 0x1000

// The DOS header is 64 bytes and the header of a PE file begins at an offset it
// names. The stub between them is the text a DOS system prints when it is handed
// the file; it has to exist, because the loader reads the offset and nothing
// else, and no byte of it is ever run.
pub const pe_header_offset = 0x80
const dos_header_size = 0x40
const dos_stub = 'This program cannot be run in DOS mode.\r\n\$'

const coff_header_size = 20
const optional_header_size = 240
const section_header_size = 40
const data_directory_count = 16

// The COFF header characteristics. An image is executable, and it is large
// address aware because the machine is 64-bit; a DLL is one the loader maps for
// another image rather than starts.
const image_file_executable = u16(0x0002)
const image_file_large_address_aware = u16(0x0020)

// The section characteristics. A section holding code is executable and
// readable; data is readable, and writable when the program writes it. The
// relocation table is discardable, because the loader that keeps the image where
// it was asked to is the one that never reads it again.
const scn_cnt_code = u32(0x00000020)
const scn_cnt_initialized_data = u32(0x00000040)
const scn_mem_discardable = u32(0x02000000)
const scn_mem_execute = u32(0x20000000)
const scn_align_shift = 20
const scn_mem_read = u32(0x40000000)
const scn_mem_write = u32(0x80000000)

// Section is one output section before it is placed: the name the loader and a
// debugger read, the bytes, and what may be done with them.
struct Section {
	name            string
	data            []u8
	characteristics u32
	// alignment is the alignment the section's first byte needs inside the
	// image. It is asked of the section's own contents rather than of the page
	// the section starts on, and it is what a sixteen-byte constant needs.
	alignment int
}

// Placed is one section after the layout has decided where it goes: its address
// in the image, where its bytes start in the file, and how long they are there.
struct Placed {
mut:
	name            string
	data            []u8
	characteristics u32
	virtual_size    int
	rva             int
	raw_offset      int
	raw_size        int
}

// Layout is the image's shape: where the headers end, where each section lies,
// and how large the image and the file are.
struct Layout {
mut:
	sections     []Placed
	headers_size int
	image_size   int
	file_size    int
}

// write turns one merged program into the bytes of a PE32+ image. Every section
// the program's blobs name is placed, the imports become the import directory,
// and each reference the merge left is filled with the number its kind asks for.
pub fn write(program unit.Program, machine target.Target, kind Kind) ![]u8 {
	if machine.format != .pe {
		return error('the ${machine.name} target is not a PE target')
	}
	if kind == .dll {
		return error('a PE DLL is not written yet: the image would need an export table and nothing here builds one')
	}
	if program.text.len == 0 {
		return error('the program has no code')
	}
	if program.entry_place < 0 || program.entry_place >= program.text.len {
		return error('the entry point is at ${program.entry_place} and the code is ${program.text.len} bytes')
	}
	plan := plan_imports(program)!
	// A program with thread-local storage needs one four-byte slot for the index
	// the loader hands out, and the program reads that index through a name the
	// link supplies. The slot is appended to the writable data, because a
	// program that uses TLS usually has none of its own and the section has to
	// exist anyway.
	mut tls := TlsInfo{}
	mut globals_blob := program.globals_blob.clone()
	if program.tls_size > 0 {
		for globals_blob.len % 4 != 0 {
			globals_blob << u8(0)
		}
		tls.index_offset = globals_blob.len
		globals_blob << []u8{len: 4}
		if program.tls_blob.len > program.tls_size {
			return error('the thread-local template is ${program.tls_blob.len} bytes and the block is ${program.tls_size}')
		}
	}
	mut sections := [
		Section{
			name:            '.text'
			data:            program.text.clone()
			characteristics: scn_cnt_code | scn_mem_execute | scn_mem_read
			alignment:       16
		},
	]
	if program.string_blob.len > 0 {
		sections << Section{
			name:            '.rdata'
			data:            program.string_blob.clone()
			characteristics: scn_cnt_initialized_data | scn_mem_read
			alignment:       8
		}
	}
	if globals_blob.len > 0 {
		sections << Section{
			name:            '.data'
			data:            globals_blob
			characteristics: scn_cnt_initialized_data | scn_mem_read | scn_mem_write
			alignment:       8
		}
	}
	if plan.size > 0 {
		sections << Section{
			name:            '.idata'
			data:            []u8{len: plan.size}
			characteristics: scn_cnt_initialized_data | scn_mem_read | scn_mem_write
			alignment:       4
		}
	}
	// The unit's named sections follow the blobs. A name the writer already
	// gave a section to is refused rather than duplicated, because two
	// sections of one name in an image is a file no loader can map by name.
	for section in program.sections {
		if section.name in ['.text', '.rdata', '.data', '.idata', '.reloc', '.tls', '.tlsdir'] {
			return error('the program carries a named section ${section.name}, which is a name the writer gives to a section it builds from the blobs')
		}
		if section.name == '' {
			return error('the program carries a named section with no name')
		}
		if section.data.len == 0 {
			continue
		}
		sections << Section{
			name:            section.name
			data:            section.data.clone()
			characteristics: section_characteristics(section.kind)
			alignment:       if section.alignment > 0 { section.alignment } else { 4 }
		}
	}
	// The thread-local template and the directory that describes it are the
	// writer's own sections: the unit carries the bytes and the size, and where
	// they go is a fact about this image.
	if program.tls_blob.len > 0 {
		sections << Section{
			name:            '.tls'
			data:            program.tls_blob.clone()
			characteristics: scn_cnt_initialized_data | scn_mem_read | scn_mem_write
			alignment:       if program.tls_alignment > 1 { program.tls_alignment } else { 4 }
		}
	}
	if program.tls_size > 0 {
		sections << Section{
			name:            '.tlsdir'
			data:            []u8{len: 40}
			characteristics: scn_cnt_initialized_data | scn_mem_read
			alignment:       8
		}
	}
	mut layout := lay(sections, machine)
	// The import directory's own addresses are inside the section that holds
	// it, so its bytes are written once the layout has said where that is.
	if plan.size > 0 {
		idata_rva := layout.address('.idata') or { return error('.idata was placed and the layout lost it') }
		layout.replace('.idata', plan.bytes(idata_rva))!
	}
	mut sites := []Site{}
	if program.tls_size > 0 {
		data_rva := layout.address('.data') or { return error('.data was placed and the layout lost it') }
		tls.index_rva = data_rva + tls.index_offset
		directory := tls_directory(program, machine, layout, tls)!
		layout.replace('.tlsdir', directory)!
		dir_rva := layout.address('.tlsdir') or { return error('.tlsdir was placed and the layout lost it') }
		sites << Site{
			rva:  dir_rva
			kind: base_reloc_dir64
		}
		sites << Site{
			rva:  dir_rva + 8
			kind: base_reloc_dir64
		}
		sites << Site{
			rva:  dir_rva + 16
			kind: base_reloc_dir64
		}
	}
	sites << relocate(mut layout, program, machine, plan, tls)!
	// The emitter's own references are instruction-shaped and the merge's are
	// fields, and both are filled once the layout is settled.
	sites << apply_fixups(mut layout, program, machine, plan, tls)!
	sites << apply_data_fixups(mut layout, program, machine, plan, tls)!
	// The loader binary-searches the exception table, so its entries are sorted
	// by the address they start at. The sort has to happen after the
	// relocations, because until then the addresses are the ones the object
	// left rather than the ones the image has.
	if index := layout.index('.pdata') {
		mut entries := layout.sections[index].data.clone()
		sort_exception_entries(mut entries)!
		layout.sections[index].data = entries
	}
	if sites.len > 0 {
		reloc := base_relocations(sites)
		layout.append(Section{
			name:            '.reloc'
			data:            reloc
			characteristics: scn_cnt_initialized_data | scn_mem_read | scn_mem_discardable
			alignment:       4
		}, machine)
	}
	return headers(program, machine, layout, plan)!
}

// lay places every section in the image and in the file. The first section
// starts at the page the headers end in, every following one at the next page,
// and the file's copy of each is padded to the file alignment. Nothing here
// decides what a section holds; it decides where it goes.
fn lay(sections []Section, machine target.Target) Layout {
	file_alignment := if machine.file_alignment > 0 { int(machine.file_alignment) } else { 0x200 }
	header_bytes := pe_header_offset + 4 + coff_header_size + optional_header_size +
		sections.len * section_header_size
	headers_size := align_up(header_bytes, file_alignment)
	mut placed := []Placed{cap: sections.len}
	mut next_rva := align_up(headers_size, section_alignment)
	mut next_raw := headers_size
	for section in sections {
		size := section.data.len
		placed << Placed{
			name:            section.name
			data:            section.data
			characteristics: section.characteristics
			virtual_size:    size
			rva:             next_rva
			raw_offset:      next_raw
			raw_size:        align_up(size, file_alignment)
		}
		next_rva = align_up(next_rva + size, section_alignment)
		next_raw += align_up(size, file_alignment)
	}
	image_size := if placed.len == 0 {
		align_up(headers_size, section_alignment)
	} else {
		align_up(placed[placed.len - 1].rva + placed[placed.len - 1].virtual_size, section_alignment)
	}
	return Layout{
		sections:     placed
		headers_size: headers_size
		image_size:   image_size
		file_size:    next_raw
	}
}

// address is where a section was placed, by name, or none when the image holds
// no section of that name.
fn (l Layout) address(name string) ?int {
	for section in l.sections {
		if section.name == name {
			return section.rva
		}
	}
	return none
}

// index is where a section stands in the layout, by name, or none when the image
// holds no section of that name.
fn (l Layout) index(name string) ?int {
	for i, section in l.sections {
		if section.name == name {
			return i
		}
	}
	return none
}

// size_of is a placed section's length in the image, which is the size the
// optional header states for a directory that lies in it.
fn (l Layout) size_of(name string) int {
	for section in l.sections {
		if section.name == name {
			return section.virtual_size
		}
	}
	return 0
}

// replace puts a section's bytes in place after the layout was made, which is how
// the import directory learns the addresses of its own tables.
fn (mut l Layout) replace(name string, data []u8) ! {
	for i in 0 .. l.sections.len {
		if l.sections[i].name == name {
			if data.len != l.sections[i].virtual_size {
				return error('the ${name} section was placed at ${l.sections[i].virtual_size} bytes and replaced with ${data.len}')
			}
			l.sections[i].data = data
			return
		}
	}
	return error('the ${name} section was never placed')
}

// append places one more section after the ones already in the image. It is used
// for the relocation table, which cannot be built until every field that needs
// an entry has been filled, and it moves nothing: the section goes last, so
// every address the fields already hold stays where it was.
fn (mut l Layout) append(section Section, machine target.Target) {
	file_alignment := if machine.file_alignment > 0 { int(machine.file_alignment) } else { 0x200 }
	last_rva := if l.sections.len == 0 {
		l.headers_size
	} else {
		l.sections[l.sections.len - 1].rva + l.sections[l.sections.len - 1].virtual_size
	}
	rva := align_up(last_rva, section_alignment)
	raw := l.file_size
	l.sections << Placed{
		name:            section.name
		data:            section.data
		characteristics: section.characteristics
		virtual_size:    section.data.len
		rva:             rva
		raw_offset:      raw
		raw_size:        align_up(section.data.len, file_alignment)
	}
	l.file_size = raw + align_up(section.data.len, file_alignment)
	l.image_size = align_up(rva + section.data.len, section_alignment)
}

// headers writes the file: the DOS header and its stub, the PE signature, the
// COFF header, the optional header with its sixteen directories, the section
// table, and then each section at the offset the layout gave it.
fn headers(program unit.Program, machine target.Target, layout Layout, plan ImportPlan) ![]u8 {
	mut bytes := []u8{len: layout.file_size}
	// The DOS header is forty bytes of fields this image does not use and one
	// that matters: the offset of the PE header, written where a DOS program
	// keeps its relocation table pointer.
	put_u16(mut bytes, 0, 0x5a4d) // 'MZ'
	put_u16(mut bytes, 2, u16(layout.file_size / 512))
	put_u16(mut bytes, 24, 0x40) // the size of the header in paragraphs
	put_u32(mut bytes, 0x3c, pe_header_offset)
	put(mut bytes, dos_header_size, dos_stub.bytes())
	put(mut bytes, pe_header_offset, [u8(`P`), u8(`E`), u8(0), u8(0)])
	coff := pe_header_offset + 4
	characteristics := image_file_executable | image_file_large_address_aware
	put_u16(mut bytes, coff, machine.coff_machine)
	put_u16(mut bytes, coff + 2, u16(layout.sections.len))
	put_u32(mut bytes, coff + 4, 0) // a timestamp is what makes two links differ
	put_u32(mut bytes, coff + 8, 0)
	put_u32(mut bytes, coff + 12, 0)
	put_u16(mut bytes, coff + 16, optional_header_size)
	put_u16(mut bytes, coff + 18, characteristics)
	optional := coff + coff_header_size
	put_u16(mut bytes, optional, 0x20b) // PE32+
	put_u8(mut bytes, optional + 2, 1)
	mut size_of_code := 0
	mut size_of_data := 0
	for section in layout.sections {
		if section.characteristics & scn_cnt_code != 0 {
			size_of_code += section.raw_size
		} else {
			size_of_data += section.raw_size
		}
	}
	put_u32(mut bytes, optional + 4, u32(size_of_code))
	put_u32(mut bytes, optional + 8, u32(size_of_data))
	put_u32(mut bytes, optional + 12, 0)
	entry := layout.address('.text') or { return error('the image was placed with no code section') }
	put_u32(mut bytes, optional + 16, u32(entry + program.entry_place))
	put_u32(mut bytes, optional + 20, u32(entry))
	put_u64(mut bytes, optional + 24, machine.load_base)
	put_u32(mut bytes, optional + 32, u32(section_alignment))
	put_u32(mut bytes, optional + 36, machine.file_alignment)
	put_u16(mut bytes, optional + 40, 6) // the oldest system this image runs on
	put_u16(mut bytes, optional + 48, 6)
	put_u32(mut bytes, optional + 56, u32(layout.image_size))
	put_u32(mut bytes, optional + 60, u32(layout.headers_size))
	put_u32(mut bytes, optional + 64, 0) // the checksum is optional for an image
	put_u16(mut bytes, optional + 68, machine.subsystem)
	put_u16(mut bytes, optional + 70, machine.dll_characteristics)
	put_u64(mut bytes, optional + 72, 0x100000) // the stack the loader commits
	put_u64(mut bytes, optional + 80, 0x1000)
	put_u64(mut bytes, optional + 88, 0x100000) // the heap it commits
	put_u64(mut bytes, optional + 96, 0x1000)
	put_u32(mut bytes, optional + 104, 0) // loader flags
	put_u32(mut bytes, optional + 108, data_directory_count)
	directories := optional + 112
	if plan.size > 0 {
		idata := layout.address('.idata') or { return error('.idata was placed and the layout lost it') }
		put_u32(mut bytes, directories + 8, u32(idata))
		put_u32(mut bytes, directories + 12, u32(plan.descriptors_size()))
		put_u32(mut bytes, directories + 96, u32(idata + plan.first_iat()))
		put_u32(mut bytes, directories + 100, u32(plan.iat_size()))
	}
	// The resource directory and the exception table are sections the input
	// brought, so the header names where the layout put them and nothing here
	// reads what they hold.
	if resources := layout.address('.rsrc') {
		put_u32(mut bytes, directories + 2 * 8, u32(resources))
		put_u32(mut bytes, directories + 2 * 8 + 4, u32(layout.size_of('.rsrc')))
	}
	if exceptions := layout.address('.pdata') {
		put_u32(mut bytes, directories + 3 * 8, u32(exceptions))
		put_u32(mut bytes, directories + 3 * 8 + 4, u32(layout.size_of('.pdata')))
	}
	if thread_local := layout.address('.tlsdir') {
		put_u32(mut bytes, directories + 9 * 8, u32(thread_local))
		put_u32(mut bytes, directories + 9 * 8 + 4, u32(layout.size_of('.tlsdir')))
	}
	if reloc := layout.address('.reloc') {
		put_u32(mut bytes, directories + 5 * 8, u32(reloc))
		put_u32(mut bytes, directories + 5 * 8 + 4, u32(layout.size_of('.reloc')))
	}
	table := optional + optional_header_size
	for i, section in layout.sections {
		at := table + i * section_header_size
		put(mut bytes, at, section.name.bytes())
		put_u32(mut bytes, at + 8, u32(section.virtual_size))
		put_u32(mut bytes, at + 12, u32(section.rva))
		put_u32(mut bytes, at + 16, u32(section.raw_size))
		put_u32(mut bytes, at + 20, u32(section.raw_offset))
		put_u32(mut bytes, at + 24, 0)
		put_u32(mut bytes, at + 28, 0)
		put_u16(mut bytes, at + 32, 0)
		put_u16(mut bytes, at + 34, 0)
		put_u32(mut bytes, at + 36, section.characteristics)
	}
	for section in layout.sections {
		put(mut bytes, section.raw_offset, section.data)
	}
	return bytes
}

// TlsInfo is where the writer put the one slot a program with thread-local
// storage reads its index from. The bytes of the block are the unit's; the slot
// and the directory are the image's, because the loader is what fills them.
struct TlsInfo {
mut:
	// index_offset is where the slot lies in the unit's writable data, before
	// the section was placed.
	index_offset int
	// index_rva is the slot's address in the image, which is what the directory
	// and a reference to `_tls_index` name.
	index_rva int
}

// tls_directory is the forty bytes that tell the loader where the template is,
// where the index slot is, which callbacks to run, and how much of each thread's
// copy to zero-fill. The three addresses that point into the image are absolute,
// so each is also a base relocation site, which `write` records.
fn tls_directory(program unit.Program, machine target.Target, layout Layout, info TlsInfo) ![]u8 {
	mut bytes := []u8{len: 40}
	mut start := u64(0)
	mut end := u64(0)
	if program.tls_blob.len > 0 {
		template := layout.address('.tls') or { return error('.tls was placed and the layout lost it') }
		start = machine.load_base + u64(template)
		end = start + u64(program.tls_blob.len)
	}
	put_u64(mut bytes, 0, start)
	put_u64(mut bytes, 8, end)
	put_u64(mut bytes, 16, machine.load_base + u64(info.index_rva))
	put_u64(mut bytes, 24, 0) // the callback array, which this writer places none of
	put_u32(mut bytes, 32, u32(program.tls_size - program.tls_blob.len))
	put_u32(mut bytes, 36, tls_alignment_characteristics(program.tls_alignment))
	return bytes
}

// tls_alignment_characteristics is the alignment of each thread's copy, written
// the way a section states its alignment: a code whose value is one more than the
// base-two logarithm of the alignment a byte count asks for.
fn tls_alignment_characteristics(alignment int) u32 {
	mut code := 0
	mut size := 1
	for size < alignment && code < 14 {
		size <<= 1
		code++
	}
	return u32(code + 1) << scn_align_shift
}

// section_characteristics is what a named section's kind means to a loader.
// Code is executable and readable, read-only data is neither executable nor
// writable, writable data is both readable and writable, and a debug record is
// readable and marked so the loader may drop it.
fn section_characteristics(kind unit.SectionKind) u32 {
	return match kind {
		.code { scn_cnt_code | scn_mem_execute | scn_mem_read }
		.read_only { scn_cnt_initialized_data | scn_mem_read }
		.data { scn_cnt_initialized_data | scn_mem_read | scn_mem_write }
		.debug { scn_cnt_initialized_data | scn_mem_read | scn_mem_discardable }
	}
}

// ExceptionEntry is one record of the exception table: the address the function
// starts at, and the three words that name its range and its unwind data.
struct ExceptionEntry {
	start u32
	bytes []u8
}

// sort_exception_entries orders the exception table by the address each entry
// starts at. Every entry is twelve bytes: the function's start, its end, and
// where its unwind information is. A table that is not a whole number of entries
// is refused, because sorting it would place the next section's bytes inside an
// entry.
fn sort_exception_entries(mut data []u8) ! {
	if data.len % 12 != 0 {
		return error('the exception table is ${data.len} bytes, and every entry is twelve')
	}
	mut entries := []ExceptionEntry{cap: data.len / 12}
	for at := 0; at < data.len; at += 12 {
		entries << ExceptionEntry{
			start: u32(read_u32(data, at))
			bytes: data[at..at + 12].clone()
		}
	}
	entries.sort(a.start < b.start)
	for i, entry in entries {
		for j, byte in entry.bytes {
			data[i * 12 + j] = byte
		}
	}
}

fn read_u32(bytes []u8, at int) int {
	mut value := u32(0)
	for i in 0 .. 4 {
		value |= u32(bytes[at + i]) << (8 * i)
	}
	return int(value)
}

// align_up rounds a number up to a multiple of an alignment. Every size the
// format states is one of these, and a size that is not is not a size.
fn align_up(value int, alignment int) int {
	if alignment <= 1 {
		return value
	}
	remainder := value % alignment
	if remainder == 0 {
		return value
	}
	return value + alignment - remainder
}

fn put(mut output []u8, offset int, bytes []u8) {
	for i, byte in bytes {
		output[offset + i] = byte
	}
}

fn put_u8(mut output []u8, offset int, value u8) {
	output[offset] = value
}

fn put_u16(mut output []u8, offset int, value u16) {
	output[offset] = u8(value & 0xff)
	output[offset + 1] = u8((value >> 8) & 0xff)
}

fn put_u32(mut output []u8, offset int, value u32) {
	for i in 0 .. 4 {
		output[offset + i] = u8((value >> (8 * i)) & 0xff)
	}
}

fn put_u64(mut output []u8, offset int, value u64) {
	for i in 0 .. 8 {
		output[offset + i] = u8((value >> (8 * i)) & 0xff)
	}
}
