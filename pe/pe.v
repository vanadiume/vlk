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
	if program.fixups.len > 0 {
		return error("the program carries ${program.fixups.len} fixups, which are this compiler's own emitter's shape, and the PE writer fills relocations")
	}
	if program.data_fixups.len > 0 {
		return error('the program carries ${program.data_fixups.len} data fixups, and the PE writer fills relocations')
	}
	if program.tls_size > 0 {
		return error('the program asks for ${program.tls_size} bytes of thread-local storage, and the PE writer places none')
	}
	if program.text.len == 0 {
		return error('the program has no code')
	}
	if program.entry_place < 0 || program.entry_place >= program.text.len {
		return error('the entry point is at ${program.entry_place} and the code is ${program.text.len} bytes')
	}
	plan := plan_imports(program)!
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
	if program.globals_blob.len > 0 {
		sections << Section{
			name:            '.data'
			data:            program.globals_blob.clone()
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
	mut layout := lay(sections, machine)
	// The import directory's own addresses are inside the section that holds
	// it, so its bytes are written once the layout has said where that is.
	if plan.size > 0 {
		idata_rva := layout.address('.idata') or { return error('.idata was placed and the layout lost it') }
		layout.replace('.idata', plan.bytes(idata_rva))!
	}
	sites := relocate(mut layout, program, machine, plan)!
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
