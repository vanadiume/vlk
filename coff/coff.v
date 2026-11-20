module coff

// The reader for a COFF object: the file a Windows compiler writes and a linker
// finishes. It is the inverse of nothing in this tree yet, and that is the point
// of reading it first: the format is written by clang, mingw and MSVC, and a
// reader checked only against this tree's own writer would agree with its
// mistakes.
//
// `coff/` is the only place that reads COFF as input, the way `object/` is the
// only place that reads ELF. It answers with what the file holds, not with a
// merged program: sections by number and name, the symbols with their storage
// classes and auxiliary records, and each section's relocations. Turning that
// into something a link places is the work of a later pass, so this module
// decides nothing about layout.
//
// Every field is read through a bounds check. A linker input is a file this
// compiler did not write, and a length or an offset from one is used to slice
// the file only after it has been shown to lie inside it.

// The machine this reader interprets. A COFF object's relocation types are the
// machine's, not the format's, so an object for another machine is refused by
// name rather than read as if the numbers meant the AMD64 ones.
pub const image_file_machine_amd64 = u16(0x8664)

// The record sizes. A COFF file is a header, a fixed-size section table, then
// arrays the header points at, and every array is walked at its own stride.
pub const coff_header_size = 20
pub const section_header_size = 40
pub const symbol_entry_size = 18
pub const relocation_entry_size = 10

// NumberOfRelocations saturates at 0xffff. When IMAGE_SCN_LNK_NRELOC_OVFL is
// set, the true count is in the VirtualAddress field of the first relocation
// entry, which holds no relocation of its own.
pub const relocation_overflow_count = u16(0xffff)

// The section characteristics a link reads. They are named here rather than
// borrowed from a writer, because a reader that shared a writer's constants
// could not catch the writer changing them.
pub const scn_cnt_code = u32(0x00000020)
pub const scn_cnt_initialized_data = u32(0x00000040)
pub const scn_cnt_uninitialized_data = u32(0x00000080)
pub const scn_lnk_info = u32(0x00000200)
pub const scn_lnk_remove = u32(0x00000800)
pub const scn_lnk_comdat = u32(0x00001000)
pub const scn_lnk_nreloc_ovfl = u32(0x01000000)
pub const scn_mem_discardable = u32(0x02000000)
pub const scn_mem_execute = u32(0x20000000)
pub const scn_mem_read = u32(0x40000000)
pub const scn_mem_write = u32(0x80000000)
// The alignment is four bits in the middle of the characteristic word, spelled
// as a code rather than a count: 1 means one byte, 2 means two, and so on, so
// the code is the base-two logarithm of the alignment plus one.
pub const scn_align_mask = u32(0x00F00000)
pub const scn_align_shift = 20

// The COMDAT selection values a section symbol's auxiliary record carries.
pub const comdat_none = u8(0)
pub const comdat_no_duplicates = u8(1)
pub const comdat_any = u8(2)
pub const comdat_same_size = u8(3)
pub const comdat_exact_match = u8(4)
pub const comdat_associative = u8(5)
pub const comdat_largest = u8(6)

// The storage classes a link reads. A symbol is external whether it is defined
// in this object or is a name the object needs, static when it is a section
// symbol or a file-scope name, and weak external when a link may substitute
// another symbol for it.
pub const sym_class_external = u8(2)
pub const sym_class_static = u8(3)
pub const sym_class_function = u8(101)
pub const sym_class_file = u8(103)
pub const sym_class_section = u8(104)
pub const sym_class_weak_external = u8(105)

// sym_type_function is the high byte of a symbol's type when the symbol names a
// function. Microsoft tools set it for every function and leave it clear for an
// object, and a link reads it to know which of the two a reference reaches.
pub const sym_type_function = u16(0x20)

// The three section numbers that are not a section. Zero is a name this object
// does not define, which is an import unless its value says how much storage it
// wants; -1 is a constant, whose value is the constant; -2 is a debug record the
// linker does not place.
pub const section_number_undefined = 0
pub const section_number_absolute = -1
pub const section_number_debug = -2

// The weak external characteristics: what happens when nothing defines the name,
// which is to search no library, search the libraries, or use the alias the
// symbol names.
pub const weak_extern_search_nolibrary = u32(1)
pub const weak_extern_search_library = u32(2)
pub const weak_extern_alias = u32(3)

// Section is one section header with its name resolved out of the string table
// when the name did not fit in the eight bytes the header holds. The number is
// one-based, the way a symbol's section field and a relocation name a section.
pub struct Section {
pub mut:
	number          int
	name            string
	virtual_size    u32
	virtual_address u32
	raw_size        u32
	raw_offset      int
	reloc_offset    int
	reloc_count     int
	line_offset     int
	line_count      int
	characteristics u32
	// comdat_selection is the value the section symbol's auxiliary record
	// carries, and zero for a section that is not part of a COMDAT group.
	comdat_selection u8
	// associative is the number of the section an ASSOCIATIVE COMDAT member
	// follows, and zero for every other selection.
	associative int
}

// SectionDefinition is the auxiliary record a section symbol carries: how long
// the section is, how many relocations and line numbers it holds, and, for a
// COMDAT group, its selection.
pub struct SectionDefinition {
pub:
	length           u32
	relocation_count u16
	line_count       u16
	checksum         u32
	number           u16
	selection        u8
}

// FunctionDefinition is the auxiliary record an external function symbol
// carries: the size of its code and where its debug records are.
pub struct FunctionDefinition {
pub:
	tag_index     u32
	total_size    u32
	line_offset   u32
	next_function u32
}

// WeakExternal is the auxiliary record a weak external carries: the symbol to
// use when nothing defines this one, and what to search.
pub struct WeakExternal {
pub:
	tag_index       u32
	characteristics u32
}

// Symbol is one symbol table entry, with its name resolved. `index` is where the
// entry stands in the table, which is what a relocation names and what an
// auxiliary record's tag index counts from.
pub struct Symbol {
pub:
	index         int
	name          string
	value         u32
	section       int
	kind          u16
	storage_class u8
	aux_count     int
	// aux is the symbol's auxiliary records as the file holds them. Which
	// record they are depends on what the symbol is, so they are read by the
	// accessor that matches it rather than at parse time.
	aux []u8
}

// section_definition is the auxiliary record of a section symbol, or none when
// the symbol carries none. Every section symbol the format writes carries
// exactly one.
pub fn (s Symbol) section_definition() ?SectionDefinition {
	if s.aux.len < symbol_entry_size {
		return none
	}
	return SectionDefinition{
		length:           read_u32(s.aux, 0) or { return none }
		relocation_count: read_u16(s.aux, 4) or { return none }
		line_count:       read_u16(s.aux, 6) or { return none }
		checksum:         read_u32(s.aux, 8) or { return none }
		number:           read_u16(s.aux, 12) or { return none }
		selection:        s.aux[14]
	}
}

// function_definition is the auxiliary record of a function symbol, or none when
// the symbol carries none.
pub fn (s Symbol) function_definition() ?FunctionDefinition {
	if s.aux.len < symbol_entry_size {
		return none
	}
	return FunctionDefinition{
		tag_index:     read_u32(s.aux, 0) or { return none }
		total_size:    read_u32(s.aux, 4) or { return none }
		line_offset:   read_u32(s.aux, 8) or { return none }
		next_function: read_u32(s.aux, 12) or { return none }
	}
}

// weak_external is the auxiliary record of a weak external, or none when the
// symbol carries none.
pub fn (s Symbol) weak_external() ?WeakExternal {
	if s.aux.len < symbol_entry_size {
		return none
	}
	return WeakExternal{
		tag_index:       read_u32(s.aux, 0) or { return none }
		characteristics: read_u32(s.aux, 4) or { return none }
	}
}

// is_undefined says the symbol is a name this object needs and does not define.
// A common symbol is section zero as well, and it is not undefined: its value is
// the storage the link has to make, so it is told apart by `is_common`.
pub fn (s Symbol) is_undefined() bool {
	return s.section == section_number_undefined && !s.is_common()
}

// is_common says the symbol is a tentative definition: section zero, external,
// and a value that is the number of bytes the link has to place.
pub fn (s Symbol) is_common() bool {
	return s.section == section_number_undefined && s.storage_class == sym_class_external
		&& s.value > 0
}

// is_section_symbol says the symbol names the start of its section rather than a
// function or an object in it. A relocation against one addresses the section,
// and its auxiliary record is where a COMDAT group's selection is written.
pub fn (s Symbol) is_section_symbol() bool {
	return s.storage_class == sym_class_static && s.value == 0
		&& s.section > section_number_undefined
}

// is_function says the symbol names code rather than storage, which is what the
// function bit of its type field states and what a link reads to know whether a
// reference reaches a thunk or an address.
pub fn (s Symbol) is_function() bool {
	return (s.kind & sym_type_function) != 0
}

// is_absolute says the symbol is a constant: its value is the number a reference
// to it stands for, and it has no storage in any section.
pub fn (s Symbol) is_absolute() bool {
	return s.section == section_number_absolute
}

// File is one read object: the header fields a link reads, the sections, the
// symbols and every section's relocations, all in the file's own order.
//
// `bytes` is the file, kept so a caller can read a section's contents without
// being handed a second copy of them. A section's bytes are a slice of it and
// were checked to lie inside it when the section table was read.
pub struct File {
pub:
	machine         u16
	time_date_stamp u32
	characteristics u16
	bytes           []u8
	sections        []Section
	// symbols holds the symbol table entries in file order, with auxiliary
	// records folded into the symbol they belong to. The count is smaller
	// than the header's NumberOfSymbols whenever a symbol carries aux data.
	symbols []Symbol
}

// data is one section's bytes in the file. A section that holds uninitialized
// data has none, which is the empty array: a COFF object states that storage by
// its size in the section table, and the linker makes it.
pub fn (f File) data(section Section) []u8 {
	if section.raw_size == 0 {
		return []u8{}
	}
	return f.bytes[section.raw_offset..section.raw_offset + int(section.raw_size)]
}

// section is one section by its one-based number, or none when the file has no
// such section.
pub fn (f File) section(number int) ?Section {
	if number < 1 || number > f.sections.len {
		return none
	}
	return f.sections[number - 1]
}

// is_comdat says whether a section is a COMDAT group member, which is what makes
// a link able to discard this copy of it.
pub fn (s Section) is_comdat() bool {
	return (s.characteristics & scn_lnk_comdat) != 0
}

// discardable says whether the section may be left out of an image: a debug
// section and a linker directive are marked so, and so is a section the linker
// has been told to remove.
pub fn (s Section) discardable() bool {
	return (s.characteristics & (scn_mem_discardable | scn_lnk_remove)) != 0
}

// alignment is the alignment the section asks for its start in the image, or
// one when the header promises nothing. The code is the logarithm plus one, so
// an explicit value decodes to a power of two and the zero value is treated as
// one byte, the way every COFF linker treats it.
pub fn (s Section) alignment() int {
	code := int((s.characteristics & scn_align_mask) >> scn_align_shift)
	if code <= 1 {
		return 1
	}
	if code > 14 {
		return 8192
	}
	return 1 << (code - 1)
}

// read turns one COFF object into the shape a link reads. It refuses a file that
// is not an object for the AMD64 machine, and it refuses one whose tables point
// outside it rather than trusting a length the file states.
pub fn read(bytes []u8) !File {
	if bytes.len < coff_header_size {
		return error('truncated file: ${bytes.len} bytes is less than the ${coff_header_size}-byte COFF header')
	}
	machine := read_u16(bytes, 0)!
	if machine != image_file_machine_amd64 {
		return error('the object is for ${machine_label(machine)} and this reader reads ${machine_label(image_file_machine_amd64)}')
	}
	optional_size := read_u16(bytes, 16)!
	if optional_size != 0 {
		// An object has no optional header. A nonzero size here is an image,
		// and reading an image as an object would place its sections as if
		// they had no addresses.
		return error('the file carries a ${optional_size}-byte optional header, so it is an image rather than an object')
	}
	section_count := int(read_u16(bytes, 2)!)
	time_date_stamp := read_u32(bytes, 4)!
	symbol_offset := read_u32(bytes, 8)!
	symbol_count := int(read_u32(bytes, 12)!)
	characteristics := read_u16(bytes, 18)!
	table_end := coff_header_size + section_count * section_header_size
	if table_end > bytes.len {
		return error('truncated file: the section table ends at ${table_end} and the file is ${bytes.len} bytes')
	}
	string_table := string_table_at(bytes, symbol_offset, symbol_count)!
	mut sections := []Section{cap: section_count}
	for i in 0 .. section_count {
		sections << read_section(bytes, i, string_table)!
	}
	symbols := read_symbols(bytes, int(symbol_offset), symbol_count, string_table)!
	apply_comdat(mut sections, symbols)
	return File{
		machine:         machine
		time_date_stamp: time_date_stamp
		characteristics: characteristics
		bytes:           bytes
		sections:        sections
		symbols:         symbols
	}
}

// read_symbols walks the symbol table, folding each symbol's auxiliary records
// into it. An auxiliary record is not a symbol: it is the rest of the entry
// before it, and a walk that stepped one entry at a time would hand a link a
// symbol named after whatever bytes the record happened to hold.
//
// The stride is therefore variable, and the last auxiliary record has to end
// inside the table. A count that runs past it is a malformed file and is refused
// rather than clipped.
fn read_symbols(bytes []u8, offset int, count int, string_table []u8) ![]Symbol {
	if count == 0 {
		return []Symbol{}
	}
	if offset == 0 {
		return error('the file states ${count} symbols and names no symbol table')
	}
	if offset + count * symbol_entry_size > bytes.len {
		return error('the symbol table ends at ${offset + count * symbol_entry_size} and the file is ${bytes.len} bytes')
	}
	mut symbols := []Symbol{cap: count}
	mut i := 0
	for i < count {
		at := offset + i * symbol_entry_size
		aux_count := int(bytes[at + 17])
		if i + aux_count >= count {
			return error('symbol ${i} says ${aux_count} auxiliary records follow and the table ends ${count - i - 1} entries after it')
		}
		aux_at := at + symbol_entry_size
		symbols << Symbol{
			index:         i
			name:          symbol_name(bytes, at, string_table)!
			value:         read_u32(bytes, at + 8)!
			section:       int(read_i16(bytes, at + 12)!)
			kind:          read_u16(bytes, at + 14)!
			storage_class: bytes[at + 16]
			aux_count:     aux_count
			aux:           bytes[aux_at..aux_at + aux_count * symbol_entry_size]
		}
		i += 1 + aux_count
	}
	return symbols
}

// symbol_name is the name one table entry holds. A name of eight bytes or fewer
// is in the entry; one with four leading zero bytes names an offset into the
// string table, which is where every longer name lives.
fn symbol_name(bytes []u8, at int, string_table []u8) !string {
	if read_u32(bytes, at)! == 0 {
		offset := int(read_u32(bytes, at + 4)!)
		if string_table.len == 0 {
			return error('the symbol at ${at} names a string and the object has no string table')
		}
		return named_offset(string_table, offset)
	}
	mut end := 0
	for end < 8 && bytes[at + end] != u8(0) {
		end++
	}
	return bytes[at..at + end].bytestr()
}

// named_offset reads a name at an offset into the string table. The first four
// bytes of the table are its own size, so an offset below four names the size
// field rather than a name and is refused.
fn named_offset(string_table []u8, offset int) !string {
	if offset < 4 {
		return error("a name at string table offset ${offset} is inside the table's own size field")
	}
	return cstr(string_table, offset)
}

// apply_comdat reads each COMDAT section's selection out of its section symbol's
// auxiliary record. The record is the only place the format writes the
// selection, so a section table on its own says a section is a COMDAT member and
// nothing more; which member wins a link is decided from here.
fn apply_comdat(mut sections []Section, symbols []Symbol) {
	for symbol in symbols {
		if !symbol.is_section_symbol() || symbol.section > sections.len {
			continue
		}
		mut section := sections[symbol.section - 1]
		if section.name != symbol.name {
			continue
		}
		definition := symbol.section_definition() or { continue }
		if definition.selection == comdat_none {
			continue
		}
		section.comdat_selection = definition.selection
		if definition.selection == comdat_associative {
			section.associative = int(definition.number)
		}
		sections[symbol.section - 1] = section
	}
}

// read_section reads one 40-byte section header and resolves its name. A name
// that begins with `/` is a decimal offset into the string table, which is how a
// name longer than eight bytes is written; a name that fills all eight bytes
// without a terminator is taken as it stands.
fn read_section(bytes []u8, index int, string_table []u8) !Section {
	at := coff_header_size + index * section_header_size
	raw_offset := int(read_u32(bytes, at + 20)!)
	raw_size := read_u32(bytes, at + 16)!
	if raw_size > 0 && raw_offset + int(raw_size) > bytes.len {
		return error('section ${index + 1} ends at ${raw_offset + int(raw_size)} and the file is ${bytes.len} bytes')
	}
	reloc_offset := int(read_u32(bytes, at + 24)!)
	reloc_count := int(read_u16(bytes, at + 32)!)
	line_offset := int(read_u32(bytes, at + 28)!)
	characteristics := read_u32(bytes, at + 36)!
	if reloc_count == int(relocation_overflow_count) && (characteristics & scn_lnk_nreloc_ovfl) != 0 {
		return error('section ${index + 1} asks for the extended relocation count, which this reader does not read yet')
	}
	if reloc_count > 0 {
		end := reloc_offset + reloc_count * relocation_entry_size
		if end > bytes.len {
			return error('the ${reloc_count} relocations of section ${index + 1} end at ${end} and the file is ${bytes.len} bytes')
		}
	}
	return Section{
		number:          index + 1
		name:            section_name(bytes, at, string_table)!
		virtual_size:    read_u32(bytes, at + 8)!
		virtual_address: read_u32(bytes, at + 12)!
		raw_size:        raw_size
		raw_offset:      raw_offset
		reloc_offset:    reloc_offset
		reloc_count:     reloc_count
		line_offset:     line_offset
		line_count:      int(read_u16(bytes, at + 34)!)
		characteristics: characteristics
	}
}

// string_table_at answers the file's string table, or an empty array when it has
// none. The table starts behind the symbol table and begins with its own
// four-byte size, which counts itself; the last byte of the table is therefore
// `start + size`, and a size field that points past the file is a malformed file
// rather than an empty table.
fn string_table_at(bytes []u8, symbol_offset u32, symbol_count int) ![]u8 {
	if symbol_offset == 0 || symbol_count == 0 {
		return []u8{}
	}
	start := u64(symbol_offset) + u64(symbol_count) * u64(symbol_entry_size)
	if start + 4 > u64(bytes.len) {
		return error('truncated file: the ${symbol_count} symbols end at ${start} and the file is ${bytes.len} bytes')
	}
	size := read_u32(bytes, int(start))!
	if size < 4 {
		return error('the string table at ${start} says it is ${size} bytes, and its own size field is four')
	}
	if start + u64(size) > u64(bytes.len) {
		return error('truncated file: the string table ends at ${start + u64(size)} and the file is ${bytes.len} bytes')
	}
	return bytes[int(start)..int(start + u64(size))]
}

// section_name is the name an eight-byte field holds: the bytes up to a
// terminator, or an offset into the string table when the field begins with a
// slash. A field of eight bytes with no terminator is a complete name.
fn section_name(bytes []u8, at int, string_table []u8) !string {
	mut end := 0
	for end < 8 {
		if bytes[at + end] == u8(0) {
			break
		}
		end++
	}
	if end == 0 {
		return ''
	}
	raw := bytes[at..at + end]
	if raw[0] == u8(`/`) {
		return long_name(raw, string_table)
	}
	return raw.bytestr()
}

// long_name resolves a `/nnn` name against the string table. A name spelled with
// two slashes is the base64 form some MSVC versions write, which this reader
// does not interpret: reading it as a number would land on bytes that are not
// the name, so it is refused by its text instead.
fn long_name(raw []u8, string_table []u8) !string {
	if raw.len > 1 && raw[1] == u8(`/`) {
		return error('the section name ${raw.bytestr()} is the base64 form of a long name, which this reader does not interpret')
	}
	mut offset := 0
	for i in 1 .. raw.len {
		if raw[i] < u8(`0`) || raw[i] > u8(`9`) {
			return error('the section name ${raw.bytestr()} is neither eight bytes nor a decimal offset into the string table')
		}
		offset = offset * 10 + int(raw[i] - u8(`0`))
	}
	if string_table.len == 0 {
		return error('the section name ${raw.bytestr()} names a string and the file has no string table')
	}
	return cstr(string_table, offset)
}

// machine_name is what a COFF machine number is called, for a diagnostic. A
// number outside the table has no name here, which is why the caller uses
// `machine_label` rather than this function alone.
pub fn machine_name(machine u16) string {
	return match machine {
		0x014c { 'i386' }
		0x8664 { 'amd64' }
		0xaa64 { 'arm64' }
		0x01c4 { 'armnt' }
		else { '' }
	}
}

// machine_label is a machine number spelled the way a diagnostic can use it,
// including a number this reader has no name for.
fn machine_label(machine u16) string {
	name := machine_name(machine)
	if name == '' {
		return 'machine 0x${machine.hex()}'
	}
	return name
}

// cstr reads a NUL-terminated name out of a table of strings. A name that runs
// to the end of the table without a terminator is refused rather than cut short.
fn cstr(bytes []u8, at int) !string {
	if at < 0 || at >= bytes.len {
		return error('a name at ${at} is outside the ${bytes.len} bytes of the string table')
	}
	mut end := at
	for end < bytes.len && bytes[end] != u8(0) {
		end++
	}
	if end >= bytes.len {
		return error('a name at ${at} has no terminator in a string table of ${bytes.len} bytes')
	}
	return bytes[at..end].bytestr()
}

fn read_u16(bytes []u8, at int) !u16 {
	if at < 0 || at + 2 > bytes.len {
		return error('a two-byte field at ${at} is outside the ${bytes.len} bytes of the file')
	}
	return u16(bytes[at]) | (u16(bytes[at + 1]) << 8)
}

// read_i16 is the same two bytes read as a signed number, which is what a
// symbol's section field is: the negative values are the sections a file does
// not have, not large section numbers.
fn read_i16(bytes []u8, at int) !i16 {
	return i16(read_u16(bytes, at)!)
}

fn read_u32(bytes []u8, at int) !u32 {
	if at < 0 || at + 4 > bytes.len {
		return error('a four-byte field at ${at} is outside the ${bytes.len} bytes of the file')
	}
	mut value := u32(0)
	for i in 0 .. 4 {
		value |= u32(bytes[at + i]) << (8 * i)
	}
	return value
}
