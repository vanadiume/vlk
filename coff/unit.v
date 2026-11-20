module coff

import vanadiume.vlk.target
import vanadiume.vlk.unit

// Turning a COFF object into the unit a link merges. The reader in `coff.v`
// answers what the file holds; this file decides what a link does with it, which
// is the same question `object/` answers for an ELF object: which blob a section
// goes into, where each symbol lands, and what each reference is measured from.
//
// The blobs are the unit's three, plus the thread-local one, and they are the
// same three an ELF object fills: code, read-only data, writable data. A section
// whose name is not one of theirs is a named section the image keeps, because a
// PE image maps sections by name and `.pdata` is not part of any blob.
//
// The addend of a COFF relocation is in the field rather than in the entry, so
// every reference is read with the bytes it will be written back into: that is
// what the field holds now, and the unit's convention is that a reference
// carries the distance from the end of its field.

// Part is which of a unit's parts one file section becomes.
enum Part {
	none
	code
	writable
	read_only
	tls
	// named is a section the image keeps under its own name, which is what a
	// PE container places by name rather than merging into a blob.
	named
}

// is_object says whether bytes are a COFF object: a file whose machine is the
// one this reader knows and which names no optional header, because an image
// does and an object does not.
pub fn is_object(bytes []u8) bool {
	if bytes.len < coff_header_size {
		return false
	}
	machine := u16(bytes[0]) | (u16(bytes[1]) << 8)
	if machine != image_file_machine_amd64 {
		return false
	}
	optional := u16(bytes[16]) | (u16(bytes[17]) << 8)
	return optional == 0
}

// Placement is where each file section went: which part of the unit it became,
// where it starts there, and, for a named section, the name the image keeps.
struct Placement {
mut:
	part []Part
	base []int
	name []string
	// text, writable, read_only and tls are the blobs, built in section order.
	text      []u8
	writable  []u8
	read_only []u8
	tls       []u8
	// sections are the named sections, one entry per file section: the merge
	// concatenates the entries two units give one name.
	sections []unit.Section
}

// read_unit turns one COFF object into the unit a link merges.
pub fn read_unit(bytes []u8, machine target.Target) !unit.Program {
	file := read(bytes)!
	if machine.coff_machine != 0 && file.machine != machine.coff_machine {
		return error('the object is for machine ${file.machine} and the link is for ${machine.name}')
	}
	placed := place(file)!
	mut program := unit.Program{
		text:                placed.text
		string_blob:         placed.read_only
		globals_blob:        placed.writable
		globals_alignment:   8
		read_only_alignment: 8
		tls_blob:            placed.tls
		tls_size:            placed.tls.len
		tls_alignment:       8
		labels:              map[string]int{}
		defined:             map[string]bool{}
		globals:             map[string]unit.GlobalSlot{}
		internal:            map[string]bool{}
		weak:                map[string]bool{}
		hidden:              map[string]bool{}
		weak_imports:        map[string]bool{}
		tls_slots:           map[string]bool{}
		read_only_globals:   map[string]unit.GlobalSlot{}
		strings:             map[string]int{}
		wide_strings:        map[string]int{}
		doubles:             map[string]int{}
		imports:             []string{}
		object_imports:      map[string]bool{}
		copy_objects:        []string{}
		libraries:           []string{}
		bound:               map[string]unit.Definition{}
		tls_labels:          map[string]int{}
		ifuncs:              map[string]bool{}
		sections:            placed.sections
	}
	read_directives(file, mut program)!
	read_unit_symbols(file, placed, mut program)!
	read_object_relocations(file, placed, mut program)!
	return program
}

// place walks the section table once and copies each allocatable section into the
// part its name asks for. A section a link does not place, because it is a
// directive or a table the writer of the object used, is dropped; a section this
// reader has no rule for is refused by name rather than placed somewhere it
// would be read wrong.
fn place(file File) !Placement {
	mut placed := Placement{
		part: []Part{len: file.sections.len, init: .none}
		base: []int{len: file.sections.len}
		name: []string{len: file.sections.len}
	}
	for i, section in file.sections {
		if section.name == '' {
			continue
		}
		base_name := section.name.all_before('$')
		alignment := section.alignment()
		match base_name {
			'.text' {
				placed.part[i] = .code
				placed.base[i] = append_at(mut placed.text, data_of(file, section), alignment)
			}
			'.data' {
				placed.part[i] = .writable
				placed.base[i] = append_at(mut placed.writable, data_of(file, section), alignment)
			}
			'.bss' {
				// A section with no bytes in the file still asks for storage,
				// and the size is in its section symbol's auxiliary record
				// because the header has nowhere to put it.
				placed.part[i] = .writable
				size := storage_size(file, section)
				placed.base[i] = placed.writable.len
				placed.writable << []u8{len: size}
			}
			'.rdata' {
				placed.part[i] = .read_only
				placed.base[i] = append_at(mut placed.read_only, data_of(file, section),
					alignment)
			}
			'.tls' {
				placed.part[i] = .tls
				placed.base[i] = append_at(mut placed.tls, data_of(file, section), alignment)
			}
			'.pdata', '.xdata', '.rsrc' {
				placed.part[i] = .named
				placed.name[i] = base_name
				placed.sections << unit.Section{
					name:      base_name
					data:      data_of(file, section)
					alignment: alignment
					kind:      .read_only
					comdat:    comdat_of(file, section)
				}
			}
			'.debug' {
				// CodeView data belongs to a PDB, and a link that writes no PDB
				// has nothing to put it in: the loader never reads it and an
				// image that carried it would carry bytes no symbol file
				// matched. It is dropped rather than placed.
				continue
			}
			'.drectve' {
				// A directive section is read by `read_directives`; it is not
				// placed, and the object is refused there if it asks for
				// something this link does not do.
				continue
			}
			else {
				if section.discardable() || section.characteristics & scn_lnk_info != 0 {
					continue
				}
				return error('section ${section.name} is not one this reader carries: it is neither a blob its name names nor a section a PE image keeps')
			}
		}
	}
	return placed
}

// data_of is a section's bytes in the file. A section with no bytes has none, and
// a `.bss` section's storage is made from its size rather than copied.
fn data_of(file File, section Section) []u8 {
	if section.raw_size == 0 {
		return []u8{}
	}
	return file.data(section)
}

// storage_size is how much storage a section with no bytes asks for: the length
// its section symbol's auxiliary record states, and the furthest byte any symbol
// in it names when the object carries no such record.
fn storage_size(file File, section Section) int {
	mut size := 0
	for symbol in file.symbols {
		if symbol.section != section.number {
			continue
		}
		if definition := symbol.section_definition() {
			if int(definition.length) > size {
				size = int(definition.length)
			}
		}
		if int(symbol.value) > size {
			size = int(symbol.value)
		}
	}
	return size
}

// comdat_of is the name of the COMDAT group a section belongs to, which is the
// symbol that follows the section symbol in the same section. It is how a link
// knows which sections of two objects are copies of one thing.
fn comdat_of(file File, section Section) string {
	if !section.is_comdat() {
		return ''
	}
	for symbol in file.symbols {
		if symbol.section != section.number || symbol.is_section_symbol() {
			continue
		}
		if symbol.name != '' && symbol.name != section.name {
			return symbol.name
		}
	}
	return ''
}

// append_at appends bytes at an alignment and answers where they start. A place
// is always at least one byte apart, and an alignment of zero promises nothing.
fn append_at(mut blob []u8, data []u8, alignment int) int {
	gap := if alignment > 1 { alignment } else { 1 }
	for blob.len % gap != 0 {
		blob << u8(0)
	}
	at := blob.len
	blob << data
	return at
}

// read_directives reads the linker options an object carries in `.drectve`. The
// only one this link honors is `/EXPORT:`, which is how a declaration of
// `__declspec(dllexport)` reaches a linker; every other directive is refused by
// name, because an option accepted and acted on by nothing is a link that
// believes something it did not do.
fn read_directives(file File, mut program unit.Program) ! {
	for section in file.sections {
		if section.name != '.drectve' {
			continue
		}
		text := data_of(file, section).bytestr()
		for word in text.split(' ') {
			option := word.trim_space().trim('"')
			if option == '' {
				continue
			}
			if option.starts_with('/EXPORT:') {
				name := option.all_after('/EXPORT:').all_before(',')
				if name != '' {
					program.exports << unit.Export{
						name: name
					}
				}
				continue
			}
			return error('the object asks for ${option}, a linker option this reader does not honor')
		}
	}
}

// read_symbols records what the object defines and what it needs. A section
// symbol is the object's own scaffolding and is skipped; a symbol defined in the
// code becomes a label, one in the writable data a slot, one in read-only data a
// slot of that blob, and a thread-local one an offset in the thread-local block.
// A common symbol's storage is made here, at the size its value states, because
// the link is what places it.
fn read_unit_symbols(file File, placed Placement, mut program unit.Program) ! {
	mut seen := map[string]bool{}
	for symbol in file.symbols {
		name := symbol.name
		if symbol.is_section_symbol() || name == '' {
			continue
		}
		if symbol.storage_class == sym_class_file || symbol.storage_class == sym_class_function {
			continue
		}
		if symbol.is_absolute() || symbol.section == section_number_debug {
			continue
		}
		if symbol.section == section_number_undefined {
			if symbol.is_common() {
				align := 8
				for program.globals_blob.len % align != 0 {
					program.globals_blob << u8(0)
				}
				program.globals[name] = unit.GlobalSlot{
					offset: program.globals_blob.len
					width:  int(symbol.value)
				}
				program.globals_blob << []u8{len: int(symbol.value)}
				continue
			}
			// The index a thread-local model reads is supplied by the image
			// rather than by a library, so the name is not an import even
			// though the object leaves it undefined.
			if name == '_tls_index' {
				continue
			}
			if name !in seen {
				seen[name] = true
				program.imports << name
			}
			continue
		}
		if symbol.section > file.sections.len {
			return error('symbol ${name} names section ${symbol.section} and the file has ${file.sections.len}')
		}
		i := symbol.section - 1
		offset := placed.base[i] + int(symbol.value)
		match placed.part[i] {
			.code {
				program.labels[name] = offset
				program.defined[name] = true
			}
			.writable {
				program.globals[name] = unit.GlobalSlot{
					offset: offset
					width:  8
				}
			}
			.read_only {
				program.read_only_globals[name] = unit.GlobalSlot{
					offset: offset
					width:  8
				}
			}
			.tls {
				program.tls_labels[name] = offset
			}
			.named {
				// A named section's symbols are addressed by the section and a
				// byte, which is what a reference to one becomes below.
			}
			.none {}
		}
		if symbol.storage_class == sym_class_static {
			program.internal[name] = true
		}
	}
}

// read_object_relocations reads every reference the object left, in section
// order, with the addend the field holds now. A reference to a section symbol
// names the section rather than a symbol, which is how `.pdata` points at
// `.text`: the section's own name and the byte inside it.
fn read_object_relocations(file File, placed Placement, mut program unit.Program) ! {
	for relocation in file.relocations {
		if relocation.section < 1 || relocation.section > file.sections.len {
			continue
		}
		i := relocation.section - 1
		part := placed.part[i]
		if part == .none {
			continue
		}
		symbol := file.symbol_for(relocation.symbol) or {
			return error('a relocation in ${file.sections[i].name} names table index ${relocation.symbol}, which the symbol walk did not record')
		}
		width := field_width_of(relocation.kind) or {
			return error('a relocation in ${file.sections[i].name} is type ${relocation.kind}, which this reader does not carry')
		}
		stored := field_addend(file, file.sections[i], relocation.offset, width)
		reference := reference_of(file, placed, symbol)!
		form := relocation_kind_of(relocation.kind)!
		mut field_place := unit.RelocationPlace.text
		mut named_section := ''
		match part {
			.code { field_place = .text }
			.read_only { field_place = .read_only }
			.writable { field_place = .data }
			.tls {
				return error('a relocation lies in the thread-local template of ${file.sections[i].name}, and this reader carries no reference inside one')
			}
			.named {
				field_place = .section
				named_section = placed.name[i]
			}
			.none {}
		}
		program.relocations << unit.Relocation{
			offset:  relocation.offset
			place:   field_place
			section: named_section
			kind:    form.kind
			name:    reference.name
			addend:  stored + reference.addend + form.extra
			width:   width
		}
	}
}

// reference_of is the name a reference is written under and the byte the name
// stands at inside the unit. A section symbol becomes the key of the part its
// section went to, with the byte inside that part; a named symbol in a named
// section becomes the section and the byte, because the image has no symbol of
// that name; and every other defined name keeps its own name, because the label
// or the slot is already where it landed.
struct Reference {
	name   string
	addend int
}

fn reference_of(file File, placed Placement, symbol Symbol) !Reference {
	if symbol.is_absolute() {
		return Reference{}
	}
	if symbol.section == section_number_undefined {
		return Reference{
			name: symbol.name
		}
	}
	if symbol.section < 1 || symbol.section > file.sections.len {
		return error('symbol ${symbol.name} names section ${symbol.section} and the file has ${file.sections.len}')
	}
	i := symbol.section - 1
	offset := placed.base[i] + int(symbol.value)
	match placed.part[i] {
		.code {
			if symbol.is_section_symbol() {
				return Reference{
					name:   unit.section_key_text
					addend: offset
				}
			}
			return Reference{
				name: symbol.name
			}
		}
		.read_only {
			if symbol.is_section_symbol() {
				return Reference{
					name:   unit.section_key_rodata
					addend: offset
				}
			}
			return Reference{
				name: symbol.name
			}
		}
		.writable {
			if symbol.is_section_symbol() {
				return Reference{
					name:   unit.section_key_data
					addend: offset
				}
			}
			return Reference{
				name: symbol.name
			}
		}
		.tls {
			return Reference{
				name: symbol.name
			}
		}
		.named {
			return Reference{
				name:   placed.name[i]
				addend: int(symbol.value)
			}
		}
		.none {
			return error('symbol ${symbol.name} lies in a section this link does not place')
		}
	}
}

// relocation_kind_of is how one AMD64 relocation reaches what it names, and the
// constant a field subtracts beyond the addend it holds. A relative reference is
// measured from the end of its field, so the four bytes of the field and the
// bytes after it are the extra the formula carries.
struct RelocationForm {
	kind  unit.RelocationKind
	extra int
}

fn relocation_kind_of(kind u16) !RelocationForm {
	return match kind {
		rel_amd64_addr64 { RelocationForm{unit.RelocationKind.absolute, 0} }
		rel_amd64_addr32 { RelocationForm{unit.RelocationKind.absolute, 0} }
		rel_amd64_addr32nb { RelocationForm{unit.RelocationKind.rva, 0} }
		rel_amd64_rel32 { RelocationForm{unit.RelocationKind.direct, -4} }
		rel_amd64_rel32_1 { RelocationForm{unit.RelocationKind.direct, -5} }
		rel_amd64_rel32_2 { RelocationForm{unit.RelocationKind.direct, -6} }
		rel_amd64_rel32_3 { RelocationForm{unit.RelocationKind.direct, -7} }
		rel_amd64_rel32_4 { RelocationForm{unit.RelocationKind.direct, -8} }
		rel_amd64_rel32_5 { RelocationForm{unit.RelocationKind.direct, -9} }
		// A section-relative field is how the code names a thread-local: the
		// number is the variable's offset inside one thread's copy, which is
		// what the unit's thread-local labels already hold.
		rel_amd64_secrel, rel_amd64_secrel7 { RelocationForm{unit.RelocationKind.tls_offset, 0} }
		else {
			return error('relocation type ${kind} is one a span-dependent or section-relative entry uses, and this reader carries neither')
		}
	}
}

// field_width_of is how many bytes of the field a relocation writes, or none for
// a type this reader does not carry.
fn field_width_of(kind u16) ?unit.RelocationWidth {
	return match kind {
		rel_amd64_addr64 { unit.RelocationWidth.wide }
		rel_amd64_addr32, rel_amd64_addr32nb, rel_amd64_rel32, rel_amd64_rel32_1,
		rel_amd64_rel32_2, rel_amd64_rel32_3, rel_amd64_rel32_4, rel_amd64_rel32_5,
		rel_amd64_secrel, rel_amd64_secrel7 {
			unit.RelocationWidth.narrow
		}
		else {
			none
		}
	}
}

// read_field is the addend a reference's field holds now: four or eight bytes at
// the byte the relocation names, inside the section's file bytes. A field past
// the section is refused rather than read from the next one.
fn field_addend(file File, section Section, offset u32, width unit.RelocationWidth) int {
	data := file.data(section)
	size := if width == .wide { 8 } else { 4 }
	if int(offset) + size > data.len {
		return 0
	}
	mut value := i64(0)
	for i in 0 .. size {
		value |= i64(data[int(offset) + i]) << (8 * i)
	}
	if width == .narrow && (value & 0x80000000) != 0 {
		// A relative field is signed, and the bytes are the addend a compiler
		// wrote; sign-extending it is what the number means.
		value -= i64(0x100000000)
	}
	return int(value)
}
