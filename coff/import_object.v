module coff

// A short import member is what an import library holds in place of an object:
// a 20-byte header that names a DLL and one export of it, and the two strings
// behind the header. It carries no code, so nothing in this file places or
// relocates anything; the caller decides what an import means to a link.
//
// The layout is the one docs/pe/08-libraries.md describes, and the one LLVM's
// llvm/Object/COFFImportFile.cpp writes.
//
// A member is read from a slice of an archive, so every offset is checked
// against that slice before it is used. The string area is bounded by the
// header's own SizeOfData and by the member's length, and a name is read only
// from inside that area.

// The three kinds of import. A code import is a call into the DLL, a data
// import is a variable the image reaches through the import address table, and
// a const import is a value the DLL exports.
pub const import_code = u16(0)
pub const import_data = u16(1)
pub const import_const = u16(2)

// Sig1 is zero and Sig2 is 0xffff. Together they are the machine number
// IMAGE_FILE_MACHINE_UNKNOWN, which no COFF object begins with: an object's
// header starts with the machine it was built for, so the two member kinds are
// told apart by these four bytes alone.
const import_sig1 = u16(0)
const import_sig2 = u16(0xffff)

// The header's length. The string area follows it and SizeOfData counts the
// strings, terminators included.
const import_header_size = 20

// The Type field. The low two bits are the kind; the three bits above them are
// the name type, which says whether the Ordinal/Hint field holds an export
// number or a hint.
const import_type_mask = u16(0x0003)
const import_name_type_shift = 2
const import_name_type_mask = u16(0x0007)
const import_name_ordinal = u16(0)

// The high bit of the Ordinal/Hint field. It is not part of the import header's
// definition: the format states by ordinal through the name type, and every
// writer this reader has been checked against leaves the high bit clear. It is
// still read, because a member that sets it is asking to be read by number and
// reading it as a hint would put a wrong export in the image.
const import_ordinal_bit = u16(0x8000)
const import_ordinal_mask = u16(0x7fff)

// ImportMember is one short import member, decoded. `name` is the symbol the
// member spells, not the export it reaches: an archive writes `__imp_foo` in
// some members and `foo` in others, and which prefix means what is the calling
// convention's business, not this reader's.
pub struct ImportMember {
pub:
	machine         u16
	time_date_stamp u32
	// hint is the Ordinal/Hint field: the export number when the member
	// imports by number, and the hint a by-name member states in it.
	hint u16
	// by_ordinal says the member names an export number rather than a name.
	// The format says so through the name type, and a member that sets the
	// high bit of the field says so as well.
	by_ordinal bool
	// kind is import_code, import_data or import_const.
	kind u16
	// name is the symbol as the member spells it, undecorated and undecoded:
	// __imp_ symbols arrive with the prefix the archive wrote, and the caller
	// decides what prefix means.
	name    string
	library string
	// exported is the name the DLL exports when it differs from the symbol the
	// member defines. A member for `__imp_foo` names `__imp_foo` and says the
	// DLL answers to `foo`; a member whose two names agree carries no third
	// string and leaves this empty.
	exported string
}

// is_import_member says whether a member holds a short import header. It reads
// four bytes and no more, so it answers for a member of any length and for a
// member the caller has not yet decided how to treat.
pub fn is_import_member(bytes []u8) bool {
	if bytes.len < 4 {
		return false
	}
	sig1 := read_u16(bytes, 0) or { return false }
	sig2 := read_u16(bytes, 2) or { return false }
	return sig1 == import_sig1 && sig2 == import_sig2
}

// read_import_member decodes one short import member.
//
// It refuses the archive's null import descriptor by name: that member carries
// the signature and nothing else, and reading it as an import would hand the
// caller a symbol with an empty name and a library with an empty name.
//
// It refuses a header the member is too short to hold, a string area that runs
// past the member, a name with no terminator inside its area, an empty symbol
// name, and a kind the format does not define.
pub fn read_import_member(bytes []u8) !ImportMember {
	if bytes.len < import_header_size {
		return error('truncated import member: ${bytes.len} bytes is less than the ${import_header_size}-byte import header')
	}
	if !is_import_member(bytes) {
		sig1 := read_u16(bytes, 0)!
		sig2 := read_u16(bytes, 2)!
		return error('the member begins with 0x${sig1.hex()} and 0x${sig2.hex()} rather than the 0 and 0xffff of a short import header')
	}
	version := read_u16(bytes, 4)!
	machine := read_u16(bytes, 6)!
	time_date_stamp := read_u32(bytes, 8)!
	size_of_data := read_u32(bytes, 12)!
	ordinal_hint := read_u16(bytes, 16)!
	type_info := read_u16(bytes, 18)!
	if version == 0 && machine == 0 && time_date_stamp == 0 && size_of_data == 0
		&& ordinal_hint == 0 && type_info == 0 {
		return error('the member is the null import descriptor: the import signature and no field after it')
	}
	// SizeOfData is the length of the string area, and the area is the rest of
	// the member. A count that reaches past the member is a malformed member,
	// and the names are read from inside the count rather than from the member,
	// because a name that ran past the count would be read from bytes that are
	// not part of this member.
	area_start := import_header_size
	area_end := u64(area_start) + u64(size_of_data)
	if area_end > u64(bytes.len) {
		return error('truncated import member: its ${size_of_data}-byte string area ends at ${area_end} and the member is ${bytes.len} bytes')
	}
	area := bytes[area_start..int(area_end)]
	mut symbol_end := -1
	for i, byte in area {
		if byte == u8(0) {
			symbol_end = i
			break
		}
	}
	if symbol_end < 0 {
		return error('the symbol name of the import member has no terminator in its ${area.len}-byte string area')
	}
	if symbol_end == 0 {
		return error('the import member names no symbol: its string area begins with the terminator')
	}
	name := area[..symbol_end].bytestr()
	mut library_end := -1
	for i in symbol_end + 1 .. area.len {
		if area[i] == u8(0) {
			library_end = i
			break
		}
	}
	if library_end < 0 {
		return error('the DLL name of the import member has no terminator in its ${area.len}-byte string area')
	}
	library := area[symbol_end + 1..library_end].bytestr()
	// A third string, when the area holds one, is the DLL's own name for the
	// export. A member that defines the name the DLL exports carries two
	// strings and nothing after them.
	mut exported := ''
	if library_end + 1 < area.len {
		rest := area[library_end + 1..]
		mut third_end := -1
		for i, byte in rest {
			if byte == u8(0) {
				third_end = i
				break
			}
		}
		if third_end > 0 {
			exported = rest[..third_end].bytestr()
		}
	}
	kind := type_info & import_type_mask
	if kind > import_const {
		return error('the import member is type ${kind}, and the format defines code, data and const')
	}
	name_type := (type_info >> import_name_type_shift) & import_name_type_mask
	// A member that imports by number keeps the number in the whole field. The
	// mask is the hint a by-name member carries, and applying it here would
	// truncate an export number above 32767 to a different export.
	by_ordinal := (ordinal_hint & import_ordinal_bit) != 0 || name_type == import_name_ordinal
	// Two spellings mark a by-number member. When the high bit is set it is a
	// mark and the number is the low fifteen bits; when the member says so
	// through its name type the field is the number itself, and that is the
	// spelling a librarian writes, so an ordinal above 32767 is read whole.
	hint := if name_type == import_name_ordinal {
		// The name type states the whole field is the number, and an ordinal
		// above 32767 has the high bit set without that meaning a mark.
		ordinal_hint
	} else if by_ordinal {
		ordinal_hint & import_ordinal_mask
	} else {
		ordinal_hint
	}
	return ImportMember{
		machine:         machine
		time_date_stamp: time_date_stamp
		hint:            hint
		by_ordinal:      by_ordinal
		kind:            kind
		name:            name
		library:         library
		exported:        exported
	}
}
