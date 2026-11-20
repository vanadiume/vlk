module pe

// The debug directory is what an image says about the debug information that
// belongs with it. Windows never reads it: the loader maps sections and runs the
// entry point. A debugger reads the entry, takes the GUID, the age and the path
// out of the CodeView record, and looks for a PDB that matches all three.
//
// One entry is written, IMAGE_DEBUG_TYPE_CODEVIEW, and the record it describes
// is placed immediately after it, so a section's bytes are the entry and then
// the record with nothing between them. The entry names the record's address in
// the image and its offset in the file, which the caller gives because the
// caller has already placed the section that holds them.

// debug_entry_size is the length of one IMAGE_DEBUG_DIRECTORY record.
const debug_entry_size = 28

// debug_type_codeview is IMAGE_DEBUG_TYPE_CODEVIEW, the type whose data is an
// RSDS record and a path.
const debug_type_codeview = u32(2)

// codeview_signature begins a CV_INFO_PDB70 record. The older shape begins with
// 'NB10' and describes a PDB 2.0 file; nothing here writes one.
const codeview_signature = 'RSDS'

// codeview_fixed_size is the part of the record that comes before the path: the
// signature, the sixteen bytes of GUID, and the age. The record states its own
// length, terminator included, in a 32-bit field, and that field is what bounds
// the path.
const codeview_fixed_size = 4 + 16 + 4

// max_size_of_data is the largest number the record's size field can hold.
const max_size_of_data = int(4294967295)

// CodeView is the pair a PDB and its image agree on, and the path the debugger
// looks in. A PDB holds the same GUID and age; a debugger that finds a file
// whose pair differs refuses it, which is why an image built against a stale PDB
// cannot be debugged.
pub struct CodeView {
pub:
	// pdb_path is the path the debugger looks for, written as given. It is
	// usually absolute at build time, and the file name alone is what a symbol
	// server needs.
	pdb_path string
	// guid is the sixteen bytes that identify the PDB. They are copied in the
	// order given: a GUID's fields are stored here the way its writer laid them
	// out, and reordering them would build a record no PDB matches.
	guid [16]u8
	// age counts the times the PDB was written for one GUID, and starts at one.
	age u32
}

// DebugDirectory is the bytes of a debug directory section and the two lengths a
// reader takes from it.
pub struct DebugDirectory {
pub:
	// data is one IMAGE_DEBUG_DIRECTORY record followed by its CodeView
	// record, laid out to be placed as a section's bytes.
	data []u8
	// entry_size is 28, the length of the directory record.
	entry_size int
	// record_size is the CodeView record's length, which the record states as
	// SizeOfData.
	record_size int
}

// codeview_directory builds the entry and the record it points at for one PDB.
// rva is the address the section will land at and file_offset is where its bytes
// start in the file, so the entry's two pointers are those numbers plus the
// entry's own length. An image that cannot state the record's address or its
// size is refused rather than written with a field cut short.
pub fn codeview_directory(view CodeView, rva int, file_offset int) !DebugDirectory {
	if view.pdb_path.len == 0 {
		return error('the CodeView record needs a PDB path and was given an empty one')
	}
	record_size := codeview_record_size(view.pdb_path.len)!
	if rva < 0 {
		return error('the debug directory was given the rva ${rva}, and an address in a PE image is unsigned')
	}
	if file_offset < 0 {
		return error('the debug directory was given the file offset ${file_offset}, and a file offset is unsigned')
	}
	address := rva + debug_entry_size
	pointer := file_offset + debug_entry_size
	if address > max_size_of_data {
		return error('the record would sit at the rva ${address}, and AddressOfRawData holds at most ${max_size_of_data}')
	}
	if pointer > max_size_of_data {
		return error('the record would sit at the file offset ${pointer}, and PointerToRawData holds at most ${max_size_of_data}')
	}
	path := view.pdb_path.bytes()
	mut data := []u8{len: debug_entry_size + record_size}
	// The entry: a timestamp of zero, because two links of one input should
	// differ in nothing, and the record's address inside the section that holds
	// both.
	put_u32(mut data, 0, 0) // Characteristics
	put_u32(mut data, 4, 0) // TimeDateStamp
	put_u16(mut data, 8, 0) // MajorVersion
	put_u16(mut data, 10, 0) // MinorVersion
	put_u32(mut data, 12, debug_type_codeview)
	put_u32(mut data, 16, u32(record_size)) // SizeOfData
	put_u32(mut data, 20, u32(address)) // AddressOfRawData
	put_u32(mut data, 24, u32(pointer)) // PointerToRawData
	// The record: the signature, the GUID byte for byte, the age, then the path
	// and the NUL that ends it.
	put(mut data, debug_entry_size, codeview_signature.bytes())
	for i, byte in view.guid {
		put_u8(mut data, debug_entry_size + 4 + i, byte)
	}
	put_u32(mut data, debug_entry_size + 20, view.age)
	put(mut data, debug_entry_size + codeview_fixed_size, path)
	put_u8(mut data, debug_entry_size + codeview_fixed_size + path.len, 0)
	return DebugDirectory{
		data:        data
		entry_size:  debug_entry_size
		record_size: record_size
	}
}

// codeview_record_size is the length of the record for a path of path_len bytes,
// or an error when the record's own size field cannot state it. The field is
// unsigned and 32 bits wide, so that is where a path stops being placeable.
fn codeview_record_size(path_len int) !int {
	if path_len > max_size_of_data - codeview_fixed_size - 1 {
		return error('a PDB path of ${path_len} bytes does not fit: the CodeView record states its size in 32 bits, and a record of at most ${max_size_of_data} bytes is what that field holds')
	}
	return codeview_fixed_size + path_len + 1
}
