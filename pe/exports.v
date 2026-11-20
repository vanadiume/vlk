module pe

// The export directory: what a PE image says another image may call or read by
// name, and the three tables the loader reads to answer a name or an ordinal.
//
// A name is sorted into the name pointer table, and the ordinal table beside it
// says which address table slot that name means. The address table is indexed by
// ordinal rather than by name, so its first entry is the base ordinal and a
// number no export answers is a zero there. The layout below is one section's
// bytes: the directory first, then the three tables, then the strings they point
// at, with every address inside stated as base plus an offset in these bytes.

// Export is one name the image offers, the address it stands for, and the
// ordinal it answers to.
pub struct Export {
pub:
	name string
	// rva is where the exported thing lies in the image, already an RVA.
	rva int
	// ordinal is the 1-based number the export answers to. Zero asks the
	// table to assign the next free one.
	ordinal int
}

// ExportTable is the export directory and every table it points at, laid out to
// be placed as one section's bytes, and the length of the directory record
// itself, which is what the optional header states for the export directory.
pub struct ExportTable {
pub:
	data []u8
	size int
}

// The IMAGE_EXPORT_DIRECTORY record is forty bytes and every field it holds is
// four bytes or smaller.
const export_directory_size = 40

// The largest ordinal the format's sixteen-bit ordinal table can name.
const export_max_ordinal = 0xffff

// resolved is one export after its ordinal is known: the name it is found by,
// the address it stands for, and the number it answers to. The table is built
// from these rather than from the caller's list, because a zero ordinal becomes
// a real one here and the name table has to be in name order.
struct ResolvedExport {
mut:
	name    string
	rva     int
	ordinal int
}

// export_table lays out the export directory for one DLL name and the exports
// given, at the base address the section will be placed at. Every address in
// the bytes is that base plus an offset into them. The directory's own Base
// field is the smallest ordinal the table answers: an image whose first export
// is number 2 states 2 there, and the address table starts at that entry. The
// bytes are deterministic: the caller's order is kept for ordinal assignment,
// names are sorted for the name pointer table, and the strings follow the
// sorted names.
pub fn export_table(dll_name string, exports []Export, base int) !ExportTable {
	if dll_name == '' {
		return error('an export table names no DLL')
	}
	mut seen := map[string]bool{}
	mut used := map[int]bool{}
	mut resolved := []ResolvedExport{cap: exports.len}
	mut last := 0
	for i, export in exports {
		if export.name == '' {
			return error('export ${i} has no name, and the export table answers names')
		}
		if export.name in seen {
			return error('the name ${export.name} is exported more than once')
		}
		seen[export.name] = true
		if export.rva < 0 {
			return error('${export.name} lies at ${export.rva}, which is not an RVA')
		}
		if export.ordinal < 0 {
			return error('${export.name} asks for the ordinal ${export.ordinal}, and an ordinal is not negative')
		}
		if export.ordinal > export_max_ordinal {
			return error('${export.name} asks for the ordinal ${export.ordinal}, which is above the ${export_max_ordinal} an ordinal table holds')
		}
		if export.ordinal > 0 {
			if export.ordinal in used {
				return error('the ordinal ${export.ordinal} is asked for by more than one export')
			}
			used[export.ordinal] = true
			if export.ordinal > last {
				last = export.ordinal
			}
		}
		resolved << ResolvedExport{
			name:    export.name
			rva:     export.rva
			ordinal: export.ordinal
		}
	}
	// The exports that asked for no ordinal take the numbers after the highest
	// one that was stated, in the order they were given.
	mut next := last + 1
	for i in 0 .. resolved.len {
		if resolved[i].ordinal != 0 {
			continue
		}
		if next > export_max_ordinal {
			return error('${resolved[i].name} has no ordinal left to take: the table reaches ${export_max_ordinal}')
		}
		resolved[i].ordinal = next
		next++
	}
	// The address table runs from the smallest ordinal to the last one, so a
	// stated ordinal far above the others costs a zero entry for every number
	// between. lld states the smallest ordinal as the directory's base too.
	if next - 1 > last {
		last = next - 1
	}
	mut ordinal_base := 1
	if resolved.len > 0 {
		ordinal_base = resolved[0].ordinal
		for entry in resolved {
			if entry.ordinal < ordinal_base {
				ordinal_base = entry.ordinal
			}
		}
	}
	functions := last - ordinal_base + 1
	mut sorted := resolved.clone()
	sorted.sort(a.name < b.name)
	eat_offset := export_directory_size
	names_offset := eat_offset + 4 * functions
	ordinals_offset := names_offset + 4 * sorted.len
	name_offset := ordinals_offset + 2 * sorted.len
	mut string_offset := name_offset
	mut name_offsets := []int{cap: sorted.len}
	dll_offset := string_offset
	string_offset += dll_name.len + 1
	for entry in sorted {
		name_offsets << string_offset
		string_offset += entry.name.len + 1
	}
	mut data := []u8{len: string_offset}
	put_u32(mut data, 0, 0) // Characteristics, reserved
	put_u32(mut data, 4, 0) // TimeDateStamp: a stamp would make two links differ
	put_u16(mut data, 8, 0) // MajorVersion
	put_u16(mut data, 10, 0) // MinorVersion
	put_u32(mut data, 12, u32(base + dll_offset))
	put_u32(mut data, 16, u32(ordinal_base))
	put_u32(mut data, 20, u32(functions))
	put_u32(mut data, 24, u32(sorted.len))
	put_u32(mut data, 28, u32(base + eat_offset))
	put_u32(mut data, 32, u32(base + names_offset))
	put_u32(mut data, 36, u32(base + ordinals_offset))
	for entry in resolved {
		put_u32(mut data, eat_offset + (entry.ordinal - ordinal_base) * 4, u32(entry.rva))
	}
	for i, entry in sorted {
		put_u32(mut data, names_offset + i * 4, u32(base + name_offsets[i]))
		put_u16(mut data, ordinals_offset + i * 2, u16(entry.ordinal - ordinal_base))
		put(mut data, name_offsets[i], entry.name.bytes())
	}
	put(mut data, dll_offset, dll_name.bytes())
	return ExportTable{
		data: data
		size: export_directory_size
	}
}
