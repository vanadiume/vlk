module pe

import vanadiume.vlk.unit

// The import directory: what a PE image says it needs from the DLLs the loader
// maps beside it. An ELF image names its libraries once and the loader searches
// them for every name; a PE image names a DLL for every group of names, and each
// name becomes an entry in two parallel arrays, one the loader reads and one it
// writes the resolved address into.
//
// The plan is made before the section's address is known and written after, so
// every number inside the section is an offset here and an address there. That
// is the only reason the two passes exist.

// ImportPlan is the .idata section's shape: the DLLs, the offsets of their
// tables inside the section, and where each name's slot will be.
struct ImportPlan {
mut:
	dlls []DllPlan
	// slots is where each imported name's address is written, as an offset
	// into the section. A reference to an import is a reference to its slot.
	slots map[string]int
	size  int
}

// DllPlan is one DLL's part of the section: its name, the names it answers, and
// where its lookup table, its address table and its strings lie.
struct DllPlan {
mut:
	name    string
	entries []ImportEntry
	// lookup is the table the loader reads the names from, as offsets into
	// the section: eight bytes per entry and a zero terminator.
	lookup int
	// addresses is the table the loader writes resolved addresses into. It
	// holds the same values as the lookup table before the image is mapped.
	addresses   int
	name_offset int
	hint_offset []int
}

// ImportEntry is one name a DLL answers, with the hint the object stated.
struct ImportEntry {
	name string
	// symbol is the spelling this link's references use for the import, when
	// an import library defined it under another name, and empty when the two
	// are the same.
	symbol     string
	hint       u16
	by_ordinal bool
	ordinal    u16
}

// plan_imports groups the program's imports by the DLL each came from and lays
// out the tables the section holds. A name the link itself defines is not an
// import: `program.bound` is the merge's answer that one of the link's own units
// defines it, and an entry for it would ask the loader for an address that is
// already here.
fn plan_imports(program unit.Program) !ImportPlan {
	mut records := map[string]unit.Import{}
	// A unit's needed names may be spelled either way: an object that saw
	// `dllimport` needs `__imp_foo`, and one that did not needs `foo`, while the
	// import library's record is keyed by the spelling its member defined. The
	// exported name is kept as a second key so either list finds the record.
	mut by_export := map[string]unit.Import{}
	for record in program.imports_by_library {
		key := if record.symbol != '' { record.symbol } else { record.name }
		if key !in records {
			records[key] = record
		}
		if record.name !in by_export {
			by_export[record.name] = record
		}
	}
	mut groups := map[string][]ImportEntry{}
	mut libraries := []string{}
	for name in program.imports {
		if name in program.bound {
			continue
		}
		record := records[name] or {
			by_export[name] or {
				return error('${name} is imported and no library is recorded for it')
			}
		}
		if record.library == '' {
			return error('${name} is imported from a library with no name')
		}
		if record.library !in groups {
			groups[record.library] = []ImportEntry{}
			libraries << record.library
		}
		mut names := groups[record.library]
		names << ImportEntry{
			name:       record.name
			symbol:     record.symbol
			hint:       record.hint
			by_ordinal: record.by_ordinal
			ordinal:    record.ordinal
		}
		groups[record.library] = names
	}
	if libraries.len == 0 {
		return ImportPlan{
			slots: map[string]int{}
		}
	}
	// The DLLs are sorted by name so that the same inputs give the same
	// bytes every run, and the names inside one keep the order the program
	// first reached for them.
	libraries.sort()
	mut dlls := []DllPlan{cap: libraries.len}
	mut size := 20 * (libraries.len + 1)
	for library in libraries {
		entries := groups[library]
		dlls << DllPlan{
			name:    library
			entries: entries
			lookup:  size
		}
		size += 8 * (entries.len + 1)
	}
	for i in 0 .. dlls.len {
		dlls[i].addresses = size
		size += 8 * (dlls[i].entries.len + 1)
	}
	for i in 0 .. dlls.len {
		mut hints := []int{cap: dlls[i].entries.len}
		for entry in dlls[i].entries {
			if entry.by_ordinal {
				hints << 0
				continue
			}
			hints << size
			size += align_up(2 + entry.name.len + 1, 2)
		}
		dlls[i].hint_offset = hints
	}
	for i in 0 .. dlls.len {
		dlls[i].name_offset = size
		size += align_up(dlls[i].name.len + 1, 2)
	}
	mut slots := map[string]int{}
	for dll in dlls {
		for i, entry in dll.entries {
			// A reference reaches the slot by the spelling the object used,
			// which is the `__imp_` one when an import library defined it.
			key := if entry.symbol != '' { entry.symbol } else { entry.name }
			slots[key] = dll.addresses + i * 8
		}
	}
	return ImportPlan{
		dlls:  dlls
		slots: slots
		size:  size
	}
}

// descriptors_size is how long the import directory table is: one twenty-byte
// record per DLL and the zero record that ends it. That is the size the optional
// header states for the directory, because it is what a reader walks.
fn (plan ImportPlan) descriptors_size() int {
	return 20 * (plan.dlls.len + 1)
}

// first_iat is where the first address table begins, which is the address the
// optional header gives the IAT directory. The tables of the DLLs that follow
// are not contiguous with it in this layout, so the size the header states is
// the sum rather than the distance.
fn (plan ImportPlan) first_iat() int {
	if plan.dlls.len == 0 {
		return 0
	}
	return plan.dlls[0].addresses
}

fn (plan ImportPlan) iat_size() int {
	mut size := 0
	for dll in plan.dlls {
		size += 8 * (dll.entries.len + 1)
	}
	return size
}

// bytes writes the import directory at the address the layout gave its section.
// Every field that names something inside the section is relative here and an
// address there, which is why the section is written after it is placed.
fn (plan ImportPlan) bytes(base int) []u8 {
	mut data := []u8{len: plan.size}
	for i, dll in plan.dlls {
		at := i * 20
		put_u32(mut data, at, u32(base + dll.lookup))
		put_u32(mut data, at + 4, 0) // the stamp of the DLL the image was bound to
		put_u32(mut data, at + 8, 0) // the forwarder chain
		put_u32(mut data, at + 12, u32(base + dll.name_offset))
		put_u32(mut data, at + 16, u32(base + dll.addresses))
		for j, entry in dll.entries {
			value := if entry.by_ordinal {
				u64(0x8000000000000000) | u64(entry.ordinal)
			} else {
				u64(base + dll.hint_offset[j])
			}
			put_u64(mut data, dll.lookup + j * 8, value)
			put_u64(mut data, dll.addresses + j * 8, value)
			if entry.by_ordinal {
				continue
			}
			put_u16(mut data, dll.hint_offset[j], entry.hint)
			put(mut data, dll.hint_offset[j] + 2, entry.name.bytes())
		}
		put(mut data, dll.name_offset, dll.name.bytes())
	}
	return data
}
