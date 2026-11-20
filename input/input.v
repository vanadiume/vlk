module input

import vanadiume.vlk.archive
import vanadiume.vlk.coff
import vanadiume.vlk.library
import vanadiume.vlk.object
import os
import vanadiume.vlk.target
import vanadiume.vlk.unit

// What a link's inputs are, read into the shape the merge takes. A path is one of
// three files: a relocatable object, which becomes a unit; an `ar` archive, which
// is a library of units and gives up only the members that answer a name the link
// still needs; or a shared object, which is not merged at all and is recorded by
// the name the loader knows.
//
// This is the module a caller that has paths rather than units reaches, so it is
// the only one in the tree besides `object/` and `archive/` that reads files as a
// link's input.

// Kind is what a path turned out to be, decided by the file's own bytes rather
// than by its name: a linker is handed files other tools built, and a suffix is a
// convention rather than a fact.
pub enum Kind {
	object
	// coff_object is a COFF object: the file a Windows compiler writes, which
	// is read by `coff/` rather than by `object/`. The two are told apart by
	// their bytes, because a suffix is a convention rather than a fact.
	coff_object
	archive
	library
}

// Read is what a link's inputs came to.
pub struct Read {
pub mut:
	// units are the inputs in the order they were read: every object file, and
	// the archive members that were pulled, each where its archive was written.
	units []unit.Program
	// shared are the shared objects the command line named by path. No byte of
	// one is merged: the loader maps it beside the image, and what the link takes
	// from it is the names it defines and the name the loader asks for.
	shared []library.Library
	// pulled is how many of the units came out of an archive rather than from a
	// path of their own, which is a path that names an archive and a `-l` name
	// that resolved to one.
	pulled int
}

const ar_magic = '!<arch>\n'
const elf_magic = [u8(0x7f), u8(`E`), u8(`L`), u8(`F`)]
const elf_header_type_offset = 16
const et_rel = u16(1)
const et_dyn = u16(3)

// classify says what the bytes of an input are. A file that is none of the three
// is refused with its path, because a link handed something it cannot consume
// has to say so rather than leave the name out of the image.
pub fn classify(bytes []u8, path string) !Kind {
	if bytes.len >= ar_magic.len && bytes[..ar_magic.len].bytestr() == ar_magic {
		return .archive
	}
	if coff.is_object(bytes) {
		return .coff_object
	}
	if bytes.len >= elf_header_type_offset + 2 && bytes[..4] == elf_magic {
		kind := u16(bytes[elf_header_type_offset]) | (u16(bytes[elf_header_type_offset + 1]) << 8)
		return match kind {
			et_rel { .object }
			et_dyn { .library }
			else {
				return error('${path}: an ELF file that is neither a relocatable object nor a shared object')
			}
		}
	}
	return error('${path}: not a relocatable object, an archive or a shared object')
}

// Group is a run of inputs a command line wrapped in --start-group and
// --end-group. Every archive in it is swept again while a sweep pulls a member,
// so two libraries that answer each other's names both get read; outside a
// group the archives are swept once, in the order they were written, and a name
// an earlier archive opens is not answered by a later one.
//
// `paths` are the files the command line named in the group, and `libraries` are
// the `-l` names it wrote there, in either order within each list. A group holds
// archives and objects; a shared object is recorded like one outside a group,
// because the loader maps it rather than the merge.
pub struct Group {
pub:
	paths     []string
	libraries []string
}

// read opens every path and answers the units the merge takes and the shared
// objects the image has to name.
//
// An archive is swept for the members that answer a name nothing in the link
// defines yet, and swept again while a sweep pulled something, because a member
// brings imports of its own and the next member may be what answers them. The
// sweep is per archive and in the order the paths were given: a name an earlier
// archive opens is answered by a later one and not the other way round.
//
// The `-l` names come after the paths, in the order they were written. A name
// that resolves to a static archive is not a file the loader maps, so it is not
// recorded and the image asks it for nothing: what the link takes from it is the
// members that answer a name nothing defines yet, pulled by the same sweep and
// against the same two maps as a path that names an archive. A name that
// resolves to a shared object is left alone here, since `settled` records its
// soname and asks it for the names the merge leaves to the loader.
//
// A command line interleaves paths and `-l` names, and this call takes them as
// two lists, so the order the link reads is the paths and then the names. That
// is the order in which a link that has already sorted its inputs by kind reads
// them; a caller that needs the command line's own order passes the archives it
// cares about as paths.
pub fn read(paths []string, libraries []string, library_dirs []string, static_link bool, groups []Group, machine target.Target) !Read {
	mut out := Read{}
	// The COMDAT groups the link has kept, shared by every input so that the
	// first object carrying a group keeps it and the rest are discarded.
	mut comdats := map[string]bool{}
	// The library each imported name comes from, as the import libraries that
	// answered it stated. An object names no library, so this is what a short
	// import member adds to the link.
	mut import_libraries := map[string]unit.Import{}
	mut provided := map[string]bool{}
	mut needed := map[string]bool{}
	dirs := library.search_dirs(library_dirs, machine.library_dirs)
	for path in paths {
		bytes := os.read_bytes(path) or { return error('${path}: ${err.msg()}') }
		match classify(bytes, path)! {
			.object, .coff_object {
				part := read_object(bytes, machine, mut comdats) or { return error('${path}: ${err.msg()}') }
				note(mut provided, mut needed, part)
				out.units << part
			}
			.archive {
				parts := archive.read(bytes) or { return error('${path}: ${err.msg()}') }
				members := pull(parts, path, machine, mut needed, mut provided, mut comdats, mut
					import_libraries)!
				out.pulled += members.len
				out.units << members
			}
			.library {
				found := library.shared_library(path) or {
					return error('${path}: ${err.msg()}')
				}
				out.shared << found
			}
		}
	}
	// A `-l` name that resolved to a static archive is read the way a path that
	// names one is, and so is an archive a GNU ld script names beside its
	// library. The search is the one the kind asks for: a static program
	// resolves a name to the archive even when a shared object of the same name
	// stands beside it, because it carries the code it calls rather than asking
	// a loader for it, and the other way round for a dynamic one.
	//
	// What is read is `archive_libraries`, not the file each name resolved to,
	// because the two are not the same list: `/usr/lib/libc.so` is a script that
	// reads `GROUP ( libc.so.6  libc_nonshared.a )`, and `atexit` is in the
	// archive rather than in the shared object the script names first.
	// An object can ask for a library in its own directives, which is how a
	// `#pragma comment(lib, ...)` reaches a linker. The name is resolved against
	// the directories the link was given and beside the object that asked, and
	// what it finds is read the way a path on the command line is: a short import
	// member still travels as a record rather than as a unit.
	mut from_directives := []string{}
	mut asked := map[string]bool{}
	for part in out.units {
		for name in part.default_libraries {
			if name in asked {
				continue
			}
			asked[name] = true
			from_directives << default_library(name, dirs, paths) or {
				return error('${name} was asked for by an object, and no file of that name was found')
			}
		}
	}
	for path in from_directives {
		bytes := os.read_bytes(path) or { return error('${path}: ${err.msg()}') }
		parts := archive.read(bytes) or { return error('${path}: ${err.msg()}') }
		members := pull(parts, path, machine, mut needed, mut provided, mut comdats, mut
			import_libraries)!
		out.pulled += members.len
		out.units << members
	}
	if libraries.len > 0 {
		for found in library.archive_libraries(libraries, dirs, static_link)! {
			bytes := os.read_bytes(found.path) or { return error('${found.path}: ${err.msg()}') }
			parts := archive.read(bytes) or { return error('${found.path}: ${err.msg()}') }
			members := pull(parts, found.path, machine, mut needed, mut provided, mut comdats,
				mut import_libraries)!
			out.pulled += members.len
			out.units << members
		}
	}
	// A group is read after the words outside it, and every archive in it shares
	// one sweep: a member one archive gives up can open a name another archive in
	// the group answers, which is what the markers exist for. The sweeping stops
	// when a whole pass over the group pulls nothing.
	for group in groups {
		read_group(group, dirs, static_link, machine, mut needed, mut provided, mut out, mut
			comdats, mut import_libraries)!
	}
	if import_libraries.len > 0 {
		for i in 0 .. out.units.len {
			out.units[i] = stamp_imports(out.units[i], import_libraries)
		}
	}
	return out
}

// default_library finds the file a directive named. A librarian's spelling is
// `foo.lib` and a caller often writes `foo`, so both are tried, in the
// directories the link was given and then in the directory of every input. A
// name that is itself a path is taken as it stands.
fn default_library(name string, dirs []string, paths []string) !string {
	mut candidates := [name]
	if !name.ends_with('.lib') && !name.ends_with('.a') {
		candidates << '${name}.lib'
	}
	if os.exists(name) {
		return name
	}
	mut roots := dirs.clone()
	for path in paths {
		dir := os.dir(path)
		if dir != '' && dir !in roots {
			roots << dir
		}
	}
	for root in roots {
		for candidate in candidates {
			path := os.join_path(root, candidate)
			if os.exists(path) {
				return path
			}
		}
	}
	return error('no file named ${name} in the search directories')
}

// stamp_imports records the library an imported name comes from on the unit that
// needs it, because a COFF object leaves the name undefined and says nothing
// about which DLL answers it. The import library is what says so, and it says it
// in a member the unit never sees.
fn stamp_imports(part unit.Program, import_libraries map[string]unit.Import) unit.Program {
	mut program := part
	mut seen := map[string]bool{}
	for record in program.imports_by_library {
		key := if record.symbol != '' { record.symbol } else { record.name }
		seen[key] = true
	}
	mut records := program.imports_by_library.clone()
	for name in program.imports {
		record := import_libraries[name] or { continue }
		if name in seen {
			continue
		}
		seen[name] = true
		records << record
	}
	program.imports_by_library = records
	return program
}

// pending_group_archive is one archive of a group while the group is swept: the
// members already given up are remembered per archive, because a second sweep
// must not pull the same member twice.
struct PendingGroupArchive {
	parts  archive.Archive
	path   string
	pulled map[int]bool
}

// read_group reads one --start-group ... --end-group run into the same maps as
// the inputs outside it, so a name either side of the markers answers the other.
// The paths and the -l names are read first, in their own order, and then the
// archives are swept together until a pass pulls nothing.
fn read_group(group Group, dirs []string, static_link bool, machine target.Target, mut needed map[string]bool, mut provided map[string]bool, mut out Read, mut comdats map[string]bool, mut import_libraries map[string]unit.Import) ! {
	mut pending := []PendingGroupArchive{}
	for path in group.paths {
		bytes := os.read_bytes(path) or { return error('${path}: ${err.msg()}') }
		match classify(bytes, path)! {
			.object, .coff_object {
				part := read_object(bytes, machine, mut comdats) or { return error('${path}: ${err.msg()}') }
				note(mut provided, mut needed, part)
				out.units << part
			}
			.archive {
				parts := archive.read(bytes) or { return error('${path}: ${err.msg()}') }
				pending << PendingGroupArchive{
					parts:  parts
					path:   path
					pulled: map[int]bool{}
				}
			}
			.library {
				found := library.shared_library(path) or {
					return error('${path}: ${err.msg()}')
				}
				out.shared << found
			}
		}
	}
	for name in group.libraries {
		for found in library.archive_libraries([name], dirs, static_link)! {
			bytes := os.read_bytes(found.path) or { return error('${found.path}: ${err.msg()}') }
			parts := archive.read(bytes) or { return error('${found.path}: ${err.msg()}') }
			pending << PendingGroupArchive{
				parts:  parts
				path:   found.path
				pulled: map[int]bool{}
			}
		}
	}
	mut again := pending.len > 0
	for again {
		again = false
		for index in 0 .. pending.len {
			// A struct copy shares the map, and the map is what the sweep
			// remembers between passes.
			mut entry := pending[index]
			members := pull_members(entry.parts, entry.path, machine, mut entry.pulled, mut needed,
				mut provided, mut comdats, mut import_libraries)!
			if members.len > 0 {
				out.pulled += members.len
				out.units << members
				again = true
			}
		}
	}
}

// read_object reads one relocatable object, whichever container wrote it. The
// bytes decide: an ELF object begins with the ELF magic and a COFF object begins
// with its machine number, so the two cannot be mistaken for each other.
fn read_object(bytes []u8, machine target.Target, mut comdats map[string]bool) !unit.Program {
	if coff.is_object(bytes) {
		return coff.read_unit_selecting(bytes, machine, mut comdats)
	}
	return object.read(bytes, machine)
}

// note_unit records what a unit defines and what it needs, which is what decides
// whether an archive member is worth pulling.
fn note(mut provided map[string]bool, mut needed map[string]bool, part unit.Program) {
	provided_with(mut provided, part)
	for symbol in part.imports {
		if symbol !in provided && symbol !in part.weak_imports {
			needed[symbol] = true
		}
	}
}

fn provided_with(mut provided map[string]bool, part unit.Program) {
	for name, _ in part.defined {
		provided[name] = true
	}
	for name, _ in part.globals {
		if name in part.copy_objects {
			continue
		}
		provided[name] = true
	}
	for name, _ in part.tls_labels {
		provided[name] = true
	}
	for name, _ in part.read_only_globals {
		provided[name] = true
	}
}

// pull takes the members of one archive that answer a name the link still needs.
// A name no unit defines yet is the only one a member is pulled for, which is the
// rule ld follows and what keeps the C library's copy of a name the runtime's own
// crt1.o already defines out of the link: two definitions of one name are what a
// link refuses.
fn pull(parts archive.Archive, path string, machine target.Target, mut needed map[string]bool, mut provided map[string]bool, mut comdats map[string]bool, mut import_libraries map[string]unit.Import) ![]unit.Program {
	mut out := []unit.Program{}
	mut pulled := map[int]bool{}
	mut again := true
	for again {
		members := pull_members(parts, path, machine, mut pulled, mut needed, mut provided, mut
			comdats, mut import_libraries)!
		if members.len == 0 {
			again = false
		} else {
			out << members
		}
	}
	return out
}

// pull_members is one sweep of an archive: every member whose name the link still
// needs and whose index has not been given up yet. The caller decides whether to
// sweep the archive again, which is what `pull` does for one archive and what a
// group does for all of its archives together.
fn pull_members(parts archive.Archive, path string, machine target.Target, mut pulled map[int]bool, mut needed map[string]bool, mut provided map[string]bool, mut comdats map[string]bool, mut import_libraries map[string]unit.Import) ![]unit.Program {
	mut out := []unit.Program{}
	mut names := parts.index.keys()
	names.sort()
	for name in names {
		if !needed[name] || provided[name] {
			continue
		}
		index := parts.index[name]
		if index in pulled {
			continue
		}
		pulled[index] = true
		member := parts.members[index]
		// A short import member is not an object: it is the archive saying
		// which DLL answers one name. It defines nothing in the image, so what
		// the link takes from it is the record and not a unit.
		if coff.is_import_member(member.bytes) {
			record := coff.read_import_member(member.bytes) or {
				return error('${path}: ${member.name}: ${err.msg()}')
			}
			spelling := record.name
			// The member says what the DLL calls the name when that differs
			// from the symbol it defines. An older member leaves it out, and
			// the `__imp_` prefix is then the only thing saying which of the
			// two names the DLL exports.
			exported := if record.exported != '' {
				record.exported
			} else if spelling.starts_with('__imp_') {
				spelling.all_after('__imp_')
			} else {
				spelling
			}
			import_libraries[spelling] = unit.Import{
				name:       exported
				library:    record.library
				symbol:     if spelling == exported { '' } else { spelling }
				// A member that names an export number keeps it in the same
				// field a name member keeps its hint in.
				hint:       if record.by_ordinal { u16(0) } else { record.hint }
				ordinal:    if record.by_ordinal { record.hint } else { u16(0) }
				by_ordinal: record.by_ordinal
			}
			provided[spelling] = true
			continue
		}
		part := read_object(member.bytes, machine, mut comdats) or {
			return error('${path}: ${member.name}: ${err.msg()}')
		}
		note(mut provided, mut needed, part)
		out << part
	}
	return out
}
