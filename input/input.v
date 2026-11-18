module input

import archive
import library
import object
import os
import target
import unit

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
	// path of their own.
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

// read opens every path and answers the units the merge takes and the shared
// objects the image has to name.
//
// An archive is swept for the members that answer a name nothing in the link
// defines yet, and swept again while a sweep pulled something, because a member
// brings imports of its own and the next member may be what answers them. The
// sweep is per archive and in the order the paths were given: a name an earlier
// archive opens is answered by a later one and not the other way round, which is
// what a command line's own `-l` names mean.
pub fn read(paths []string, machine target.Target) !Read {
	mut out := Read{}
	mut provided := map[string]bool{}
	mut needed := map[string]bool{}
	for path in paths {
		bytes := os.read_bytes(path) or { return error('${path}: ${err.msg()}') }
		match classify(bytes, path)! {
			.object {
				part := object.read(bytes, machine) or { return error('${path}: ${err.msg()}') }
				note(mut provided, mut needed, part)
				out.units << part
			}
			.archive {
				parts := archive.read(bytes) or { return error('${path}: ${err.msg()}') }
				members := pull(parts, path, machine, mut needed, mut provided)!
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
	return out
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
fn pull(parts archive.Archive, path string, machine target.Target, mut needed map[string]bool, mut provided map[string]bool) ![]unit.Program {
	mut out := []unit.Program{}
	mut pulled := map[int]bool{}
	mut again := true
	for again {
		again = false
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
			part := object.read(member.bytes, machine) or {
				return error('${path}: ${member.name}: ${err.msg()}')
			}
			note(mut provided, mut needed, part)
			out << part
			again = true
		}
	}
	return out
}
