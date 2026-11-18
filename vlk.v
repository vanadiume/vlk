module vlk

import input
import library
import os
import output
import place
import reloc
import symbols
import target
import unit

// vlk is a linker library. The inputs of one link go in, the single program that
// link produces comes out, and the bytes of that program are written by `output`
// for the container the system runs.
//
// The library answers at three depths, so a caller takes as much of a link as it
// wants and no more. `link` is the whole of one, for a caller that has paths and
// wants an image back. `merge` is the same link without the library check and
// without the container, for a caller that has already settled its libraries or
// wants to write the image itself. The passes underneath, `symbols.collect`,
// `place.lay` and `reloc`, are public and take the state they read, for a caller
// that has a layout or a reference policy of its own.

// Target is the machine and the system a link is for, and the one definition of
// it is `target.Target`: this library never carries a second copy of another
// tree's target description, and a link for a second machine is a value rather
// than a branch. A caller writes `vlk.Target` and fills the fields the link
// reads, because the name a caller's code is compiled against belongs here.
pub type Target = target.Target

// Options is what a caller asks a link for. The zero value is a link of what the
// units say, with the entry the caller names and no library named by the caller.
// One struct serves all three depths: a field the depth a caller chose does not
// read is a field it does not have to fill. The fields are mutable because the
// high entries fill in what they resolved, and a caller's struct is a value it
// owns rather than one the library keeps.
pub struct Options {
pub mut:
	// entry is the name of the function the process stub calls. A link none of
	// whose units defines it is refused, and that refusal is the only thing this
	// field is used for.
	entry string
	// target is the machine and system the link is for.
	target Target
	// libraries are the `-l` names the command line gave, in order and as they
	// were written: `c` for `-lc`. Resolving one to a file is this library's
	// search, because the high entries are what read the file and the image
	// records the name the loader knows rather than the name it was asked for.
	libraries []string
	// library_dirs are the `-L` directories the command line gave, in order.
	library_dirs []string
	// shared_libraries are the shared objects the command line named as files
	// rather than through -l, in order. They are not units: no byte of one is
	// placed in the merged image. What the link takes from one is the names it
	// defines, which answer the image's imports, and the name the loader is
	// asked for, which the image records the way it records a -l name.
	shared_libraries []library.Library
	// no_default_libraries says the link names no default library: no C library
	// and no runtime archive. An import nothing in the link answers is then left
	// to the loader instead of being refused.
	no_default_libraries bool
	// output is the path the image is written to, for the high entries. Empty
	// means the caller wants the bytes and no file.
	output string
	// kind is which of the container's three shapes the image takes: a dynamic
	// program, a static program, or a shared object.
	kind output.Kind
	// container is what the caller asks the container for beyond the kind: an
	// executable stack, eager binding, a read-only relocation segment, a soname.
	container output.Options
}

// Merged is one merge's answer: the single program the units became, and the
// names that program needs a library to answer.
//
// The two travel together because they are decided together. A caller that reads
// only the program gets a link that looks finished and is not: nothing has asked
// whether the loader can find `printf`. `required` is that question, in the order
// the references named the names, and it is what `link` asks the libraries.
pub struct Merged {
pub:
	program unit.Program
	// required is every name the image leaves to the loader and none of its own
	// units answers: the imports that stayed unbound, and the storage copied out
	// of a library. A weak import is not one, because an undefined weak symbol
	// stands for zero.
	required []string
}

// merge is one link without the last two steps: the names, the layout and the
// references, answering with the merged program and the names a library has to
// answer. It reads no file and asks no library, so a caller that knows its
// libraries already can stop here, and `link` is this plus the check and the
// container.
pub fn merge(units []unit.Program, options Options) !Merged {
	if units.len == 0 {
		return error('a link has no units')
	}
	// The names come first: their resolution is what decides which unit's
	// storage an object binds to and which references are bound at all.
	names := symbols.collect(units)!
	// A shared object has no entry: nothing starts it, so there is no name to
	// resolve here and no diagnostic to make about one. An empty entry is how
	// the caller says that, and the container writes an entry point of zero for
	// that kind of link.
	if options.entry != '' {
		entry := names.definitions[options.entry] or {
			return error('no definition of ${options.entry} in any part of the link')
		}
		if !entry.function {
			return error('the entry ${options.entry} names an object and not a function')
		}
	}
	layout := place.lay(units, names.globals_alignment, names.read_only_alignment)
	read_only := merge_read_only(units, layout)
	tls := merge_tls(units, layout)
	ifuncs := merge_ifuncs(units)
	// bound is the truth a reference is answered from: the names whose definition
	// is inside this image. It is built before the copy list is filtered, because
	// a name both lists carry is one the filtering has to drop from the copies.
	mut bound := bind(units, layout, names)!
	// Each constructor table has two ends the C library's own startup reaches
	// for by name rather than by being told where the table is: `__libc_csu_init`
	// walks `__init_array_start` to `__init_array_end` and the same for the
	// fini table. The linker is what knows where the tables landed, so it is
	// what answers for the four names, and only for the ones something in the
	// link actually named.
	mut arrays := map[string]int{}
	arrays['__init_array_start'] = layout.constructor_base
	arrays['__init_array_end'] = layout.constructor_base + layout.init_len
	arrays['__fini_array_start'] = layout.constructor_base + layout.init_len
	arrays['__fini_array_end'] = layout.constructor_base + layout.init_len + layout.fini_len
	// The preinit table is a third one, and it is empty: a preinit function runs
	// before the one that starts the program, which is a place this compiler
	// generates no code for and no unit of a link can put one in. Both ends name
	// the same place, so a startup that walks them between the two finds
	// nothing, which is the answer an image with no preinit table gives.
	arrays['__preinit_array_start'] = layout.constructor_base
	arrays['__preinit_array_end'] = layout.constructor_base
	for name, offset in arrays {
		if name in names.imports {
			bound[name] = unit.Definition{
				offset: offset
			}
		}
	}
	// More names the runtime's own startup reaches for are the link's to answer,
	// because they are about the image rather than about a symbol in it:
	// `__ehdr_start` is where the image begins, which is what a program reads to
	// find its own program headers.
	//
	// The rest bound the writable data. `__data_start` and its alias `data_start`
	// name its first byte and `_end` its last, and those are the ends the Boehm
	// collector registers as the program's data roots. The region between
	// `__bss_start` and `_end` is the storage that has no bytes in the file, and
	// this image has none: every zero it holds is written into the file, so the
	// region is empty and both ends and `_edata` name the same place. Answering
	// the bounds with the start of the writable data would have the C library
	// zero the initializers it just loaded.
	//
	// Each is answered from the layout, and only the ones something in the link
	// actually named.
	mut data_bounds := map[string]int{}
	data_bounds['__data_start'] = 0
	data_bounds['data_start'] = 0
	data_bounds['_edata'] = layout.globals_len
	data_bounds['__bss_start'] = layout.globals_len
	data_bounds['_end'] = layout.globals_len
	for name, offset in data_bounds {
		if name in names.imports || name in names.object_imports || name in names.copy_objects {
			bound[name] = unit.Definition{
				offset: offset
			}
		}
	}
	if '__ehdr_start' in names.imports {
		bound['__ehdr_start'] = unit.Definition{
			image_base: true
		}
	}
	// The references a unit carried as relocations are merged like its fixups,
	// and the imported functions among them need a stub: a unit read back from
	// a relocatable object reaches a library function with a direct branch, and
	// a direct branch cannot read the value a slot holds, so the container gives
	// each such name a stub and the call goes there instead.
	merged_relocations := merge_relocations(units, layout)
	mut plts := []string{}
	for relocation in merged_relocations {
		// A reference that goes through the global offset table reads the
		// table's slot, not a stub, and a direct branch to a name the link
		// defines reaches it without either.
		if relocation.kind != .direct {
			continue
		}
		if is_section_key(relocation.name) {
			continue
		}
		if relocation.name in names.definitions && relocation.name !in ifuncs {
			continue
		}
		// A name the link answers itself is not one a stub stands for either.
		// The four constructor-table ends and the image's own bounds are places
		// the linker knows and no unit defines, so a reference to one of them
		// has to read the address the container writes rather than a stub whose
		// slot nothing fills. An IFUNC is the exception it already was: it is a
		// name whose definition is a resolver, so a call still needs the slot.
		if relocation.name in bound && relocation.name !in ifuncs {
			continue
		}
		// An IFUNC is defined by a unit of this link and still needs a stub: the
		// name stands for the resolver rather than for the function, so a call
		// to it has to reach the slot the resolver's answer is written into, and
		// that is what a stub is. A reference that already goes through the
		// table is skipped above.
		if relocation.name in ifuncs && relocation.name !in plts {
			plts << relocation.name
			continue
		}
		if relocation.name in names.object_imports {
			// A direct reference to an object in a shared library would have
			// to read the object's address out of the table, which is a
			// reference this linker does not build. It is named rather than
			// pointed at a wrong address.
			return error('${relocation.name} is an object a relocatable object reaches through the global offset table, and this linker builds no such reference: -external-linker links an input this compiler cannot place yet')
		}
		if relocation.name in names.imports && relocation.name !in plts {
			plts << relocation.name
		}
	}
	mut copies := []string{cap: names.copy_objects.len}
	for name in names.copy_objects {
		// A copy object a unit defines is not a copy any more: the image holds
		// the object itself, and the loader is not asked to fill it. A name the
		// link answers from its own layout is not a copy either: there is no
		// library object to copy, and the name is bound to the place the layout
		// gave it.
		if name !in names.definitions && name !in bound {
			copies << name
		}
	}
	labels := merge_labels(units, layout, names.definitions)
	place_of_entry := entry_place_of(units, layout, labels, options.entry)
	mut merged := unit.Program{
		text:                 merge_text(units, layout)
		labels:               labels
		stub:                 has_stub(units)
		executable_stack:     merge_executable_stack(units)
		entry_place:          place_of_entry
		function_runs:        merge_function_runs(units, layout)
		string_blob:          read_only.blob
		strings:              read_only.strings
		wide_strings:         read_only.wide_strings
		doubles:              read_only.doubles
		globals_blob:         merge_globals_blob(units, layout)
		globals:              merge_globals(units, layout, names.definitions)
		read_only_globals:    merge_read_only_globals(units, layout, names.definitions)
		globals_alignment:    names.globals_alignment
		read_only_alignment:  names.read_only_alignment
		defined:              names.defined
		weak:                 names.weak
		hidden:               names.hidden
		internal:             names.internal
		imports:              names.imports
		object_imports:       names.object_imports
		weak_imports:         names.weak_imports
		tls_slots:            names.tls_slots
		libraries:            names.libraries
		copy_objects:         copies
		bound:                bound
		fixups:               merge_fixups(units, layout)
		data_fixups:          merge_data_fixups(units, layout, names.definitions)
		relocations:          merged_relocations
		plts:                 plts
		tls_blob:             tls.blob
		tls_size:             tls.size
		tls_alignment:        tls.alignment
		tls_labels:           tls.labels
		init_array:           unit.ConstructorTable{
			offset: layout.constructor_base
			count:  layout.init_len / 8
		}
		fini_array:           unit.ConstructorTable{
			offset: layout.constructor_base + layout.init_len
			count:  layout.fini_len / 8
		}
		ifuncs:               ifuncs
		// Whether the container names the C library is the link's answer, the
		// same way the libraries it names are, so it travels on the merged
		// program to whoever wraps it.
		no_default_libraries: options.no_default_libraries
	}
	// A shared object named as a file is recorded the way a -l name is: the
	// loader maps it beside this image and answers the names it defines. Its
	// bytes are not merged, because an image that held a copy of every name a
	// library exports would be a second definition of them rather than a use
	// of the first. The name is the one the library carries for the loader, not
	// the path on this command line, which is why the reader answered it when
	// the input was classified.
	for library in options.shared_libraries {
		if library.soname !in merged.libraries {
			merged.libraries << library.soname
		}
	}
	// Every reference that is still external has to be answerable by a library
	// the image names, or the program dies at load with nothing on the
	// compiler's stderr. The copies are collected beside the imports because a
	// copy is a name the loader has to find too, even though it is not an
	// import in the image. Asking which of them the libraries answer is the
	// step this function does not take: it is a file read, and the answer is
	// `required`.
	mut requested := []string{cap: names.imports.len + copies.len}
	for name in names.imports {
		// A weak import is the one name a link does not have to answer, so it
		// is not asked of any library: the check would report it and this link
		// would refuse a program that runs.
		if name !in bound && name !in names.weak_imports {
			requested << name
		}
	}
	for name in copies {
		if name !in requested {
			requested << name
		}
	}
	return Merged{
		program:  merged
		required: requested
	}
}

// link is the whole of one link from units: the merge, the check that a library
// answers every name the image leaves to the loader, and the bytes of the image.
//
// It answers with the bytes rather than writing them, so a caller that has a
// place of its own for an image keeps them. `link_files` is the same link for a
// caller that has paths.
pub fn link(units []unit.Program, options Options) ![]u8 {
	merged := merge(units, options)!
	program := settled(merged, options)!
	return output.image(program, options.target, options.kind, options.container)
}

// Report is what a link of paths came to.
pub struct Report {
pub:
	// path is the file the image was written to, empty when the caller asked
	// for no file.
	path string
	// bytes is how long the image is.
	bytes int
	// units is how many inputs the merge took, and pulled is how many of them
	// came out of an archive rather than from a path of their own.
	units  int
	pulled int
	// libraries are the names the image records as needed, in order.
	libraries []string
}

// link_files is the whole of one link from the paths of its inputs: each file is
// read as a relocatable object, an archive or a shared object, the merge runs on
// what comes out, and the image is written to `Options.output` when that names a
// file.
//
// The `-l` names the caller passed are part of the same read: a name that
// resolves to a static archive adds the members that answer a name nothing
// defines yet, after the paths and in the order the names were written, because
// two lists cannot carry the order one command line has.
//
// This is the entry for a caller that does not want to drive a linker: one call,
// paths in, an executable out. A caller that has units already, or wants the
// image bytes and no file, uses `link` or `merge` instead.
pub fn link_files(paths []string, options Options) !Report {
	read := input.read(paths, options.libraries, options.library_dirs, options.target)!
	mut opts := options
	if read.shared.len > 0 {
		mut shared := opts.shared_libraries.clone()
		shared << read.shared
		opts.shared_libraries = shared
	}
	merged := merge(read.units, opts)!
	program := settled(merged, opts)!
	bytes := output.image(program, opts.target, opts.kind, opts.container)!
	if opts.output != '' {
		os.write_file_array(opts.output, bytes) or {
			return error('${opts.output}: ${err.msg()}')
		}
		// An image something starts gets the execute bit; a shared object is
		// mapped rather than started, so it keeps the mode the write gave it.
		if opts.kind != .shared {
			info := os.stat(opts.output) or { return error('${opts.output}: ${err.msg()}') }
			if (info.mode & os.s_ifmt) == os.s_ifreg && (info.mode & os.s_ixusr) == 0 {
				os.chmod(opts.output, 0o755) or {
					return error('${opts.output}: ${err.msg()}')
				}
			}
		}
	}
	return Report{
		path:      opts.output
		bytes:     bytes.len
		units:     read.units.len
		pulled:    read.pulled
		libraries: program.libraries
	}
}

// settled is the merge's answer made ready to wrap. The names the image leaves to
// the loader are asked of the libraries the caller named, and `-l` names are
// resolved to what the loader knows so the image can record them: `-lm` is
// `libm.so.6` in the image and `/usr/lib/libm.so` on this machine, and the two
// are different strings for one library.
fn settled(merged Merged, options Options) !unit.Program {
	dirs := library.search_dirs(options.library_dirs, options.target.library_dirs)
	// A link with no default libraries names no C library in its image, so that
	// library answers nothing for its imports: a name only it defines is as
	// unresolved as any other, and the loader would fail on it.
	base := if options.no_default_libraries { '' } else { options.target.base_library }
	unresolved := library.unresolved_imports_including_files(merged.required,
		options.libraries, options.shared_libraries, dirs, base)
	if unresolved.len > 0 {
		return error('undefined reference to `${unresolved[0]}`: no library the image names defines it')
	}
	sonames := library.resolve_libraries(options.libraries, dirs,
		options.kind == .static_program)!
	mut program := merged.program
	for soname in sonames {
		if soname !in program.libraries {
			program.libraries << soname
		}
	}
	return program
}

// merge_text builds the merged text at its final length and copies each unit in
// at its base. The units are read in the order they were given and the bases are
// the layout's, so the same units produce the same bytes every run. A second
// full copy of a unit is never kept: its bytes move into this blob once.
// has_stub says whether any unit of the link opens with the process stub the
// kernel jumps to. A link of this compiler's own output has one; a link of start
// files has none, and begins at the function the link's entry names.
fn has_stub(units []unit.Program) bool {
	for part in units {
		if part.stub {
			return true
		}
	}
	return false
}

// entry_place_of is where in the merged text the process begins, which is what
// the container writes as the entry point. The unit that opens with the stub is
// the place when the link has one, since the kernel lands on the stub. A link of
// start files has no stub and begins at the function its entry names, which is
// what the merged labels hold for that name. Neither answer is the start of the
// merged text: the gathered `.init` and `.fini` runs are placed there, and the
// branch at the end of the first fragment is written to reach into the next.
fn entry_place_of(units []unit.Program, layout place.Layout, labels map[string]int, entry string) int {
	for i, part in units {
		if part.stub {
			return layout.text_bases[i]
		}
	}
	if entry == '' {
		return 0
	}
	return labels[entry] or { 0 }
}

fn merge_text(units []unit.Program, layout place.Layout) []u8 {
	mut text := []u8{len: layout.text_len}
	for i, part in units {
		fill(mut text, layout.text_bases[i], part.text)
	}
	// The gathered fragments are copied again where their runs hold them, which
	// is where every reference into one of them was moved to. The copy the unit's
	// own text still carries is unreachable and keeps the bytes it was read with,
	// so the same input still writes the same unit.
	for i, part in units {
		if part.init_run.len > 0 {
			fill(mut text, layout.init_run_bases[i], part.text[part.init_run.base..part
				.init_run.base + part.init_run.len])
		}
		if part.fini_run.len > 0 {
			fill(mut text, layout.fini_run_bases[i], part.text[part.fini_run.base..part
				.fini_run.base + part.fini_run.len])
		}
	}
	return text
}

// merge_function_runs rebases each unit's function bodies into the merged code.
// The container builds the image's unwind table from these ranges, so a merged
// program that carried none would describe no frame and a walk through it would
// stop at the function that called into it. A body's place is where the byte at
// its start lands in the merged code, which `text_place` answers: the unit's
// text base for a body, since a function body is never inside the gathered
// `.init` or `.fini` runs, but the same helper the merge's other moved ranges
// are placed with so the two cannot disagree.
fn merge_function_runs(units []unit.Program, layout place.Layout) []unit.CodeRun {
	mut count := 0
	for part in units {
		count += part.function_runs.len
	}
	mut runs := []unit.CodeRun{cap: count}
	for i, part in units {
		for run in part.function_runs {
			runs << unit.CodeRun{
				base: text_place(part, i, run.base, layout)
				len:  run.len
			}
		}
	}
	return runs
}

// text_place is where a byte of a unit's code blob lands in the merged code: the
// unit's own text, or the run the merge gathered that section into when the byte
// is inside one of the two fragments it moves.
fn text_place(part unit.Program, unit_index int, offset int, layout place.Layout) int {
	if part.init_run.len > 0 && offset >= part.init_run.base
		&& offset < part.init_run.base + part.init_run.len {
		return layout.init_run_bases[unit_index] + (offset - part.init_run.base)
	}
	if part.fini_run.len > 0 && offset >= part.fini_run.base
		&& offset < part.fini_run.base + part.fini_run.len {
		return layout.fini_run_bases[unit_index] + (offset - part.fini_run.base)
	}
	return layout.text_bases[unit_index] + offset
}

// merge_labels unions the units' labels, each moved by its unit's text base, so
// that a reference in the merged code finds the same place it named inside its
// unit. A label is public when it names a function the unit defines with
// external linkage; everything else is private to the unit, which is a `static`
// function's entry and every jump label the emitter made. The emitter numbers
// its jump labels from zero in each unit, so two units can both hold a `.L0`
// naming a different place, and a private label is keyed by its unit for that
// reason. A public key is the name itself, and it belongs to the unit the link
// resolved the name to: two units name one public function when one definition
// is weak, and a call inside either unit is a local reference to that name, so
// the table has to answer with the resolved definition rather than the first
// unit's. Every other unit's label for the name is keyed privately, where no
// reference reaches it.
fn merge_labels(units []unit.Program, layout place.Layout, definitions map[string]symbols.Definition) map[string]int {
	mut labels := map[string]int{}
	for i, part in units {
		for name, offset in part.labels {
			key := if name in part.defined && name !in part.internal {
				if definition := definitions[name] {
					if definition.part == i {
						name
					} else {
						symbols.private_key(i, name)
					}
				} else {
					name
				}
			} else {
				symbols.private_key(i, name)
			}
			if key !in labels {
				labels[key] = text_place(part, i, offset, layout)
			}
		}
	}
	return labels
}

// ReadOnly is the one read-only blob and the three tables that point into it.
// A string, a wide string, and a double all live in the same bytes and are
// looked up in their own table, which is the shape one unit already has, so the
// merge keeps the tables apart and only moves their offsets.
struct ReadOnly {
	blob         []u8
	strings      map[string]int
	wide_strings map[string]int
	doubles      map[string]int
}

// Tls is the merged thread-local block and where each name lies in it. The block
// is the image's whole thread-local storage, which is what a `tpoff` reference
// measures from its end: the storage sits below the thread pointer, so a
// thread-local's distance from it is its offset in the block minus the block's
// length.
struct Tls {
	blob      []u8
	size      int
	alignment int
	labels    map[string]int
}

// merge_tls concatenates the units' thread-local storage at its final length and
// rebases each name into it. A unit is placed at the alignment its members asked
// for, so the gaps between units stay zero, which is what a thread-local part the
// unit did not initialize is.
fn merge_tls(units []unit.Program, layout place.Layout) Tls {
	mut blob := []u8{len: layout.tls_len}
	mut labels := map[string]int{}
	for i, part in units {
		base := layout.tls_bases[i]
		fill(mut blob, base, part.tls_blob)
		for name, offset in part.tls_labels {
			key := if name in part.internal { symbols.private_key(i, name) } else { name }
			if key !in labels {
				labels[key] = offset + base
			}
		}
	}
	return Tls{
		blob:      blob
		size:      layout.tls_len
		alignment: layout.tls_alignment
		labels:    labels
	}
}

// merge_ifuncs is the union of the units' IFUNC names. The container needs the
// set so that each one's slot is filled by asking its resolver when the image
// starts rather than by copying an address, and so that a call to one goes
// through a stub.
fn merge_ifuncs(units []unit.Program) map[string]bool {
	mut ifuncs := map[string]bool{}
	for part in units {
		for name, _ in part.ifuncs {
			ifuncs[name] = true
		}
	}
	return ifuncs
}

// merge_executable_stack answers whether the merged program's stack has to be
// executable. The permission belongs to the image rather than to a unit, so one
// unit's request is the link's: dropping it would take the code that runs out of
// its frame and hand it a stack the kernel maps read-only. An input that says
// nothing contributes nothing, which is the same answer ELF gives a note that
// does not set the execute flag.
fn merge_executable_stack(units []unit.Program) bool {
	for part in units {
		if part.executable_stack {
			return true
		}
	}
	return false
}

// merge_read_only concatenates the units' read-only data at its final length and
// rebases each of the three tables into it. A table is keyed by the bytes or the
// bit pattern the entry stands for, so two units holding the same entry hold the
// same thing and the first unit's offset is as good as the second's.
fn merge_read_only(units []unit.Program, layout place.Layout) ReadOnly {
	mut blob := []u8{len: layout.string_len}
	mut strings := map[string]int{}
	mut wide_strings := map[string]int{}
	mut doubles := map[string]int{}
	// The gathered fragments are copied again at the front of the merged
	// read-only data, which is where a reference into one of them was moved to.
	for i, part in units {
		run := part.eh_frame_run
		if run.len > 0 {
			fill(mut blob, layout.eh_frame_bases[i], part.string_blob[run.base..run.base + run.len])
		}
	}
	for i, part in units {
		base := layout.string_bases[i]
		fill(mut blob, base, part.string_blob)
		for name, offset in part.strings {
			if name !in strings {
				strings[name] = offset + base
			}
		}
		for name, offset in part.wide_strings {
			if name !in wide_strings {
				wide_strings[name] = offset + base
			}
		}
		for name, offset in part.doubles {
			if name !in doubles {
				doubles[name] = offset + base
			}
		}
	}
	return ReadOnly{
		blob:         blob
		strings:      strings
		wide_strings: wide_strings
		doubles:      doubles
	}
}

// merge_globals_blob concatenates the units' writable data at its final length.
// The layout put each unit at its alignment, so the gaps between units are the
// padding that makes those alignments true, and they stay zero.
fn merge_globals_blob(units []unit.Program, layout place.Layout) []u8 {
	mut blob := []u8{len: layout.globals_len}
	for i, part in units {
		fill(mut blob, layout.globals_bases[i], part.globals_blob)
	}
	return blob
}

// merge_globals rebases each top-level object's slot into the merged writable
// data. A name one unit defines binds to that unit's slot; a name no unit
// defines is a copy of a library's object and the first unit to name it keeps
// its storage. Reading the defining unit's slot matters: a unit that only names
// an `extern` object has a slot of its own, and binding a reference to that
// storage instead of the object's is a wrong address rather than a loud failure.
// An object with internal linkage is private to its unit, so two units may each
// hold a `static` object of one name; such a slot is keyed by its unit, the same
// key symbols.collect recorded its definition under, and the definition lookup
// uses that key or it would read another unit's answer.
fn merge_globals(units []unit.Program, layout place.Layout, definitions map[string]symbols.Definition) map[string]unit.GlobalSlot {
	mut globals := map[string]unit.GlobalSlot{}
	for i, part in units {
		for name, slot in part.globals {
			key := if name in part.internal { symbols.private_key(i, name) } else { name }
			if definition := definitions[key] {
				if definition.function || definition.part != i {
					continue
				}
			} else if key in globals {
				continue
			}
			globals[key] = unit.GlobalSlot{
				offset:   slot.offset + layout.globals_bases[i]
				width:    slot.width
				count:    slot.count
				object:   slot.object
				floating: slot.floating
				single:   slot.single
				unsigned: slot.unsigned
			}
		}
	}
	return globals
}

// eh_frame_place is where an offset in a unit's read-only data lands: the place
// it moved to when it is inside the part of that data which is this unit's
// `.eh_frame` fragment, and its own unit's read-only data otherwise. The merge
// gathers the fragments into one table, so an object a unit defines inside one
// moves with it.
fn eh_frame_place(part unit.Program, offset int, read_only_base int, run_base int) int {
	fragment := part.eh_frame_run
	if fragment.base < 0 || offset < fragment.base || offset > fragment.base + fragment.len {
		return offset + read_only_base
	}
	return run_base + (offset - fragment.base)
}

// merge_read_only_globals rebases each object a unit defines in read-only data
// into the merged read-only data. The offsets count from that blob's start, not
// the writable data's, and the defining unit's slot is the one that binds: a
// `const` object is the bytes one unit wrote, and a reference to it from another
// unit has to land on them.
fn merge_read_only_globals(units []unit.Program, layout place.Layout, definitions map[string]symbols.Definition) map[string]unit.GlobalSlot {
	mut globals := map[string]unit.GlobalSlot{}
	for i, part in units {
		for name, slot in part.read_only_globals {
			key := if name in part.internal { symbols.private_key(i, name) } else { name }
			if definition := definitions[key] {
				if !definition.read_only || definition.part != i {
					continue
				}
			} else if key in globals {
				continue
			}
			globals[key] = unit.GlobalSlot{
				offset: eh_frame_place(part, slot.offset, layout.string_bases[i], layout.eh_frame_bases[i])
				width:  slot.width
			}
		}
	}
	return globals
}

// merge_fixups sizes the merged reference list once and has each unit append its
// rewritten references, so no per-unit array is built only to be copied again.
fn merge_fixups(units []unit.Program, layout place.Layout) []unit.Fixup {
	mut count := 0
	for part in units {
		count += part.fixups.len
	}
	mut fixups := []unit.Fixup{cap: count}
	for i, part in units {
		reloc.fixups(part, i, layout.text_bases[i], mut fixups)
	}
	return fixups
}

// merge_data_fixups is the same for the references in the writable data, which
// also need the definitions because a bound name changes the kind of reference
// the container writes.
fn merge_data_fixups(units []unit.Program, layout place.Layout, definitions map[string]symbols.Definition) []unit.DataFixup {
	mut count := 0
	for part in units {
		count += part.data_fixups.len
	}
	mut fixups := []unit.DataFixup{cap: count}
	for i, part in units {
		reloc.data_fixups(part, i, layout.globals_bases[i], layout.text_bases[i],
			layout.string_bases[i], definitions, mut fixups)
	}
	return fixups
}

// merge_relocations sizes the merged relocation list once and has each unit
// append its rewritten references, the way merge_fixups does for the references
// the emitter left as fixups.
fn merge_relocations(units []unit.Program, layout place.Layout) []unit.Relocation {
	mut count := 0
	for part in units {
		count += part.relocations.len
	}
	mut relocations := []unit.Relocation{cap: count}
	for i, part in units {
		reloc.relocations(part, i, layout.text_bases[i], layout.string_bases[i],
			layout.globals_bases[i], layout.tls_bases[i], layout.init_run_bases[i],
			layout.fini_run_bases[i], layout.eh_frame_bases[i], tables_of(part, layout, i), mut
			relocations)
	}
	return relocations
}

// tables_of is where one unit's two constructor tables land in the merged
// writable data, read from the layout the merge places the unit by. A unit with
// no table of a kind answers with the zero value, which the rewriter reads as
// "this field moves with the unit's own data".
fn tables_of(part unit.Program, layout place.Layout, i int) reloc.Tables {
	return reloc.Tables{
		init_base:   layout.init_bases[i]
		init_offset: part.init_array.offset
		init_count:  part.init_array.count
		fini_base:   layout.fini_bases[i]
		fini_offset: part.fini_array.offset
		fini_count:  part.fini_array.count
	}
}

// is_section_key says whether a relocation's name is one of a unit's own section
// keys rather than a symbol. Such a name points at a place in a merged blob and
// never at a symbol table entry, so it is not a name a stub or a library check
// can be asked about.
fn is_section_key(name string) bool {
	return name == unit.section_key_text || name == unit.section_key_rodata
		|| name == unit.section_key_data
}

// bind answers, for each name the image needs and one of its units defines, where
// the definition is. An import that is a definition is bound; a copy object that
// is a definition is bound too, which is why both lists are walked. The offset
// points into the merged text for a function and into the merged writable data
// for an object, which is the one place a caller can turn it back into an
// address.
fn bind(units []unit.Program, layout place.Layout, names symbols.Names) !map[string]unit.Definition {
	mut bound := map[string]unit.Definition{}
	for name in names.imports {
		if name in names.definitions {
			bound[name] = definition_at(units, layout, names.definitions[name], name)!
		}
	}
	for name in names.copy_objects {
		if name in names.definitions && name !in bound {
			bound[name] = definition_at(units, layout, names.definitions[name], name)!
		}
	}
	return bound
}

// definition_at is where one resolved definition lives in the merged program.
// A function's place is its label, which every unit records for the functions it
// defines; an object's is its slot in the unit's writable data.
fn definition_at(units []unit.Program, layout place.Layout, definition symbols.Definition, name string) !unit.Definition {
	if definition.read_only {
		slot := units[definition.part].read_only_globals[name] or {
			return error('the link binds ${name} to an object in read-only data part ${definition.part} defines and has no slot for')
		}
		return unit.Definition{
			offset: eh_frame_place(units[definition.part], slot.offset, layout.string_bases[definition.part],
				layout.eh_frame_bases[definition.part])
		}
	}
	if definition.tls {
		offset := units[definition.part].tls_labels[name] or {
			return error('the link binds ${name} to a thread-local part ${definition.part} defines and has no offset for')
		}
		return unit.Definition{
			offset: offset + layout.tls_bases[definition.part]
			tls:    true
		}
	}
	if definition.function {
		offset := units[definition.part].labels[name] or {
			return error('the link binds ${name} to a function part ${definition.part} defines and has no label for')
		}
		return unit.Definition{
			offset:   offset + layout.text_bases[definition.part]
			function: true
		}
	}
	slot := units[definition.part].globals[name] or {
		return error('the link binds ${name} to an object part ${definition.part} defines and has no storage for')
	}
	return unit.Definition{
		offset:   slot.offset + layout.globals_bases[definition.part]
		function: false
	}
}

// fill copies one unit's bytes into the merged blob at the base it was placed
// at. It is a byte loop rather than a growing array because the blob is already
// the length it will be, and appending per unit is what the layout exists to
// avoid.
fn fill(mut dst []u8, at int, src []u8) {
	for i, byte in src {
		dst[at + i] = byte
	}
}
