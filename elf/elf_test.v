module elf

import vanadiume.vlk.target
import vanadiume.vlk.unit
import os

// exit_sequence and exit_sequence_from are the two programs a test runs to see
// that the container wrote something the kernel starts. The bytes are x86-64
// Linux's exit call: the status into edi, the number 60 into eax, then the trap.
// They are written here rather than asked of the library, because a linker has no
// business carrying an assembler and what is under test is the image.
fn exit_sequence(code u8) ![]u8 {
	return [u8(0xbf), code, u8(0), u8(0), u8(0), u8(0xb8), u8(60), u8(0), u8(0), u8(0), u8(0x0f),
		u8(0x05)]
}

fn exit_sequence_from(held target.Register) ![]u8 {
	return [u8(0x89), u8(0xc0 | ((held.code & 0x07) << 3) | 0x07), u8(0xb8), u8(60), u8(0), u8(0),
		u8(0), u8(0x0f), u8(0x05)]
}

// The three output kinds are checked the same way the dynamic program is: a
// Program built by hand and read back through the headers, because the questions
// worth pinning are about a header, a symbol and a relocation that the emitter's
// whole output cannot show, and about a program the kernel can actually start.
// V compiles each `_test.v` file on its own, so the byte readers here are
// defined again under names this file owns rather than shared with the others.

fn se16(bytes []u8, at int) u16 {
	return u16(bytes[at]) | (u16(bytes[at + 1]) << 8)
}

fn se32(bytes []u8, at int) u32 {
	mut value := u32(0)
	for shift in [0, 8, 16, 24] {
		value |= u32(bytes[at + shift / 8]) << shift
	}
	return value
}

fn se64(bytes []u8, at int) u64 {
	mut value := u64(0)
	for shift in [0, 8, 16, 24, 32, 40, 48, 56] {
		value |= u64(bytes[at + shift / 8]) << shift
	}
	return value
}

fn se_target() target.Target {
	return target.host() or { panic('the elf tests need the host target') }
}

// se_phdr_at is where one program header begins: after the ELF header, with the
// entry size the header gives.
fn se_phdr_at(bytes []u8, index int) int {
	return int(se64(bytes, 32)) + index * int(se16(bytes, 54))
}

// se_dynamic_offset and se_dynamic_size reach the PT_DYNAMIC segment through the
// program header table, which is the only map a program has.
fn se_dynamic_offset(bytes []u8) int {
	for i in 0 .. int(se16(bytes, 56)) {
		at := se_phdr_at(bytes, i)
		if se32(bytes, at) == elf_ph_type_dynamic {
			return int(se64(bytes, at + 8))
		}
	}
	return 0
}

fn se_dynamic_size(bytes []u8) int {
	for i in 0 .. int(se16(bytes, 56)) {
		at := se_phdr_at(bytes, i)
		if se32(bytes, at) == elf_ph_type_dynamic {
			return int(se64(bytes, at + 32))
		}
	}
	return 0
}

fn se_has_interp(bytes []u8) bool {
	for i in 0 .. int(se16(bytes, 56)) {
		if se32(bytes, se_phdr_at(bytes, i)) == elf_ph_type_interp {
			return true
		}
	}
	return false
}

fn se_needed_count(bytes []u8) int {
	offset := se_dynamic_offset(bytes)
	mut count := 0
	for i in 0 .. se_dynamic_size(bytes) / elf_dynamic_entry_size {
		if se64(bytes, offset + i * elf_dynamic_entry_size) == dt_needed {
			count++
		}
	}
	return count
}

// SeTables is where the loader's tables are in the image, as file offsets. A
// shared object's dynamic addresses are file offsets already, so the base it is
// read with is zero.
struct SeTables {
mut:
	strtab int
	symtab int
	hash   int
	rela   int
	relasz int
}

fn se_tables(bytes []u8, base u64) SeTables {
	offset := se_dynamic_offset(bytes)
	mut tables := SeTables{}
	for i in 0 .. se_dynamic_size(bytes) / elf_dynamic_entry_size {
		tag := se64(bytes, offset + i * elf_dynamic_entry_size)
		value := se64(bytes, offset + i * elf_dynamic_entry_size + 8)
		match tag {
			dt_hash { tables.hash = int(value - base) }
			dt_strtab { tables.strtab = int(value - base) }
			dt_symtab { tables.symtab = int(value - base) }
			dt_rela { tables.rela = int(value - base) }
			dt_relasz { tables.relasz = int(value) }
			else {}
		}
	}
	return tables
}

fn se_name(bytes []u8, at int) string {
	mut end := at
	for bytes[end] != u8(0) {
		end++
	}
	return bytes[at..end].bytestr()
}

struct SeSymbol {
	index int
	info  u8
	value u64
	size  u64
	name  string
}

// se_symbol_of finds a dynamic symbol by name. There is no section header to say
// how many entries the table has, so the count comes from the hash table's chain
// length, which is the number of symbols in the table.
fn se_symbol_of(bytes []u8, tables SeTables, name string) SeSymbol {
	count := int(se32(bytes, tables.hash + 4))
	for i in 1 .. count {
		at := tables.symtab + i * elf_symbol_size
		here := se_name(bytes, tables.strtab + int(se32(bytes, at)))
		if here == name {
			return SeSymbol{
				index: i
				info:  bytes[at + 4]
				value: se64(bytes, at + 8)
				size:  se64(bytes, at + 16)
				name:  here
			}
		}
	}
	return SeSymbol{}
}

struct SeRelocation {
	offset u64
	info   u64
	addend i64
}

fn se_relative_relocation(bytes []u8, tables SeTables) SeRelocation {
	for i in 0 .. tables.relasz / elf_relocation_size {
		at := tables.rela + i * elf_relocation_size
		info := se64(bytes, at + 8)
		if info & 0xffffffff == relocation_relative {
			return SeRelocation{
				offset: se64(bytes, at)
				info:   info
				addend: i64(se64(bytes, at + 16))
			}
		}
	}
	return SeRelocation{}
}

// A static program is one the kernel starts with no loader: no interpreter
// header, no library named, and every address settled here. The stub the import
// is reached through is laid out the same way as a dynamic program's, and the
// program has to run: the exit status is the one the code was asked for.
fn test_a_static_program_is_an_exec_with_no_interpreter_and_no_library() {
	machine := se_target()
	code := exit_sequence(7) or { panic('the machine has no exit sequence: ${err.msg()}') }
	mut program := unit.Program{}
	program.text = code
	program.imports << 'entry'
	program.bound['entry'] = unit.Definition{
		offset:   0
		function: true
	}
	program.plts << 'entry'
	bytes := write(program, machine, .static_program) or {
		panic('the static program was not written: ${err.msg()}')
	}
	assert se16(bytes, 16) == elf_type_exec
	assert !se_has_interp(bytes)
	assert se_needed_count(bytes) == 0
	path := os.join_path(os.temp_dir(), 'vcc_elf_static_${os.getpid()}')
	os.write_file_array(path, bytes) or { panic(err) }
	os.chmod(path, 0o755) or { panic(err) }
	result := os.execute(os.quoted_path(path))
	os.rm(path) or {}
	assert result.exit_code == 7
}

// A static link resolves its libraries into the file it writes. A name still
// left to a library is one this link cannot place, and the diagnostic has to
// name it rather than write a file that would start with the name's address
// zero.
fn test_a_static_program_left_to_a_library_is_refused() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 8, init: u8(0x90)}
	program.imports << 'puts'
	write(program, machine, .static_program) or {
		assert err.msg().contains('puts')
		return
	}
	assert false, 'a static program was written with puts left to a library'
}

// A shared object is a file another program loads: the header says ET_DYN, there
// is no interpreter and no entry point, and the names this image defines are
// exported in the dynamic symbol table, each at the file offset of its
// definition. An import whose definition is inside the image has its slot filled
// with the offset and an R_X86_64_RELATIVE entry beside it, because where the
// object goes is the loader's to choose. Both are pinned here: the slot holds the
// same offset the relocation's addend carries.
fn test_a_shared_object_is_dynamic_and_exports_what_it_defines() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0)}
	program.text[4] = u8(0xab)
	program.defined['exported_fn'] = true
	program.labels['exported_fn'] = 4
	program.globals_blob = []u8{len: 8, init: u8(0)}
	program.globals['exported_obj'] = unit.GlobalSlot{
		offset: 0
		width:  4
		count:  2
	}
	program.imports << 'bound_fn'
	program.bound['bound_fn'] = unit.Definition{
		offset:   4
		function: true
	}
	bytes := write(program, machine, .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	assert se16(bytes, 16) == elf_type_dyn
	assert !se_has_interp(bytes)
	assert se64(bytes, 24) == 0 // no entry point
	tables := se_tables(bytes, 0)
	// The function is exported as a function, and its value is the file offset
	// the label named: the byte there is the one the text holds at offset four.
	exported := se_symbol_of(bytes, tables, 'exported_fn')
	assert exported.name == 'exported_fn'
	assert exported.info & 0xf == 0x2
	assert bytes[int(exported.value)] == u8(0xab)
	// The object is exported as an object, and its size is its whole storage:
	// two four-byte elements.
	object := se_symbol_of(bytes, tables, 'exported_obj')
	assert object.name == 'exported_obj'
	assert object.info & 0xf == 0x1
	assert object.size == 8
	// The bound import's slot is an address that points into the image, so it is
	// an offset beside a relocation that adds the load base, and the offset is
	// the definition's: the same place the exported function's label named.
	relative := se_relative_relocation(bytes, tables)
	assert relative.info & 0xffffffff == relocation_relative
	assert relative.addend == i64(exported.value)
	assert se64(bytes, int(relative.offset)) == u64(relative.addend)
}

// A name the program asked to hide with `visibility("hidden")` is one this image
// defines and its own references reach, and not one a loader finds: it is absent
// from the dynamic symbol table while the plain definition beside it is there.
// The image still calls it, which is a reference the emitter settles inside the
// image and none of this table's business.
fn test_a_hidden_definition_is_not_exported_by_a_shared_object() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0)}
	program.defined['pub_fn'] = true
	program.labels['pub_fn'] = 0
	program.defined['hidden_fn'] = true
	program.labels['hidden_fn'] = 4
	program.hidden['hidden_fn'] = true
	bytes := write(program, machine, .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	tables := se_tables(bytes, 0)
	exported := se_symbol_of(bytes, tables, 'pub_fn')
	assert exported.name == 'pub_fn'
	assert bytes[int(exported.value)] == u8(0)
	// The hidden name is nowhere in the table, so the reader finds no entry for
	// it rather than an entry with the wrong binding.
	assert se_symbol_of(bytes, tables, 'hidden_fn').name == ''
}

// A copy relocation asks a loader to copy a library's object into this image's
// storage, which is a non-position-independent executable's shape and not a
// shared object's. The refusal names the object.
fn test_a_shared_object_that_would_copy_a_library_object_is_refused() {
	machine := se_target()
	mut program := unit.Program{}
	program.globals_blob = []u8{len: 8, init: u8(0)}
	program.globals['stdout'] = unit.GlobalSlot{
		offset: 0
		width:  8
	}
	program.copy_objects << 'stdout'
	write(program, machine, .shared) or {
		assert err.msg().contains('stdout')
		return
	}
	assert false, 'a shared object was written with a copy relocation'
}

// The same Program has to write the same bytes every run, and the two symbol
// sets a shared object exports are maps, whose order is not the program's. The
// exports are sorted, so the index of `a` is below the index of `b` however the
// maps were built, and the two writes are compared byte for byte.
fn test_a_shared_object_is_the_same_every_run() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 8, init: u8(0x90)}
	program.string_blob = []u8{len: 8, init: u8(0)}
	program.strings['s'] = 0
	program.globals_blob = []u8{len: 16, init: u8(0)}
	program.globals['a'] = unit.GlobalSlot{
		offset: 0
		width:  8
	}
	program.globals['b'] = unit.GlobalSlot{
		offset: 8
		width:  8
	}
	program.data_fixups << unit.DataFixup{
		offset: 0
		kind:   .take_address
		name:   's'
	}
	first := write(program, machine, .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	second := write(program, machine, .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	assert first == second
	tables := se_tables(first, 0)
	assert se_symbol_of(first, tables, 'a').index < se_symbol_of(first, tables, 'b').index
}

// se_phdr_of is where the program header of a kind begins, or -1 when the image
// has none. A program has no section header table, so the program header table
// is the only map of its parts.
fn se_phdr_of(bytes []u8, kind u32) int {
	for i in 0 .. int(se16(bytes, 56)) {
		at := se_phdr_at(bytes, i)
		if se32(bytes, at) == kind {
			return at
		}
	}
	return -1
}

// se_phdr_count is how many headers of one kind the image carries, which is what
// says whether a promise is stated once or twice.
fn se_phdr_count(bytes []u8, kind u32) int {
	mut count := 0
	for i in 0 .. int(se16(bytes, 56)) {
		if se32(bytes, se_phdr_at(bytes, i)) == kind {
			count++
		}
	}
	return count
}

// se_dynamic_has says whether the dynamic table names a tag at all, which is
// how a test tells an entry that is absent from one whose value is zero.
fn se_dynamic_has(bytes []u8, tag u64) bool {
	offset := se_dynamic_offset(bytes)
	for i in 0 .. se_dynamic_size(bytes) / elf_dynamic_entry_size {
		if se64(bytes, offset + i * elf_dynamic_entry_size) == tag {
			return true
		}
	}
	return false
}

// se_dynamic_value is the value of the entry a tag names, and none when the
// table has no such entry.
fn se_dynamic_value(bytes []u8, tag u64) ?u64 {
	offset := se_dynamic_offset(bytes)
	for i in 0 .. se_dynamic_size(bytes) / elf_dynamic_entry_size {
		if se64(bytes, offset + i * elf_dynamic_entry_size) == tag {
			return se64(bytes, offset + i * elf_dynamic_entry_size + 8)
		}
	}
	return none
}

// se_relocation_of finds the first entry of a kind in the table the dynamic
// segment names, and se_relocation_count_of says how many there are.
fn se_relocation_of(bytes []u8, tables SeTables, kind u64) SeRelocation {
	for i in 0 .. tables.relasz / elf_relocation_size {
		at := tables.rela + i * elf_relocation_size
		info := se64(bytes, at + 8)
		if info & 0xffffffff == kind {
			return SeRelocation{
				offset: se64(bytes, at)
				info:   info
				addend: i64(se64(bytes, at + 16))
			}
		}
	}
	return SeRelocation{}
}

fn se_relocation_count_of(bytes []u8, tables SeTables, kind u64) int {
	mut count := 0
	for i in 0 .. tables.relasz / elf_relocation_size {
		if se64(bytes, tables.rela + i * elf_relocation_size + 8) & 0xffffffff == kind {
			count++
		}
	}
	return count
}

// A wide reference is an eight-byte field and all eight bytes are written: the
// distance is a 64-bit one, so a value whose upper half is not zero reaches the
// field instead of being cut to its low thirty-two bits the way a narrow field
// is. The addend here is 2^32, which is what puts a bit in the upper half.
fn test_a_wide_direct_reference_fills_eight_bytes() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 32, init: u8(0)}
	program.labels['machine'] = 24
	program.relocations << unit.Relocation{
		offset: 4
		kind:   .direct
		name:   'machine'
		addend: int(i64(1) << 32)
		width:  .wide
	}
	bytes := write(program, machine, .static_program) or {
		panic('the static program was not written: ${err.msg()}')
	}
	// A static program is not shared, so its entry point is the load base plus
	// the text offset, which is all that reaches the code of a program with no
	// section headers.
	text := int(se64(bytes, 24)) - int(machine.load_base)
	assert se64(bytes, text + 4) == u64(0x1_0000_0014) // (text + 24) + 2^32 - (text + 4)
	assert se32(bytes, text + 4) == u32(0x14) // the low half of the same number
	assert se32(bytes, text + 8) == u32(1) // and the high half, which a narrow field drops
}

// A tpoff reference is measured from the thread pointer, which sits at the end
// of the block rounded up to its alignment, so the value is the name's place in
// the block minus that rounded size. A block of twenty bytes aligned to sixteen
// rounds to thirty-two, and a name at four is twenty-eight below the pointer.
fn test_a_tpoff_reference_is_measured_from_the_end_of_the_rounded_block() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 8, init: u8(0)}
	program.tls_blob = []u8{len: 20, init: u8(0)}
	program.tls_size = 20
	program.tls_alignment = 16
	program.tls_labels['x'] = 4
	program.relocations << unit.Relocation{
		offset: 0
		kind:   .tpoff
		name:   'x'
		width:  .narrow
	}
	bytes := write(program, machine, .static_program) or {
		panic('the static program was not written: ${err.msg()}')
	}
	text := int(se64(bytes, 24)) - int(machine.load_base)
	// roundup(20, 16) is 32, and 4 - 32 is -28.
	assert i32(se32(bytes, text)) == -28
}

// A thread-local block turns into a PT_TLS header, and it is a header of its own
// for every kind: it adds one to the four a dynamic program has, the three a
// shared object has, and the two a static program has. The header names where
// the initialization image was placed, the bytes to copy out of it, and the
// block's rounded size and alignment, which is what the runtime reads.
fn test_a_thread_local_block_writes_a_pt_tls_header() {
	machine := se_target()
	mut program := unit.Program{}
	program.tls_blob = []u8{len: 12, init: u8(0)}
	program.tls_size = 12
	program.tls_alignment = 8
	bytes := write(program, machine, .static_program) or {
		panic('the static program was not written: ${err.msg()}')
	}
	assert se16(bytes, 56) == 3 // the load, the stack, and the block
	at := se_phdr_of(bytes, elf_ph_type_tls)
	assert at >= 0
	assert se32(bytes, at + 4) == elf_ph_flags_read
	// The one PT_LOAD maps the whole file at the load base, so a virtual address
	// is the base plus the file offset and p_vaddr has to agree with p_offset.
	assert se64(bytes, at + 16) == machine.load_base + se64(bytes, at + 8)
	assert se64(bytes, at + 32) == 12 // p_filesz: the initialization image
	assert se64(bytes, at + 40) == 16 // p_memsz: roundup(12, 8)
	assert se64(bytes, at + 48) == 8 // p_align
	// The same block adds one to the other two kinds' header counts.
	dynamic := write(program, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	assert se16(dynamic, 56) == 5
	shared := write(program, machine, .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	assert se16(shared, 56) == 4
}

// A program with no thread-local storage writes no PT_TLS header, and its header
// count is the one the kind always has: the block's header is not carried when
// there is no block.
fn test_a_program_without_thread_local_storage_writes_no_pt_tls_header() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 8, init: u8(0)}
	bytes := write(program, machine, .static_program) or {
		panic('the static program was not written: ${err.msg()}')
	}
	assert se16(bytes, 56) == 2
	assert se_phdr_of(bytes, elf_ph_type_tls) == -1
}

// A constructor table is named in the dynamic table by its address and its size,
// eight bytes per entry. The two tables lie in the writable data at the offsets
// the program gave, so their addresses differ by sixteen when the init table is
// at eight and the fini table at twenty-four. A program with no table names
// neither, and a static program writes no dynamic table to name one in.
fn test_a_constructor_table_is_named_in_the_dynamic_table() {
	machine := se_target()
	mut program := unit.Program{}
	program.globals_blob = []u8{len: 32, init: u8(0)}
	program.init_array = unit.ConstructorTable{
		offset: 8
		count:  2
	}
	program.fini_array = unit.ConstructorTable{
		offset: 24
		count:  1
	}
	bytes := write(program, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	init := se_dynamic_value(bytes, dt_init_array) or { panic('no DT_INIT_ARRAY') }
	fini := se_dynamic_value(bytes, dt_fini_array) or { panic('no DT_FINI_ARRAY') }
	assert se_dynamic_value(bytes, dt_init_arraysz) or { panic('no DT_INIT_ARRAYSZ') } == 16
	assert se_dynamic_value(bytes, dt_fini_arraysz) or { panic('no DT_FINI_ARRAYSZ') } == 8
	assert fini - init == 16
	// The address is one the loader maps, inside the image the file became.
	assert init >= machine.load_base
	assert init < machine.load_base + u64(bytes.len)
	// A program with no constructor table names none of the four entries.
	plain := write(unit.Program{}, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	assert !se_dynamic_has(plain, dt_init_array)
	assert !se_dynamic_has(plain, dt_fini_array)
	// And a static program writes no dynamic table at all for them to live in.
	static_bytes := write(program, machine, .static_program) or {
		panic('the static program was not written: ${err.msg()}')
	}
	assert se_dynamic_offset(static_bytes) == 0
}

// A name whose definition is a resolver has its slot filled by asking the
// resolver, not by the loader copying an address, so the slot gets an
// R_X86_64_IRELATIVE entry: the entry names the slot, names no symbol, and its
// addend is the resolver's own address, which the loader calls. The slot holds
// that address too, which is what a bound name's slot always holds, and a bound
// name that is not an ifunc gets no such entry.
fn test_an_ifunc_name_gets_an_irelative_entry_for_its_slot() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.imports << 'memcpy'
	program.bound['memcpy'] = unit.Definition{
		offset:   4
		function: true
	}
	program.ifuncs['memcpy'] = true
	program.imports << 'plain'
	program.bound['plain'] = unit.Definition{
		offset:   0
		function: true
	}
	bytes := write(program, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	tables := se_tables(bytes, machine.load_base)
	assert se_relocation_count_of(bytes, tables, relocation_irelative) == 1
	entry := se_relocation_of(bytes, tables, relocation_irelative)
	// The resolver is the definition: the code's start, which the entry point
	// names, plus the definition's offset.
	resolver := se64(bytes, 24) + 4
	assert entry.addend == i64(resolver)
	// The entry names the slot, and the slot already holds the resolver so the
	// loader has an address to call before it writes the answer over it.
	assert se64(bytes, int(entry.offset - machine.load_base)) == resolver
}

// The tpoff the container writes has to agree with the runtime that places the
// thread pointer, and the way to know it does is to run a program that reads a
// thread-local and stops with what it read. The code moves one byte out of
// fs:[tpoff] and exits with it; the value comes out of the block the runtime
// copied from the image, so a wrong offset reads a byte of something else.
fn test_a_thread_local_reads_its_initial_value_through_the_pointer() {
	machine := se_target()
	held := machine.reg('eax') or { panic('no eax register') }
	mut program := unit.Program{}
	// movzx eax, byte ptr fs:[disp32]: the fs prefix and the instruction, then
	// the four bytes of the field a tpoff reference fills in at offset five.
	program.text = [u8(0x64), 0x0f, 0xb6, 0x04, 0x25, 0, 0, 0, 0]
	exit := exit_sequence_from(held) or { panic('no exit sequence: ${err.msg()}') }
	program.text << exit
	program.tls_blob = [u8(42)]
	program.tls_size = 1
	program.tls_alignment = 1
	program.tls_labels['x'] = 0
	program.relocations << unit.Relocation{
		offset: 5
		kind:   .tpoff
		name:   'x'
		width:  .narrow
	}
	bytes := write(program, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	path := os.join_path(os.temp_dir(), 'vcc_elf_tls_${os.getpid()}')
	os.write_file_array(path, bytes) or { panic(err) }
	os.chmod(path, 0o755) or { panic(err) }
	result := os.execute(os.quoted_path(path))
	os.rm(path) or {}
	assert result.exit_code == 42
}

// An image with function bodies carries the unwind table and the header that
// indexes it, and PT_GNU_EH_FRAME names the header so an unwinder reaches the
// table without scanning. Two bodies make the shape visible: the table is one
// CIE, one FDE per body and a zero record that ends it, and the header's search
// table is sorted by the address each body covers and points at the FDE that
// describes it. The bodies are handed out of address order so the sort is
// exercised, and the FDE measures to its body from its own field while the
// search table measures from the header's start, which is the datarel encoding
// gcc writes.
fn test_function_bodies_write_an_unwind_table_the_header_indexes() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 64, init: u8(0x90)}
	program.function_runs << unit.CodeRun{
		base: 32
		len:  16
	}
	program.function_runs << unit.CodeRun{
		base: 0
		len:  8
	}
	bytes := write(program, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	at := se_phdr_of(bytes, elf_ph_type_gnu_eh_frame)
	assert at >= 0
	assert se32(bytes, at + 4) == elf_ph_flags_read
	// The one segment maps the whole file, so a virtual address is the base
	// plus the file offset, and the block is the fixed header and two entries.
	assert se64(bytes, at + 16) == machine.load_base + se64(bytes, at + 8)
	assert se64(bytes, at + 32) == 12 + 2 * 8
	assert se64(bytes, at + 48) == 4
	hdr := int(se64(bytes, at + 8))
	// The version and the three encodings are gcc's, and the table address is
	// a distance from the field itself to `.eh_frame`.
	assert bytes[hdr] == u8(1)
	assert bytes[hdr + 1] == u8(0x1b)
	assert bytes[hdr + 2] == u8(0x03)
	assert bytes[hdr + 3] == u8(0x3b)
	assert se32(bytes, hdr + 8) == 2
	eh_frame := hdr + 4 + int(i32(se32(bytes, hdr + 4)))
	text := int(se64(bytes, 24)) - int(machine.load_base)
	// The CIE is the table's first entry; the two FDEs follow it in address
	// order, the body at zero before the one at thirty-two.
	assert se32(bytes, eh_frame) == 20
	first_fde := eh_frame + 24
	second_fde := first_fde + 20
	assert se32(bytes, first_fde) == 16
	// The search table's first entry is the body that begins lowest, and it
	// names the FDE that describes it.
	assert hdr + int(i32(se32(bytes, hdr + 12))) == text
	assert hdr + int(i32(se32(bytes, hdr + 16))) == first_fde
	assert first_fde + 8 + int(i32(se32(bytes, first_fde + 8))) == text
	assert se32(bytes, first_fde + 12) == 8
	assert hdr + int(i32(se32(bytes, hdr + 20))) == text + 32
	assert second_fde + 8 + int(i32(se32(bytes, second_fde + 8))) == text + 32
	assert se32(bytes, second_fde + 12) == 16
}

// The entry a weak import gets says both things about it, and the two are separate
// questions: the type nibble says the name stands for an object, which is what the
// declaration says, and the binding says a loader does not have to find it, which
// is why the slot it is reached through is allowed to stay at zero. A reader of the
// table that took the object for a function would be reading a claim this compiler
// knows to be wrong, and the object writer already says object for the same
// declaration in a relocatable file.
fn test_an_imported_weak_object_says_object_and_weak_in_the_table() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = [u8(0x90)]
	program.imports << 'slot'
	program.object_imports['slot'] = true
	program.weak_imports['slot'] = true
	bytes := write(program, machine, .program) or {
		panic('the program was not written: ${err.msg()}')
	}
	tables := se_tables(bytes, machine.load_base)
	symbol := se_symbol_of(bytes, tables, 'slot')
	assert symbol.name == 'slot'
	assert symbol.info == symbol_weak_object
	// An imported function is still a function, so the type is read per name and
	// not from the binding.
	mut callable := unit.Program{}
	callable.text = [u8(0x90)]
	callable.imports << 'slot'
	callable.weak_imports['slot'] = true
	callable_bytes := write(callable, machine, .program) or {
		panic('the program was not written: ${err.msg()}')
	}
	callable_tables := se_tables(callable_bytes, machine.load_base)
	callable_symbol := se_symbol_of(callable_bytes, callable_tables, 'slot')
	assert callable_symbol.info == symbol_weak_function
}

// An image with no function body writes no table and no header, and its header
// count is the one the kind always had: the unwind table's header is not carried
// when there is nothing to index.
fn test_an_image_with_no_function_body_writes_no_unwind_header() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 8, init: u8(0x90)}
	bytes := write(program, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	assert se16(bytes, 56) == 4
	assert se_phdr_of(bytes, elf_ph_type_gnu_eh_frame) == -1
}

// An undefined weak symbol stands for the address zero (ELF), and a name no unit
// of the link defines is the one a reference to it names. The runtime's own
// crtbegin.o is where a link meets the shape: `mov $0, %eax` loads the address of
// `_ITM_deregisterTMCloneTable`, the `test %rax, %rax` under it skips the call
// when the address is zero, and the field the move holds is an absolute
// reference, a four-byte address rather than a distance. Ubuntu's crtbegin.o
// carries that reference as R_X86_64_32, and the Arch one carries the same hook
// as R_X86_64_REX_GOTPCRELX, which a slot answers; the absolute form is the one
// that reached the resolver with nothing to answer it, and the image base in the
// field's place would have the code jump to the base instead of skipping.
//
// The program is that shape in miniature. The exit status says which of the two
// arms the test reached: 7 when the loaded address is zero, 1 when it is not.
fn se_weak_absolute_program(machine target.Target, weak bool) unit.Program {
	zero := exit_sequence(7) or { panic('the machine has no exit sequence: ${err.msg()}') }
	other := exit_sequence(1) or { panic('the machine has no exit sequence: ${err.msg()}') }
	mut program := unit.Program{}
	// mov $hook, %eax: the four bytes the address is written into are the field
	// the relocation fills, one byte past the opcode.
	program.text = [u8(0xb8), 0, 0, 0, 0]
	program.text << u8(0x48) // test %rax, %rax
	program.text << u8(0x85)
	program.text << u8(0xc0)
	program.text << u8(0x75) // jne past the exit the zero reaches
	program.text << u8(zero.len)
	program.text << zero
	program.text << other
	program.imports << 'hook'
	if weak {
		program.weak_imports['hook'] = true
	}
	program.relocations << unit.Relocation{
		offset: 1
		kind:   .absolute
		name:   'hook'
	}
	return program
}

fn test_an_absolute_reference_to_an_undefined_weak_symbol_holds_the_zero() {
	machine := se_target()
	program := se_weak_absolute_program(machine, true)
	bytes := write(program, machine, .program) or {
		panic('the program was not written: ${err.msg()}')
	}
	text := int(se64(bytes, 24)) - int(machine.load_base)
	assert se32(bytes, text + 1) == 0
	path := os.join_path(os.temp_dir(), 'vcc_elf_weak_${os.getpid()}')
	os.write_file_array(path, bytes) or { panic(err) }
	os.chmod(path, 0o755) or { panic(err) }
	result := os.execute(os.quoted_path(path))
	os.rm(path) or {}
	assert result.exit_code == 7
}

// The zero is the undefined weak symbol's and not every undefined name's: the
// same reference to a name no unit defines and nothing marks weak is what a link
// has to refuse, because a field holding the base with the caller's own comment
// saying otherwise is worse than no file at all.
fn test_an_absolute_reference_to_an_undefined_name_is_still_refused() {
	machine := se_target()
	program := se_weak_absolute_program(machine, false)
	write(program, machine, .program) or {
		assert err.msg().contains('hook')
		return
	}
	assert false, 'a program was written with an absolute reference to a name no part defines'
}

// se_stack_flags reads the permission field out of the PT_GNU_STACK header.
fn se_stack_flags(bytes []u8) u32 {
	at := se_phdr_of(bytes, elf_ph_type_gnu_stack)
	assert at >= 0
	return se32(bytes, at + 4)
}

// -Wl,-z,execstack marks the stack executable and -Wl,-z,noexecstack takes the
// permission away again, even from a unit that said it runs code out of its
// frame. The header is the whole effect, so the permission is read out of it.
fn test_the_execstack_options_set_the_stack_permission() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 8}
	plain := write_options(program, machine, .static_program, Options{}) or {
		panic('the static program was not written: ${err.msg()}')
	}
	assert se_stack_flags(plain) == elf_ph_flags_read | elf_ph_flags_write
	exec := write_options(program, machine, .static_program, Options{
		execstack: true
	}) or { panic('the static program was not written: ${err.msg()}') }
	assert se_stack_flags(exec) == elf_ph_flags_read | elf_ph_flags_write | elf_ph_flags_execute
	// A unit whose code takes a nested function's address asks for an
	// executable stack itself; -Wl,-z,noexecstack overrides that request, which
	// is what asking a linker for a non-executable stack means.
	program.executable_stack = true
	needed := write_options(program, machine, .static_program, Options{}) or {
		panic('the static program was not written: ${err.msg()}')
	}
	assert se_stack_flags(needed) & elf_ph_flags_execute != 0
	noexec := write_options(program, machine, .static_program, Options{
		noexecstack: true
	}) or { panic('the static program was not written: ${err.msg()}') }
	assert se_stack_flags(noexec) & elf_ph_flags_execute == 0
}

// -Wl,-z,now writes both spellings of the promise into the dynamic table, and
// the table the PT_DYNAMIC header reports grows by the two entries rather than
// running past its own end.
fn test_the_bind_now_option_writes_the_dynamic_flags() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 8}
	plain := write(program, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	assert !se_dynamic_has(plain, dt_flags)
	assert !se_dynamic_has(plain, dt_flags_1)
	bound := write_options(program, machine, .program, Options{
		bind_now: true
	}) or { panic('the dynamic program was not written: ${err.msg()}') }
	assert se_dynamic_value(bound, dt_flags) or { panic('no DT_FLAGS') } == df_bind_now
	assert se_dynamic_value(bound, dt_flags_1) or { panic('no DT_FLAGS_1') } == df_1_now
	assert se_dynamic_size(bound) == se_dynamic_size(plain) + 2 * elf_dynamic_entry_size
}

// se_string_at reads a null-terminated string out of the file, which is how the
// table's name entries are read back.
fn se_string_at(bytes []u8, at int) string {
	mut out := []u8{}
	mut i := at
	for i < bytes.len && bytes[i] != 0 {
		out << bytes[i]
		i++
	}
	return out.bytestr()
}

// -Wl,-soname names the shared object, and the name is written into the string
// table with a DT_SONAME entry pointing at it. That entry is what a program
// linked against the object records as its DT_NEEDED, so it is what lets a
// program name `libvcc.so` and run against `libvcc.so.0`. A link that names no
// name records none, which is what ld writes: an object with no DT_SONAME is
// known to its loader by the name of the file it opened.
fn test_the_soname_option_names_the_shared_object() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 8}
	bytes := write_options(program, machine, .shared, Options{
		soname: 'libt.so.0'
	}) or { panic('the shared object was not written: ${err.msg()}') }
	offset := se_dynamic_value(bytes, dt_soname) or { panic('no DT_SONAME entry') }
	tables := se_tables(bytes, 0)
	assert se_string_at(bytes, tables.strtab + int(offset)) == 'libt.so.0'
	// The entry costs one record in the table the header reports the size of,
	// so a table written without the extra slot would run past its own end.
	plain := write_options(program, machine, .shared, Options{}) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	assert !se_dynamic_has(plain, dt_soname)
	assert se_dynamic_size(bytes) == se_dynamic_size(plain) + elf_dynamic_entry_size
	// A program is never looked up by name, so the option writes nothing into
	// one even when it was given.
	run := write_options(program, machine, .program, Options{
		soname: 'libt.so.0'
	}) or { panic('the program was not written: ${err.msg()}') }
	assert !se_dynamic_has(run, dt_soname)
}

// -Wl,-z,relro writes a PT_GNU_RELRO segment over the table the loader fills in,
// the relocations it applies and the dynamic table it reads. The start is page
// aligned because the loader rounds it down before mprotect: a start inside a
// page holding the program's own writable data would make that data read-only.
// The program has to run with the range in place, which is what proves the
// loader's writes landed before the protection did.
fn test_the_relro_option_writes_a_segment_over_the_loader_tables() {
	machine := se_target()
	code := exit_sequence(7) or { panic('no exit sequence: ${err.msg()}') }
	mut program := unit.Program{}
	program.text = code
	program.imports << 'exit'
	bytes := write_options(program, machine, .program, Options{
		relro: true
	}) or { panic('the dynamic program was not written: ${err.msg()}') }
	at := se_phdr_of(bytes, elf_ph_type_gnu_relro)
	assert at >= 0
	start := se64(bytes, at + 8)
	size := se64(bytes, at + 32)
	assert se64(bytes, at + 16) == machine.load_base + start
	assert se64(bytes, at + 24) == machine.load_base + start
	assert size > 0
	assert start % machine.page_size == 0
	dynamic := u64(se_dynamic_offset(bytes))
	assert start <= dynamic
	assert start + size >= dynamic + u64(se_dynamic_size(bytes))
	// Without the option there is no segment and one header fewer.
	plain := write(program, machine, .program) or {
		panic('the dynamic program was not written: ${err.msg()}')
	}
	assert se_phdr_of(plain, elf_ph_type_gnu_relro) == -1
	assert se16(bytes, 56) == se16(plain, 56) + 1
	path := os.join_path(os.temp_dir(), 'vcc_elf_relro_${os.getpid()}')
	os.write_file_array(path, bytes) or { panic(err) }
	os.chmod(path, 0o755) or { panic(err) }
	result := os.execute(os.quoted_path(path))
	os.rm(path) or {}
	assert result.exit_code == 7
}

// A position-independent executable is the shared object's container with a
// program's entry point: ET_DYN, an interpreter, a real entry, and DF_1_PIE among
// the flags. The entry names a file offset inside the code rather than the start
// of the file, and every address the dynamic table carries is an offset for the
// same reason: where the image goes is the kernel's to choose, so the link cannot
// add a base to anything.
fn test_a_pie_is_a_dynamic_image_with_an_entry_point() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.text[0] = u8(0x48)
	program.defined['main'] = true
	program.labels['main'] = 0
	bytes := write(program, machine, .pie) or {
		panic('the pie was not written: ${err.msg()}')
	}
	assert se16(bytes, 16) == elf_type_dyn
	assert se_has_interp(bytes)
	assert se_phdr_of(bytes, elf_ph_type_dynamic) >= 0
	// PT_PHDR tells the loader where the table it just read was mapped: the
	// entries are offsets, so the address of the table is not one of them. Its
	// size is the whole table, which is the one thing a loader reads from it.
	phdr := se_phdr_of(bytes, elf_ph_type_phdr)
	assert phdr >= 0
	assert se64(bytes, phdr + 8) == u64(elf_header_size)
	assert se64(bytes, phdr + 32) == u64(se16(bytes, 56)) * u64(elf_program_header_size)
	entry := se64(bytes, 24)
	assert entry != 0
	assert entry < u64(bytes.len)
	// The byte the entry names is the first instruction, so the header points at
	// the code and not at the ELF header the image opens with.
	assert bytes[int(entry)] == u8(0x48)
	// It names a library to run against, the way a dynamic program does.
	assert se_needed_count(bytes) > 0
	// DF_1_PIE says the file is a program and not a library, and it is the only
	// flag in the table until -Wl,-z,now asks for the other.
	assert se_dynamic_value(bytes, dt_flags_1) or { panic('no DT_FLAGS_1') } == df_1_pie
	assert !se_dynamic_has(bytes, dt_flags)
	// Nothing loads it beside itself, so it exports nothing: a definition it
	// holds is not a name in its dynamic table.
	tables := se_tables(bytes, 0)
	assert se_symbol_of(bytes, tables, 'main').name == ''
	// Its tables are at file offsets, not at a load base.
	assert (se_dynamic_value(bytes, dt_strtab) or { panic('no DT_STRTAB') }) < u64(bytes.len)
	// -Wl,-z,now adds DT_FLAGS and shares the one DT_FLAGS_1 entry with DF_1_PIE,
	// so the table grows by one record and not two.
	now := write_options(program, machine, .pie, Options{
		bind_now: true
	}) or { panic('the pie was not written: ${err.msg()}') }
	assert se_dynamic_value(now, dt_flags) or { panic('no DT_FLAGS') } == df_bind_now
	assert se_dynamic_value(now, dt_flags_1) or { panic('no DT_FLAGS_1') } == (df_1_now |
		df_1_pie)
	assert se_dynamic_size(now) == se_dynamic_size(bytes) + elf_dynamic_entry_size
}

// pie_sequence is a position-independent program in two parts: code that reads a
// function's address out of the global offset table and calls it, and that
// function, which stops the process with a status. `lea rax, [rip + 0]` is the
// reference to the slot, `mov rax, [rax]` reads the address the loader wrote
// there, and `call rax` reaches the code. The four zero bytes of the
// displacement are the fixup's to fill.
fn pie_sequence(code u8) ![]u8 {
	mut text := [u8(0x48), u8(0x8d), u8(0x05), u8(0), u8(0), u8(0), u8(0), u8(0x48), u8(0x8b),
		u8(0x00), u8(0xff), u8(0xd0)]
	text << exit_sequence(code)!
	return text
}

// The image has to run, which is the only answer to whether the loader put it
// where the code expects. A slot holding an address inside the image is written
// as an offset beside an R_X86_64_RELATIVE entry; a link that skipped the entry
// would leave the raw offset in the slot, and the call would jump into the first
// page of the address space and die instead of exiting. Both the bytes and the
// exit status are checked, so a failure says whether the table or the load is
// wrong.
fn test_a_pie_runs_where_its_loader_puts_it() {
	machine := se_target()
	code := pie_sequence(42) or { panic('the sequence was not built: ${err.msg()}') }
	mut program := unit.Program{}
	program.text = code
	program.entry_place = 0
	program.labels['target'] = 12
	program.imports << 'target'
	program.bound['target'] = unit.Definition{
		offset:   12
		function: true
	}
	program.fixups << unit.Fixup{
		start:    0
		length:   7
		kind:     .got_address
		name:     'target'
		register: 'rax'
	}
	bytes := write(program, machine, .pie) or {
		panic('the pie was not written: ${err.msg()}')
	}
	tables := se_tables(bytes, 0)
	relative := se_relative_relocation(bytes, tables)
	assert relative.info & 0xffffffff == relocation_relative
	// The entry is the first instruction, so the target, twelve bytes into the
	// code, is the entry plus twelve.
	assert relative.addend == i64(se64(bytes, 24) + 12)
	assert se64(bytes, int(relative.offset)) == u64(relative.addend)
	path := os.join_path(os.temp_dir(), 'vlk_elf_pie_${os.getpid()}')
	os.write_file_array(path, bytes) or { panic(err) }
	os.chmod(path, 0o755) or { panic(err) }
	result := os.exec([path])
	os.rm(path) or {}
	assert result.exit_code == 42
}

// -Wl,-z,relro over a pie covers the table the loader fills in, the relocations it
// applies and the dynamic table it reads, which is the range a program's segment
// covers, and the start is page aligned for the same reason: the loader rounds it
// down before it calls mprotect, and a start inside a page the image's own data
// lives in would make that data read-only. The range is checked against the slot
// the bound name's relative entry fills as well as against the dynamic table, and
// the image is run, which is what proves the loader wrote the slot before the
// protection went up.
fn test_a_pie_writes_a_relro_segment_over_its_loader_tables() {
	machine := se_target()
	code := pie_sequence(42) or { panic('the sequence was not built: ${err.msg()}') }
	mut program := unit.Program{}
	program.text = code
	program.entry_place = 0
	program.labels['target'] = 12
	program.imports << 'target'
	program.bound['target'] = unit.Definition{
		offset:   12
		function: true
	}
	program.fixups << unit.Fixup{
		start:    0
		length:   7
		kind:     .got_address
		name:     'target'
		register: 'rax'
	}
	bytes := write_options(program, machine, .pie, Options{
		relro: true
	}) or { panic('the pie was not written: ${err.msg()}') }
	// One segment: a second header over the same range would be two statements of
	// one promise.
	assert se_phdr_count(bytes, elf_ph_type_gnu_relro) == 1
	at := se_phdr_of(bytes, elf_ph_type_gnu_relro)
	start := se64(bytes, at + 8)
	size := se64(bytes, at + 32)
	assert size > 0
	assert start % machine.page_size == 0
	// The image's base is zero, so the address the header names is the offset.
	assert se64(bytes, at + 16) == start
	assert se64(bytes, at + 24) == start
	// The range covers the slot the loader fills and the table it reads.
	tables := se_tables(bytes, 0)
	slot := se_relative_relocation(bytes, tables).offset
	assert slot >= start
	assert slot + 8 <= start + size
	dynamic := u64(se_dynamic_offset(bytes))
	assert start <= dynamic
	assert start + size >= dynamic + u64(se_dynamic_size(bytes))
	// Without the option there is no segment and one header fewer.
	plain := write(program, machine, .pie) or {
		panic('the pie was not written: ${err.msg()}')
	}
	assert se_phdr_count(plain, elf_ph_type_gnu_relro) == 0
	assert se16(bytes, 56) == se16(plain, 56) + 1
	path := os.join_path(os.temp_dir(), 'vlk_elf_pie_relro_${os.getpid()}')
	os.write_file_array(path, bytes) or { panic(err) }
	os.chmod(path, 0o755) or { panic(err) }
	result := os.exec([path])
	os.rm(path) or {}
	assert result.exit_code == 42
}

// A copy relocation asks a loader to copy a library's object into this image's
// storage, which is the shape of an image whose addresses the link settles
// itself. A position-independent executable has no such storage to name, so the
// refusal says so and names the object.
fn test_a_pie_that_would_copy_a_library_object_is_refused() {
	machine := se_target()
	mut program := unit.Program{}
	program.globals_blob = []u8{len: 8, init: u8(0)}
	program.globals['stdout'] = unit.GlobalSlot{
		offset: 0
		width:  8
	}
	program.copy_objects << 'stdout'
	write(program, machine, .pie) or {
		assert err.msg().contains('stdout')
		assert err.msg().contains('position-independent')
		return
	}
	assert false, 'a pie was written with a copy relocation'
}

// A field that holds a name's absolute address is settled for an image a loader
// places by writing the offset and a relative entry beside it: the loader adds the
// base it mapped the image at. The field here is in the code, so the image is a
// text relocation, and DT_FLAGS says so. The target is four bytes in rather than
// at the start, so an addend of zero and an addend of the target are different
// numbers.
fn test_a_pie_writes_a_relative_entry_for_an_absolute_field_in_its_code() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.text[4] = u8(0xab)
	program.defined['target'] = true
	program.labels['target'] = 4
	program.relocations << unit.Relocation{
		offset: 8
		kind:   .absolute
		name:   'target'
		width:  .wide
	}
	bytes := write(program, machine, .pie) or {
		panic('the pie was not written: ${err.msg()}')
	}
	entry := se64(bytes, 24)
	tables := se_tables(bytes, 0)
	relative := se_relative_relocation(bytes, tables)
	assert relative.info & 0xffffffff == relocation_relative
	// The entry names the field, at the eighth byte of the code, and its addend
	// is the target's place in the image, which is what the bytes hold.
	assert relative.offset == entry + 8
	assert relative.addend == i64(entry + 4)
	assert se64(bytes, int(relative.offset)) == u64(relative.addend)
	assert bytes[int(relative.addend)] == u8(0xab)
	// The loader writes into the text while it relocates, so DT_FLAGS says so,
	// and the pie's own flag is still the only DT_FLAGS_1 record.
	assert se_dynamic_value(bytes, dt_flags) or { panic('no DT_FLAGS') } == df_textrel
	assert se_dynamic_value(bytes, dt_flags_1) or { panic('no DT_FLAGS_1') } == df_1_pie
	// DT_FLAGS is one record, which the table's size has to have made room for.
	mut plain := unit.Program{}
	plain.text = []u8{len: 16, init: u8(0x90)}
	plain.defined['target'] = true
	plain.labels['target'] = 4
	without := write(plain, machine, .pie) or {
		panic('the pie was not written: ${err.msg()}')
	}
	assert se_dynamic_size(bytes) == se_dynamic_size(without) + elf_dynamic_entry_size
	assert !se_dynamic_has(without, dt_flags)
}

// The same field in the writable data is not a text relocation, because the loader
// writes there anyway. The entry still names the field, and the addend is still
// the target's place in the image.
fn test_a_pie_writes_a_relative_entry_for_an_absolute_field_in_its_data() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.text[4] = u8(0xab)
	program.globals_blob = []u8{len: 8, init: u8(0)}
	program.defined['target'] = true
	program.labels['target'] = 4
	program.relocations << unit.Relocation{
		offset: 0
		place:  .data
		kind:   .absolute
		name:   'target'
		width:  .wide
	}
	bytes := write(program, machine, .pie) or {
		panic('the pie was not written: ${err.msg()}')
	}
	entry := se64(bytes, 24)
	tables := se_tables(bytes, 0)
	relative := se_relative_relocation(bytes, tables)
	assert relative.info & 0xffffffff == relocation_relative
	// The field is in the writable data, which is placed after the code, and it
	// holds the offset the entry adds the base to.
	assert relative.offset > entry + 16
	assert relative.addend == i64(entry + 4)
	assert se64(bytes, int(relative.offset)) == u64(relative.addend)
	// One entry and no more: the table has room for exactly the field.
	assert tables.relasz == elf_relocation_size
	// Nothing is written into the code, so there is no textrel bit.
	assert !se_dynamic_has(bytes, dt_flags)
}

// The rule is the container's and not the pie's: a shared object carries the same
// field the same way. The entry's addend is the target's place in the image, and
// the bytes at the place the entry names hold that number.
fn test_a_shared_object_writes_a_relative_entry_for_an_absolute_field() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.text[4] = u8(0xab)
	program.globals_blob = []u8{len: 8, init: u8(0)}
	program.defined['target'] = true
	program.labels['target'] = 4
	program.relocations << unit.Relocation{
		offset: 0
		place:  .data
		kind:   .absolute
		name:   'target'
		width:  .wide
	}
	bytes := write(program, machine, .shared) or {
		panic('the shared object was not written: ${err.msg()}')
	}
	tables := se_tables(bytes, 0)
	relative := se_relative_relocation(bytes, tables)
	assert relative.info & 0xffffffff == relocation_relative
	assert relative.addend != 0
	assert bytes[int(relative.addend)] == u8(0xab)
	assert se64(bytes, int(relative.offset)) == u64(relative.addend)
	assert tables.relasz == elf_relocation_size
	assert !se_dynamic_has(bytes, dt_flags)
}

// A four-byte absolute field cannot be carried: the relative entry writes eight
// bytes, so the field's neighbours would be written with it. The refusal names the
// reference and says what the image cannot do with it.
fn test_a_pie_refuses_a_narrow_absolute_reference() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.defined['target'] = true
	program.labels['target'] = 4
	program.relocations << unit.Relocation{
		offset: 8
		kind:   .absolute
		name:   'target'
		width:  .narrow
	}
	write(program, machine, .pie) or {
		assert err.msg().contains('target')
		assert err.msg().contains('32-bit')
		return
	}
	assert false, 'a pie was written with a four-byte absolute reference'
}

// A name nothing defines and nothing marks weak is still refused, and the refusal
// comes from the reference rather than from the count: a name a library would have
// answered has no place in the image to add a base to, so it gets no entry and the
// field cannot be written.
fn test_a_pie_refuses_an_absolute_reference_to_a_name_nothing_defines() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.imports << 'nowhere'
	program.relocations << unit.Relocation{
		offset: 8
		kind:   .absolute
		name:   'nowhere'
		width:  .wide
	}
	write(program, machine, .pie) or {
		assert err.msg().contains('nowhere')
		return
	}
	assert false, 'a pie was written with an absolute reference to a name nothing defines'
}

// The shared object carries the field the same way, so it refuses it the same way.
fn test_a_shared_object_refuses_a_narrow_absolute_reference() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.defined['target'] = true
	program.labels['target'] = 4
	program.relocations << unit.Relocation{
		offset: 8
		kind:   .absolute
		name:   'target'
		width:  .narrow
	}
	write(program, machine, .shared) or {
		assert err.msg().contains('target')
		assert err.msg().contains('32-bit')
		return
	}
	assert false, 'a shared object was written with a four-byte absolute reference'
}

// The exception to the rule above: a field that holds the address of a name
// nothing defines and the link marks weak stands for zero, and zero is the same
// number at every base. A start file writes exactly this, so it gets no relative
// entry: one would add the base to the zero and turn a skip into a jump.
fn test_a_pie_with_an_undefined_weak_absolute_reference_is_written() {
	machine := se_target()
	mut program := unit.Program{}
	program.text = []u8{len: 16, init: u8(0x90)}
	program.relocations << unit.Relocation{
		offset: 8
		kind:   .absolute
		name:   'never_defined'
		width:  .wide
	}
	program.imports << 'never_defined'
	program.weak_imports['never_defined'] = true
	bytes := write(program, machine, .pie) or {
		panic('a pie with an undefined weak absolute reference was refused: ${err.msg()}')
	}
	// The field holds the addend, which is zero, and no relocation names it.
	tables := se_tables(bytes, 0)
	assert se_relative_relocation(bytes, tables).info == 0
}
