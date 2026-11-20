module pe

import vanadiume.vlk.target
import vanadiume.vlk.unit

// Filling the references a merge left, and the table that tells the loader
// which fields hold an address.
//
// A COFF relocation states the formula and leaves the addend in the field; a
// unit carries the same thing as a place, an offset, a kind and a name. This file
// turns the second into the first: it finds the address the name stands for, adds
// the addend, subtracts the field's own address where the kind is relative, and
// writes the number back into the bytes the section holds.
//
// Every field that ends up holding an absolute address is also a site the loader
// has to adjust when it maps the image somewhere else, so the same pass records
// those sites and hands them to the relocation table.

// The two base relocation kinds an AMD64 image uses: an eight-byte address and a
// four-byte one. The format numbers them the same way for every machine.
const base_reloc_highlow = u16(3)
const base_reloc_dir64 = u16(10)

// Site is one field of the image that holds an address the loader has to add its
// base to. The offset inside the page is what the table entry holds; the rest of
// the address is the page the entry is grouped under.
struct Site {
	rva  int
	kind u16
}

// relocate fills every reference the program carries and answers the sites the
// base relocation table has to cover.
fn relocate(mut layout Layout, program unit.Program, machine target.Target, plan ImportPlan, tls TlsInfo) ![]Site {
	mut sites := []Site{}
	for relocation in program.relocations {
		section_name := match relocation.place {
			.text { '.text' }
			.read_only { '.rdata' }
			.data { '.data' }
			.section { relocation.section }
			.tls {
				return error('a relocation lies in thread-local storage, and the PE writer places none')
			}
		}
		index := layout.index(section_name) or {
			return error('a relocation names ${section_name} and the image has no such section')
		}
		width := if relocation.width == .wide { 8 } else { 4 }
		size := layout.sections[index].virtual_size
		if relocation.offset < 0 || relocation.offset + width > size {
			return error("a relocation at ${relocation.offset} in ${section_name} does not lie inside the section's ${size} bytes")
		}
		field := layout.sections[index].rva + relocation.offset
		place := reference(program, layout, plan, tls, relocation.name)!
		value := match relocation.kind {
			.direct { i64(place) + relocation.addend - field }
			.got {
				// A PE reference through a table is a reference to the
				// import's slot, which is the address table's entry. The
				// `.got` spelling is the ELF vocabulary for the same place,
				// so it reads the slot rather than a table of its own.
				if relocation.name !in plan.slots {
					return error('${relocation.name} is reached through a table and is not an import')
				}
				idata := layout.address('.idata') or {
					return error('.idata is not a section of this image')
				}
				i64(idata + plan.slots[relocation.name]) + relocation.addend - field
			}
			.absolute {
				if relocation.name == '' {
					i64(relocation.addend)
				} else {
					i64(machine.load_base) + place + relocation.addend
				}
			}
			.rva {
				// An image-relative address: the same number `absolute`
				// writes with the image's base left out. A field of one is
				// never a base relocation site, because nothing in it changes
				// when the loader moves the image.
				i64(place) + relocation.addend
			}
			.tpoff {
				return error('a thread pointer offset reference to ${relocation.name} is left for a later version, which places thread-local storage')
			}
		}
		if width == 4 {
			// A relative field is signed and a written address is not: an
			// absolute 32-bit value runs to 4 GB-1, while a displacement only
			// has to fit a signed word.
			if relocation.kind == .absolute || relocation.kind == .rva {
				if value < 0 || value > 4294967295 {
					return error('the reference to ${relocation.name} at ${field} is ${value}, which a four-byte address does not hold')
				}
			} else if value < -2147483648 || value > 2147483647 {
				return error('the reference to ${relocation.name} at ${field} is ${value}, which a four-byte field does not hold')
			}
			put_u32(mut layout.sections[index].data, relocation.offset, u32(value & 0xffffffff))
		} else {
			put_u64_at(mut layout.sections[index].data, relocation.offset, value)
		}
		if relocation.kind == .absolute && relocation.name != '' {
			sites << Site{
				rva:  field
				kind: if width == 8 { base_reloc_dir64 } else { base_reloc_highlow }
			}
		}
	}
	return sites
}

// apply_fixups rewrites the instructions a unit's emitter left unfinished. A
// fixup is instruction-shaped: the emitter keeps the whole instruction and its
// register, and the container replaces it with one whose displacement reaches
// what the name stands for. The machine's encoders are the same ones the ELF
// container uses, because the instructions are the machine's; what differs is
// where the name stands, and that is the referent below.
fn apply_fixups(mut layout Layout, program unit.Program, machine target.Target, plan ImportPlan, tls TlsInfo) ![]Site {
	if program.fixups.len == 0 {
		return []Site{}
	}
	index := layout.index('.text') or { return error('.text is not a section of this image') }
	text := layout.sections[index].rva
	for fixup in program.fixups {
		referent := fixup_referent(program, layout, plan, tls, fixup.kind, fixup.name)!
		instruction := text + fixup.start
		disp := i32(referent - (instruction + fixup.length))
		mut replacement := []u8{}
		match fixup.kind {
			.call_local { replacement = machine.call_near(disp) }
			.call_import { replacement = machine.call_slot(disp) }
			.take_address, .take_wide_address, .global_address, .got_address, .function_address {
				register := machine.reg(fixup.register) or {
					return error('no register named ${fixup.register} to compute an address into')
				}
				replacement = machine.address_of(register, disp)
			}
			.import_address {
				register := machine.reg(fixup.register) or {
					return error('no register named ${fixup.register} to compute an address into')
				}
				replacement = machine.load_slot_value(register, disp)
			}
			.float_constant {
				register := machine.float_reg(fixup.register) or {
					return error('no floating-point register named ${fixup.register} to read a constant into')
				}
				replacement = machine.load_double_constant(register, disp)!
			}
			.single_constant {
				register := machine.float_reg(fixup.register) or {
					return error('no floating-point register named ${fixup.register} to read a constant into')
				}
				replacement = machine.load_float_constant(register, disp)!
			}
			.jump_local { replacement = machine.jump(disp) }
			.branch_zero { replacement = machine.jump_if_zero(disp) }
			.branch_nonzero { replacement = machine.jump_if_not_zero(disp) }
			.section_address {
				// The emitter names one of its own sections rather than a
				// symbol, and a section is not an instruction shape of its
				// own: a field reference to a place in a blob is written by
				// the merge's relocations, not by a fixup.
				return error('a fixup names ${fixup.name}, which is a place in a blob rather than an instruction reference')
			}
		}
		if replacement.len != fixup.length {
			return error('the reference to ${fixup.name} was ${fixup.length} bytes and became ${replacement.len}')
		}
		put(mut layout.sections[index].data, fixup.start, replacement)
	}
	return []Site{}
}

// apply_data_fixups writes the addresses a unit's writable data holds as
// initializers. Each is eight bytes, so each is a base relocation site: the
// number written is the image's base plus a place, and the loader adds the
// difference when it maps the image somewhere else. An imported address is the
// one kind left at zero, because the loader writes it into the slot rather than
// into the data.
fn apply_data_fixups(mut layout Layout, program unit.Program, machine target.Target, plan ImportPlan, tls TlsInfo) ![]Site {
	if program.data_fixups.len == 0 {
		return []Site{}
	}
	index := layout.index('.data') or {
		return error('the program holds ${program.data_fixups.len} address-valued initializers and no writable data')
	}
	data_rva := layout.sections[index].rva
	mut sites := []Site{}
	for fixup in program.data_fixups {
		if fixup.kind == .import_address {
			continue
		}
		referent := fixup_referent(program, layout, plan, tls, fixup.kind, fixup.name)!
		value := i64(machine.load_base) + i64(referent) + fixup.addend
		if fixup.offset < 0 || fixup.offset + 8 > layout.sections[index].virtual_size {
			return error('an initializer for ${fixup.name} at ${fixup.offset} does not lie inside the writable data')
		}
		put_u64_at(mut layout.sections[index].data, fixup.offset, value)
		sites << Site{
			rva:  data_rva + fixup.offset
			kind: base_reloc_dir64
		}
	}
	return sites
}

// fixup_referent is where the name a fixup carries stands in this image, as an
// address relative to its base. The kinds are the emitter's: a call or a jump
// reaches a label, an address reference reads a string, a constant or an
// object's place, and an import is the slot the loader writes.
fn fixup_referent(program unit.Program, layout Layout, plan ImportPlan, tls TlsInfo, kind unit.FixupKind, name string) !int {
	if tls.index_rva > 0 && name == '_tls_index' {
		return tls.index_rva
	}
	match kind {
		.call_local, .jump_local, .branch_zero, .branch_nonzero, .function_address {
			text := layout.address('.text') or { return error('.text is not a section of this image') }
			return text + (program.labels[name] or {
				return error('no code for ${name}')
			})
		}
		.call_import, .import_address, .got_address {
			slot := plan.slots[name] or {
				return error('${name} is reached as an import and no import table entry was made for it')
			}
			idata := layout.address('.idata') or { return error('.idata is not a section of this image') }
			return idata + slot
		}
		.take_address {
			rdata := layout.address('.rdata') or { return error('.rdata is not a section of this image') }
			return rdata + (program.strings[name] or {
				return error('no string ${name} in the image')
			})
		}
		.take_wide_address {
			rdata := layout.address('.rdata') or { return error('.rdata is not a section of this image') }
			return rdata + (program.wide_strings[name] or {
				return error('no wide string ${name} in the image')
			})
		}
		.float_constant, .single_constant {
			rdata := layout.address('.rdata') or { return error('.rdata is not a section of this image') }
			return rdata + (program.doubles[name] or {
				return error('no floating constant ${name} in the image')
			})
		}
		.section_address {
			return match name {
				unit.section_key_text {
					layout.address('.text') or { return error('.text is not a section of this image') }
				}
				unit.section_key_rodata {
					layout.address('.rdata') or { return error('.rdata is not a section of this image') }
				}
				unit.section_key_data {
					layout.address('.data') or { return error('.data is not a section of this image') }
				}
				else { return error('${name} is not a section of this image') }
			}
		}
		.global_address {
			if slot := program.read_only_globals[name] {
				rdata := layout.address('.rdata') or { return error('.rdata is not a section of this image') }
				return rdata + slot.offset
			}
			if definition := program.bound[name] {
				if definition.function {
					text := layout.address('.text') or { return error('.text is not a section of this image') }
					return text + definition.offset
				}
				if definition.tls {
					return error('${name} is a thread-local and the PE writer places none')
				}
				data := layout.address('.data') or { return error('.data is not a section of this image') }
				return data + definition.offset
			}
			data := layout.address('.data') or { return error('.data is not a section of this image') }
			return data + (program.globals[name] or {
				return error('no global ${name} in the image')
			}).offset
		}
	}
}

// reference is where one name stands in the image being written, as an address
// relative to the image's base. The order is the same one the ELF writer asks
// its own referent question in: a name the link answered itself comes before the
// slot a unit keeps for it, because the answer is where the bytes are.
fn reference(program unit.Program, layout Layout, plan ImportPlan, tls TlsInfo, name string) !int {
	// The index a thread-local model reads is a slot the image holds and the
	// loader fills, and the link is what names it: no unit defines it, because
	// the number in it is not known until the image is mapped.
	if tls.index_rva > 0 && name == '_tls_index' {
		return tls.index_rva
	}
	if relocation_slot := plan.slots[name] {
		idata := layout.address('.idata') or { return error('.idata is not a section of this image') }
		return idata + relocation_slot
	}
	if name in program.read_only_globals {
		rdata := layout.address('.rdata') or { return error('.rdata is not a section of this image') }
		return rdata + program.read_only_globals[name].offset
	}
	if definition := program.bound[name] {
		if definition.tls {
			return error('${name} is a thread-local and the PE writer places none')
		}
		if definition.function {
			text := layout.address('.text') or { return error('.text is not a section of this image') }
			return text + definition.offset
		}
		data := layout.address('.data') or { return error('.data is not a section of this image') }
		return data + definition.offset
	}
	// A reference may name a section of this image rather than a symbol in it,
	// which is how a COFF object's unwind entry points at `.xdata`: the object
	// writes a relocation against the section symbol and the section has no
	// symbol of its own in the image.
	if section_rva := layout.address(name) {
		return section_rva
	}
	if name in program.labels {
		text := layout.address('.text') or { return error('.text is not a section of this image') }
		return text + program.labels[name]
	}
	if name in program.globals {
		data := layout.address('.data') or { return error('.data is not a section of this image') }
		return data + program.globals[name].offset
	}
	match name {
		unit.section_key_text {
			return layout.address('.text') or { return error('.text is not a section of this image') }
		}
		unit.section_key_rodata {
			return layout.address('.rdata') or { return error('.rdata is not a section of this image') }
		}
		unit.section_key_data {
			return layout.address('.data') or { return error('.data is not a section of this image') }
		}
		else {}
	}
	return error('${name} is referenced and nothing in the image defines it')
}

// base_relocations builds the .reloc section: one block per page that holds a
// site, each block stating its page and then its entries. A page with an odd
// number of sites gets one more entry of the absolute kind, which the loader
// ignores, so that the block is a multiple of four bytes.
fn base_relocations(sites []Site) []u8 {
	mut sorted := sites.clone()
	sorted.sort(a.rva < b.rva)
	mut data := []u8{}
	mut i := 0
	for i < sorted.len {
		page := sorted[i].rva & ~0xfff
		mut entries := []u16{}
		for i < sorted.len && (sorted[i].rva & ~0xfff) == page {
			// The entry is the kind in the top four bits and the offset inside
			// the page in the low twelve, which is how a loader reads a block.
			entries << (sorted[i].kind << 12) | u16(sorted[i].rva & 0xfff)
			i++
		}
		if entries.len % 2 != 0 {
			entries << u16(0)
		}
		append_u32(mut data, u32(page))
		append_u32(mut data, u32(8 + entries.len * 2))
		for entry in entries {
			append_u16(mut data, entry)
		}
	}
	return data
}

fn append_u16(mut data []u8, value u16) {
	data << u8(value & 0xff)
	data << u8((value >> 8) & 0xff)
}

fn append_u32(mut data []u8, value u32) {
	for i in 0 .. 4 {
		data << u8((value >> (8 * i)) & 0xff)
	}
}

// put_u64_at writes an eight-byte value without giving up the sign: a relative
// field can be negative, and the two halves are taken through a mask so that the
// cast to an unsigned number never sees one.
fn put_u64_at(mut output []u8, offset int, value i64) {
	put_u32(mut output, offset, u32(value & 0xffffffff))
	put_u32(mut output, offset + 4, u32((value >> 32) & 0xffffffff))
}
