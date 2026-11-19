module elf

// Kind is which link a caller asked for. The four differ in what the container
// writes and in nothing else, so they are one value with four cases rather than
// four ways to build an image.
//
// A program is the dynamic one: the kernel hands it to the loader in
// `Target.interpreter`, and it runs at the load base the image was written for.
// A position-independent executable is the same thing placed by its loader: the
// kernel still hands it over, and every address inside it travels as an offset
// beside a relocation that adds wherever the kernel put it. A static program
// names no loader and resolves every library into itself, and a shared object is
// a file another program loads rather than one the kernel starts, so it has no
// entry point and no loader either.
pub enum Kind {
	program
	static_program
	shared
	pie
}

// placed_by_the_loader is whether the kind's base is the loader's to choose
// rather than the link's. A shared object and a position-independent executable
// are the two that are mapped where their loader likes, so they are the two whose
// addresses travel as offsets beside a relative relocation; a program, static or
// dynamic, is written at the target's load base and has no such entry.
fn placed_by_the_loader(kind Kind) bool {
	return kind == .shared || kind == .pie
}

// Options is what the caller asks the container for beyond the kind. Each one is
// a promise the image records rather than a change to what the link decided: an
// image names one of these facts in a program header or a dynamic table entry,
// and a loader reads it from there.
pub struct Options {
pub:
	// execstack says the stack the kernel maps is executable even when no unit
	// asked for that.
	execstack bool
	// noexecstack says the stack is not executable, even for a unit that wrote a
	// nested function's trampoline into its frame. The option wins over the
	// unit's own request, which is what asking for it means in a linker that has
	// one.
	noexecstack bool
	// bind_now says every imported name is resolved before the first instruction
	// runs. The container already writes one eager binding per import and no lazy
	// stub, so the flag states the promise in the dynamic table rather than
	// changing a relocation.
	bind_now bool
	// relro says the image carries a PT_GNU_RELRO segment over the tables the
	// loader writes and nothing writes again.
	relro bool
	// soname is the name the shared object records as its own, written as a
	// DT_SONAME entry. Empty writes none, which is what a link that named no name
	// gets.
	soname string
}
