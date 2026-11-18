module target

// host is the target of the machine this program is running on, for a caller
// whose link is for that machine: a test, or a tool that links what it just
// compiled. A compiler with a target of its own fills a Target itself, which is
// why every field is public and this function is not the only way to get one.
//
// A machine or a system this library does not describe answers none rather than
// a guess, so a caller on an unknown machine is told so instead of being linked
// an image it cannot run.
pub fn host() ?Target {
	$if amd64 && linux {
		return Target{
			name:         'x86_64-linux'
			word_size:    8
			elf_machine:  62 // EM_X86_64
			page_size:    0x1000
			load_base:    0x400000
			interpreter:  '/lib64/ld-linux-x86-64.so.2'
			base_library: 'libc.so.6'
			library_dirs: ['/usr/local/lib', '/usr/lib/x86_64-linux-gnu', '/usr/lib', '/lib']
		}
	} $else {
		return none
	}
}
