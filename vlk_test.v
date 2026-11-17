module vlk

import unit

// The entry refuses while the implementation is still in vcc. The test exists so
// that the refusal is a property of the library rather than a thing a reader has
// to take on trust: a caller that gets a program back from an empty link has been
// told something false.
fn test_link_refuses_until_the_merge_moves_here() {
	merged := link([]unit.Program{}, Options{}) or {
		assert err.msg().contains('has no linker yet')
		return
	}
	assert false, 'link answered with a program of ${merged.text.len} bytes of text'
}
