module vlk

import unit

// The merge is here and the container is not, so `link` refuses and `merge` is
// what a caller can use today. Both refusals are properties of the library
// rather than things a reader has to take on trust.
fn test_link_refuses_until_the_container_moves_here() {
	merged := link([]unit.Program{}, Options{}) or {
		assert err.msg().contains('cannot write an image yet')
		return
	}
	assert false, 'link answered with a program of ${merged.text.len} bytes of text'
}

fn test_merge_of_no_units_is_refused() {
	_ := merge([]unit.Program{}, Options{}) or {
		assert err.msg() == 'a link has no units'
		return
	}
	assert false, 'a merge of no units answered'
}
