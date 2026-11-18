module vlk

import vanadiume.vlk.unit

// The three depths answer the same request at different stages, so the refusals
// worth pinning are the ones a caller meets before anything is read or written.
fn test_link_of_no_units_is_refused() {
	_ := link([]unit.Program{}, Options{}) or {
		assert err.msg() == 'a link has no units'
		return
	}
	assert false, 'a link of no units answered'
}

fn test_merge_of_no_units_is_refused() {
	_ := merge([]unit.Program{}, Options{}) or {
		assert err.msg() == 'a link has no units'
		return
	}
	assert false, 'a merge of no units answered'
}
