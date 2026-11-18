module library

import os

// The search is checked against this machine's own libraries, because that is
// what a link reads: a test that made up a directory tree would be checking a
// system nobody runs.

fn test_a_library_name_resolves_to_the_name_the_loader_knows() {
	dirs := search_dirs([], ['/usr/lib/x86_64-linux-gnu', '/usr/lib', '/lib'])
	found := resolve_libraries(['c'], dirs, false) or { panic('libc did not resolve: ${err.msg()}') }
	assert 'libc.so.6' in found
}

fn test_a_shared_object_named_by_path_carries_its_own_name() {
	path := '/usr/lib/x86_64-linux-gnu/libc.so.6'
	if !os.exists(path) {
		return
	}
	found := shared_library(path) or { panic('${path} was not read: ${err.msg()}') }
	assert found.path == path
	assert found.soname == 'libc.so.6'
	assert !found.archive
}

fn test_the_c_library_answers_a_name_it_defines() {
	dirs := search_dirs([], ['/usr/lib/x86_64-linux-gnu', '/usr/lib', '/lib'])
	missing := unresolved_imports(['printf', 'nosuchname_xyz'], [], dirs, 'libc.so.6')
	assert 'printf' !in missing
	assert 'nosuchname_xyz' in missing
}
