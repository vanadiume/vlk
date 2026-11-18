#!/usr/bin/env -S v run

// The local gate: what a pull request has to pass, runnable before pushing so
// that a red review is never the first news of a problem.
//
// Five steps, each reporting on its own line: formatting, the pure-V rule, the
// suite, the suite again with no garbage collector, and the links between the
// documents in the tree. The exit status is
// zero only when all four pass.
//
// There is no build step because a library has nothing to build: `v test`
// compiles every module in the tree, so a module that does not compile fails
// the suite step rather than a step of its own.

import os

const c_source_extensions = ['.c', '.h', '.cc', '.cpp', '.hpp', '.S', '.s']

// The patterns that bring C into a V library. A line whose trimmed text starts
// with `//` is exempt, which is why prose in a comment is safe and a trailing
// comment on a code line is not.
const interop_patterns = ['#include ', '#flag ', 'C.']

struct CommandResult {
	output    string
	exit_code int
}

fn main() {
	root := os.dir(os.dir(@FILE))
	println('gate: ${root}')
	mut failures := []string{}
	report('formatting', check_formatting(root), mut failures)
	report('pure V', check_pure_v(root), mut failures)
	report('tests', check_tests(root), mut failures)
	report('tests, no collector', check_tests_without_a_collector(root), mut failures)
	report('links', check_links(root), mut failures)
	if failures.len > 0 {
		eprintln('')
		eprintln('gate: ${failures.len} step(s) failed: ${failures.join(', ')}')
		exit(1)
	}
	println('')
	println('gate: all steps pass')
}

fn report(name string, problems []string, mut failures []string) {
	if problems.len == 0 {
		println('  ${name}: ok')
		return
	}
	failures << name
	eprintln('  ${name}: failed')
	for problem in problems {
		eprintln('    ${problem}')
	}
}

fn run(arguments []string) CommandResult {
	result := os.exec(arguments)
	return CommandResult{
		output:    result.output
		exit_code: result.exit_code
	}
}

fn check_formatting(root string) []string {
	result := run(['v', 'fmt', '-verify', root])
	if result.exit_code == 0 {
		return []
	}
	mut problems := []string{}
	for line in result.output.split_into_lines() {
		trimmed := line.trim_space()
		if trimmed.contains('is not formatted') || trimmed.starts_with('diff ') {
			problems << trimmed
		}
	}
	if problems.len == 0 {
		problems << 'v fmt -verify exited ${result.exit_code}: ${result.output.trim_space()}'
	}
	return problems
}

// check_pure_v looks for what breaks the first rule rather than for the rule:
// a C source file anywhere in the tree, and C interop in any file the library is
// compiled from. tools/ is skipped because the gate names those patterns on
// purpose, and .omh/ holds notes for one agent run rather than library source.
fn check_pure_v(root string) []string {
	mut problems := []string{}
	for extension in c_source_extensions {
		for file in os.walk_ext(root, extension) {
			if ignored(file) {
				continue
			}
			problems << '${relative(file, root)}: C source in a tree that is V only'
		}
	}
	for file in os.walk_ext(root, '.v') {
		if ignored(file) || file.contains('/tools/') {
			continue
		}
		lines := os.read_lines(file) or { continue }
		for i, line in lines {
			trimmed := line.trim_space()
			if trimmed.starts_with('//') {
				continue
			}
			for pattern in interop_patterns {
				if trimmed.contains(pattern) {
					problems << '${relative(file, root)}:${i + 1}: ${pattern.trim_space()} brings C into the library'
				}
			}
		}
	}
	return problems
}

fn check_tests(root string) []string {
	// -nocache, not `v test .`: the module cache makes a run depend on which C
	// compiler V picked for each file, and a failing suite that clears itself on
	// a cold cache wastes the reader's afternoon.
	return test_failures(run(['v', '-nocache', 'test', root]))
}

// check_tests_without_a_collector is the same suite compiled the way the program
// that links through this library is built: `-gc none`, no collector at all. A
// library that leaned on a collection running would pass the first step and break
// every build of its consumer, so both are the bar.
fn check_tests_without_a_collector(root string) []string {
	return test_failures(run(['v', '-gc', 'none', '-nocache', 'test', root]))
}

fn test_failures(result CommandResult) []string {
	if result.exit_code == 0 {
		return []
	}
	mut problems := []string{}
	for line in result.output.split_into_lines() {
		trimmed := line.trim_space()
		if trimmed.starts_with('FAIL') || trimmed.contains('error:') {
			problems << trimmed
		}
	}
	if problems.len == 0 {
		problems << 'v -nocache test exited ${result.exit_code}: ${result.output.trim_space()}'
	}
	return problems
}

// check_links resolves every relative link in the markdown at the root of the
// tree. A link to a file that is not here is a promise to a reader that the
// tree does not keep, and nothing else in the tree reads markdown.
fn check_links(root string) []string {
	mut problems := []string{}
	for file in os.walk_ext(root, '.md') {
		if ignored(file) {
			continue
		}
		text := os.read_file(file) or { continue }
		directory := os.dir(file)
		mut rest := text
		for {
			start := rest.index('](') or { break }
			rest = rest[start + 2..]
			end := rest.index(')') or { break }
			target := rest[..end].trim_space()
			rest = rest[end + 1..]
			if target == '' || target.starts_with('#') || target.starts_with('http://')
				|| target.starts_with('https://') || target.starts_with('mailto:') {
				continue
			}
			path := target.all_before('#')
			if os.exists(os.join_path(directory, path)) || os.exists(os.join_path(root, path)) {
				continue
			}
			problems << '${relative(file, root)}: ${target} does not resolve'
		}
	}
	return problems
}

// ignored keeps the walk out of the directories that hold no library source:
// the git database, and the notes for one agent run.
fn ignored(file string) bool {
	return file.contains('/.git/') || file.contains('/.omh/')
}

fn relative(file string, root string) string {
	return file.replace('${root}/', '')
}
