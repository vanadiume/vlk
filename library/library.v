module library

// Library is what a `-l` name comes to: the file the search found and the name
// the image carries for it. The two are not the same string, which is the reason
// both are kept: `-lm` is `/usr/lib/libm.so` on this machine and `libm.so.6` in
// the image, and a caller that has to read the library needs the file.
//
// An archive is the third shape the search answers with. It has no SONAME for
// the image to carry, so `soname` holds its own file name, and `archive` says
// the file is an ar container a link reads members out of rather than a library
// the loader maps.
//
// A shared object the command line named by path is the same value filled in by
// the caller: vlk.Options.shared_libraries takes one so that the names it
// defines can answer the image's imports and its soname can be recorded.
pub struct Library {
pub:
	path    string
	soname  string
	archive bool // the file is an ar archive, so the link reads its members
}
