# Security

vlk reads object files, archives and shared objects that other programs wrote,
and it writes an executable. Both directions can go wrong in ways that matter.

A report belongs here when the input is malformed and vlk does something a
reader of the format would not allow: a read past the end of a buffer, a length
that is believed, an offset into the file that is not checked, a loop that never
ends, or a file written somewhere other than the path it was given. A report also
belongs here when the input is well formed and the image is not what the input
describes, because a wrong relocation or a symbol bound to the wrong place is a
program that does something the source did not ask for.

Send it through the repository's private advisory form,
https://github.com/vanadiume/vlk/security/advisories/new, rather than an issue.
When the report is about reading a file, attach the file if you can; a crash
that reproduces from a 200-byte object is worth more than a description of one.

You will get an answer saying whether the report was reproduced, and if it was,
what the fix is and when it is planned. Credit in the advisory is yours unless
you say otherwise.
