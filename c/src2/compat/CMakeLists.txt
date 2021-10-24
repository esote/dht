include(CheckSymbolExists)

add_library(compat
	compat.h

	imsg.h
	imsg.c
	imsg-buffer.c

	queue.h

	explicit_bzero.c
	freezero.c
	getdtablecount.c
	getdtablesize.c
	getpagesize.c
	recallocarray.c
)

set_property(TARGET compat PROPERTY C_EXTENSIONS OFF)
set_property(TARGET compat PROPERTY C_STANDARD 99)
set_property(TARGET compat PROPERTY C_STANDARD_REQUIRED ON)

add_compile_definitions(compat
	PRIVATE
		_POSIX_C_SOURCE=200809L
		_XOPEN_SOURCE=700
)
