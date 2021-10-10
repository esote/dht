include(CheckSymbolExists)

add_library(compat_imsg
	imsg.h
	imsg.c
	imsg-buffer.c

	compat.h
	explicit_bzero.c
	freezero.c
	getdtablecount.c
	getdtablesize.c
	getpagesize.c
	queue.h
	recallocarray.c
)

if (EXISTS "/proc/self/fd/" AND IS_DIRECTORY "/proc/self/fd/")
	target_compile_definitions(compat_imsg PRIVATE HAVE_PROC_PID=1)
endif()

set_property(TARGET compat_imsg PROPERTY C_EXTENSIONS OFF)
set_property(TARGET compat_imsg PROPERTY C_STANDARD 99)
set_property(TARGET compat_imsg PROPERTY C_STANDARD_REQUIRED ON)

add_compile_definitions(compat_imsg
	PRIVATE
		_POSIX_C_SOURCE=200809L
		_XOPEN_SOURCE=700
)
