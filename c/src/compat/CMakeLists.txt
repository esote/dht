include(CheckSymbolExists)

add_library(compat_imsg
	imsg.h
	imsg.c
	imsg-buffer.c
	compat.h
)

# Look for explicit_bzero()
check_symbol_exists(explicit_bzero "string.h" HAVE_EXPLICIT_BZERO)
if (NOT HAVE_EXPLICIT_BZERO)
	target_sources(compat_imsg PRIVATE explicit_bzero.c)
endif()

# Look for freezero()
check_symbol_exists(freezero "stdlib.h" HAVE_FREEZERO)
if (NOT HAVE_FREEZERO)
	target_sources(compat_imsg PRIVATE freezero.c)
endif()

# Look for getdtablecount()
check_symbol_exists(getdtablecount "unistd.h" HAVE_GETDTABLECOUNT)
if (NOT HAVE_GETDTABLECOUNT)
	target_sources(compat_imsg PRIVATE getdtablecount.c)
endif()

if (EXISTS "/proc/self/fd/" AND IS_DIRECTORY "/proc/self/fd/")
	target_compile_definitions(compat_imsg PRIVATE HAVE_PROC_PID=1)
endif()

# Look for getdtablesize()
check_symbol_exists(getdtablesize "unistd.h" HAVE_GETDTABLESIZE)
if (NOT HAVE_GETDTABLESIZE)
	target_sources(compat_imsg PRIVATE getdtablesize.c)
endif()

# Look for getpagesize()
check_symbol_exists(getpagesize "unistd.h" HAVE_GETPAGESIZE)
if (NOT HAVE_GETPAGESIZE)
	target_sources(compat_imsg PRIVATE getpagesize.c)
endif()

# Look for queue.h macros
check_symbol_exists(TAILQ_CONCAT "sys/queue.h" HAVE_QUEUE)
if (NOT HAVE_QUEUE)
	target_sources(compat_imsg PRIVATE queue.h)
endif()

# Look for recallocarray()
check_symbol_exists(recallocarray "stdlib.h" HAVE_RECALLOCARRAY)
if (NOT HAVE_RECALLOCARRAY)
	target_sources(compat_imsg PRIVATE recallocarray.c)
endif()

set_property(TARGET compat_imsg PROPERTY C_EXTENSIONS OFF)
set_property(TARGET compat_imsg PROPERTY C_STANDARD 99)
set_property(TARGET compat_imsg PROPERTY C_STANDARD_REQUIRED ON)

add_compile_definitions(compat_imsg
	PRIVATE
		_POSIX_C_SOURCE=200809L
		_XOPEN_SOURCE=700
)
