include(CheckSymbolExists)

add_executable(dhtd2
	dhtd.c
	listen.c
	parent.c
	rtable.c)

set_property(TARGET dhtd2 PROPERTY C_EXTENSIONS OFF)
set_property(TARGET dhtd2 PROPERTY C_STANDARD 99)
set_property(TARGET dhtd2 PROPERTY C_STANDARD_REQUIRED ON)

add_compile_definitions(dhtd2
	PRIVATE
		_POSIX_C_SOURCE=200809L
		_XOPEN_SOURCE=700
		_DEFAULT_SOURCE
		_GNU_SOURCE
)
