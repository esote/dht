include(CheckSymbolExists)

add_subdirectory(compat)
check_symbol_exists(imsg_init "imsg.h" HAVE_IMSG)

add_executable(dhtd
	crypto.c
	crypto_sha3.c
	dhtd.c
	listen.c
	monitor.c
	proto.c
	rtable.c
	rtable_sqlite.c
	util.c)

add_library(dhtd_internal
	crypto.c
	crypto.h
	crypto_sha3.c
	crypto_sha3.h
	dhtd.c
	dhtd.h
	listen.c
	listen.h
	monitor.c
	monitor.h
	proto.c
	proto.h
	rtable.c
	rtable.h
	rtable_sqlite.c
	rtable_sqlite.h
	util.c
	util.h)

if (NOT HAVE_IMSG)
	include_directories(${dhtd_SOURCE_DIR}/src/compat)
	target_link_libraries(dhtd PRIVATE compat_imsg)
	target_link_libraries(dhtd_internal PRIVATE compat_imsg)
endif()

#set_property(TARGET dhtd PROPERTY C_EXTENSIONS OFF)
set_property(TARGET dhtd PROPERTY C_STANDARD 11)
set_property(TARGET dhtd PROPERTY C_STANDARD_REQUIRED ON)

#add_compile_definitions(dhtd
#	PRIVATE
#		_POSIX_C_SOURCE=200809L
#)

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Sodium REQUIRED)
target_link_libraries(dhtd
	PRIVATE
		Threads::Threads
		SQLite::SQLite3
		sodium
)
target_link_libraries(dhtd_internal
	PRIVATE
		Threads::Threads
		SQLite::SQLite3
		sodium
)
