include_directories(${dhtd_SOURCE_DIR}/src)
add_executable(test_dhtd
	monitor_test.c
	rtable_sqlite_test.c
	test.c)
find_package(Threads REQUIRED)
find_package(Check REQUIRED)
target_link_libraries(test_dhtd
	PRIVATE
		dhtd_internal
		Threads::Threads
		check
)
add_test (NAME test_dhtd COMMAND test_dhtd)
