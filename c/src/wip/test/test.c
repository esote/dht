#include <check.h>

#include "test.h"

int
main(void)
{
	int failed;
	SRunner *sr = srunner_create(suite_storer());

	srunner_set_fork_status(sr, CK_NOFORK);

	srunner_run_all(sr, CK_NORMAL);
	failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return failed != 0;
}
