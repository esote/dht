#include <unistd.h>

#include "compat.h"

int
getpagesize(void)
{
	return (sysconf(_SC_PAGESIZE));
}
