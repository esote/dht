#include <stdlib.h>
#include <string.h>

#include "compat.h"

void
freezero(void *ptr, size_t size)
{
	if (ptr != NULL) {
		explicit_bzero(ptr, size);
		free(ptr);
	}
}
