#include "../kbucket.h"
#include "../proto.h"
int
main(void)
{
	struct node n1 = {.id={1}}, n2 = {.id={2}}, n3 = {.id={3}};
	struct kbucket *kb = kbucket_new(2);
	int s = kbucket_store(kb, &n1);
	s = kbucket_store(kb, &n2);
	s = kbucket_store(kb, &n3);
	s = kbucket_store(kb, &n1);
	const struct node *ln1 = kbucket_load(kb, n1.id);
	const struct node *ln3 = kbucket_load(kb, n3.id);
	size_t len = 0;
	struct node *list = kbucket_append(kb, NULL, &len, 10);
	free(list);
	const struct node *old = kbucket_oldest(kb);
	struct node *rn1 = kbucket_remove(kb, n1.id);
	free(rn1);
	struct node *rn2 = kbucket_remove(kb, n2.id);
	free(rn2);
	struct node *rn3 = kbucket_remove(kb, n3.id);
	kbucket_free(kb);
}
