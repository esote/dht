#include "../kbucket.h"
#include "../proto.h"
int
main(void)
{
	struct node_triple n1 = {.id={1}}, n2 = {.id={2}}, n3 = {.id={3}};
	struct kbucket *kb = kb_new(2);
	int s = kb_store(kb, &n1);
	s = kb_store(kb, &n2);
	s = kb_store(kb, &n3);
	s = kb_store(kb, &n1);
	const struct node_triple *ln1 = kb_load(kb, n1.id);
	const struct node_triple *ln3 = kb_load(kb, n3.id);
	size_t len = 0;
	struct node_triple *list = kb_append(kb, NULL, &len, 10);
	free(list);
	const struct node_triple *old = kb_oldest(kb);
	struct node_triple *rn1 = kb_remove(kb, n1.id);
	free(rn1);
	struct node_triple *rn2 = kb_remove(kb, n2.id);
	free(rn2);
	struct node_triple *rn3 = kb_remove(kb, n3.id);
	kb_free(kb);
}
