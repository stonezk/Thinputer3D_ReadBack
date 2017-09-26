/*******************************************************************
 * app windows attacher interface
 * 
 * add by zhangrui 2017-9-19
 *
*******************************************************************/

#include "cr_error.h"

#include "smem.h"


int  smem_win_init(struct smem_window *sw, int key)
{
	if (key == 0)
		return -1;

	memset(sw, 0, sizeof(*sw));

	sw->mem = smem_node_alloc();

	if (sw->mem == NULL) {
		crDebug("##zr## smem : smem_win_init get smem_node Failed!");
		return -1;
	}

	if (smem_layout_init(&sw->layout, sw->mem)) {
		smem_node_free(sw->mem);
		sw->mem = NULL;
		return -1;
	}

	sw->attach_key = key;
	crDebug("##zr## smem : smem_init success key %x, uva %p", key, sw->mem->uva);

	return 0;
}

void smem_win_clean(struct smem_window *sw, int key)
{
	if (key == 0)
		return;

	if (sw->attach_key != key) {
		crDebug("##zr## smem : smem_clean attach_key check failed!");
		return;
	}

	smem_layout_clean(&sw->layout);

	smem_node_free(sw->mem);
	
	memset(sw, 0, sizeof(*sw));
}

