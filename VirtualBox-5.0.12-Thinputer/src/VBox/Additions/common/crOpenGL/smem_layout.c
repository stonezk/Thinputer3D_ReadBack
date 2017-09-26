/*******************************************************************
 * app shared memory layout manager
 * 
 * add by zhangrui 2017-9-19
 *
*******************************************************************/

#include "smem.h"
#include "cr_error.h"


/* ÓëÇý¶¯Ò»ÖÂ */
#define	TOTAL_MEM_SIZE		(16*1024*1024)

#define	RING_SIZE_TOHOST	(6*1024*1024)
#define	RING_SIZE_TOGUEST	(1*1024*1024)
#define	BUFF_SIZE_DISPLAY	(8*1024*1024)

#define	MEM_OFFSET_RING_TOHOST		(0)
#define	MEM_OFFSET_RING_TOGUEST		(RING_SIZE_TOHOST + sizeof(struct smem_ring))
#define	MEM_OFFSET_DISPLAY			(TOTAL_MEM_SIZE-BUFF_SIZE_DISPLAY-sizeof(struct smem_display))
#define	MEM_OFFSET_NOTIFY			(MEM_OFFSET_DISPLAY-sizeof(struct smem_notify))


/**********************************
Low addr:
_________________________________
|								|
|	  Ring-Buff  (to Host)		|
|_______________________________|
|								|
|	  Ring-Buff  (to Guest)		|
|_______________________________|
|	  		Reserve				|
|_______________________________|
|								|
|	  Display Data Buff 		|
|								|
|_______________________________|

***********************************/

static __inline void smem_phyaddr_offset(struct smem_phy_addr *dst, struct smem_phy_addr *src, int offset)
{
	dst->high_addr = src->high_addr;
	dst->low_addr = src->low_addr + offset;
}


int smem_layout_init(struct smem_layout *pl, struct smem_node *node)
{
	memset(pl, 0, sizeof(*pl));

	if (node->size != TOTAL_MEM_SIZE) {
		crDebug("##zr## smem : smem_layout_init size error %d expect %d!", node->size, TOTAL_MEM_SIZE);
		return -1;
	}

	pl->to_host  = (struct smem_ring*)((char*)node->uva + MEM_OFFSET_RING_TOHOST);
	pl->to_guest = (struct smem_ring*)((char*)node->uva + MEM_OFFSET_RING_TOGUEST);
	pl->display  = (struct smem_display*)((char*)node->uva + MEM_OFFSET_DISPLAY);
	pl->notify   = (struct smem_notify*)((char*)node->uva + MEM_OFFSET_NOTIFY);

	smem_phyaddr_offset(&pl->phy_to_host, &node->phy_addr, MEM_OFFSET_RING_TOHOST);
	smem_phyaddr_offset(&pl->phy_to_guest, &node->phy_addr, MEM_OFFSET_RING_TOGUEST);
	smem_phyaddr_offset(&pl->phy_display, &node->phy_addr, MEM_OFFSET_DISPLAY);
	smem_phyaddr_offset(&pl->phy_notify, &node->phy_addr, MEM_OFFSET_NOTIFY);

	crDebug("smem_ring %d, smem_display %d , smem_notify %d", 
		sizeof(struct smem_ring), sizeof(struct smem_display), sizeof(struct smem_notify));
	crDebug("##zr## smem : smem_layout_init uva %p, to host ring %p %x, to guest ring %p %x, notify %p %x, display %p %x", 
		node->uva, 
		pl->to_host, MEM_OFFSET_RING_TOHOST,
		pl->to_guest, MEM_OFFSET_RING_TOGUEST,
		pl->notify, MEM_OFFSET_NOTIFY,
		pl->display, MEM_OFFSET_DISPLAY);

	crDebug("##zr## smem : phyaddr base %x-%x, tohost %x-%x, toguest %x-%x, notify %x-%x, disp %x-%x", 
		node->phy_addr.high_addr, node->phy_addr.low_addr, 
		pl->phy_to_host.high_addr, pl->phy_to_host.low_addr,
		pl->phy_to_guest.high_addr, pl->phy_to_guest.low_addr,
		pl->phy_notify.high_addr, pl->phy_notify.low_addr, 
		pl->phy_display.high_addr, pl->phy_display.low_addr);

	return 0;
}

void smem_layout_clean(struct smem_layout *pl)
{
	memset(pl, 0, sizeof(*pl));
}


