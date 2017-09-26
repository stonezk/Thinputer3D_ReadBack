#ifndef __THINPUTER_OPENGL_SMEM_H
#define	__THINPUTER_OPENGL_SMEM_H

#include <stdlib.h>


#include "smem_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

struct smem_phy_addr
{
	int		high_addr;
	int		low_addr;
};

struct smem_layout
{
	struct smem_ring		*to_host;
	struct smem_ring		*to_guest;
	struct smem_display		*display;
	struct smem_notify		*notify;

	struct smem_phy_addr	phy_to_host;
	struct smem_phy_addr	phy_to_guest;
	struct smem_phy_addr	phy_display;
	struct smem_phy_addr	phy_notify;
};


struct smem_node
{
	int		is_valid;	/* 是否有效 */
	
	int		size;
	void	*uva;

	struct smem_phy_addr	phy_addr;
};


struct smem_window
{
	int					attach_key;	/* 关联的key */
	
	struct smem_node	*mem;		/* user|kernel 共享内存相关  */

	struct smem_layout	layout;
};


static __inline int smem_node_is_vaild(struct smem_node *node)
{
	if (node->is_valid && node->uva != NULL)
		return 1;

	return 0;
}

extern void smem_module_init();
extern void smem_module_clean();

extern struct smem_node *smem_node_alloc();
extern void smem_node_free(struct smem_node *node);


extern int smem_layout_init(struct smem_layout *pl, struct smem_node *node);
extern void smem_layout_clean(struct smem_layout *pl);


extern int  smem_win_init(struct smem_window *sw, int key);
extern void smem_win_clean(struct smem_window *sw, int key);



#ifdef __cplusplus
}
#endif


#endif	/* __THINPUTER_OPENGL_SMEM_H */

