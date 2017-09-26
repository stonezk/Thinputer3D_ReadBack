/*******************************************************************
 * smem   guset<--->host   proto (used for both guest and host)
 * 
 * add by zhangrui 2017-9-19
 *
*******************************************************************/

#ifndef __THINPUTER_OPENGL_SMEM_PROTO_H
#define	__THINPUTER_OPENGL_SMEM_PROTO_H

#ifdef __cplusplus
extern "C" {
#endif


struct smem_notify
{
	/* Host Set, Guest Clear */
	int	__declspec(align(128))	h2g;

	/* Guest Set, Host Clear */
	int	__declspec(align(128))	g2h;
};



struct smem_ring
{
	int	__declspec(align(128))	head;
	int	__declspec(align(128))	tail;

	int	__declspec(align(128))	size;
};

struct smem_display
{
	//int			buff_size;
	
	int			width;
	int			height;
};

static __inline void *smem_ring_get_data(struct smem_ring *ring)
{
	return (void *)(ring+1);
}

static __inline void *smem_display_get_data(struct smem_display *disp)
{
	return (void *)(disp+1);
}

#ifdef __cplusplus
}
#endif

#endif	/* __THINPUTER_OPENGL_SMEM_PROTO_H */

