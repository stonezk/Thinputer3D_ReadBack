/*******************************************************************
 * cr_pack.h 's helper , batch of cmd
 * 
 * add by zhangrui 2017-9-20
 *
*******************************************************************/
#ifndef __THINPUTER_CR_PATCH_BATCH_H
#define	__THINPUTER_CR_PATCH_BATCH_H

#ifdef __cplusplus
extern "C" {
#endif



#define	PACK_MGR_STATE_EVALUATE			1
#define	PACK_MGR_BATCH_STATE_BATCH		2



struct bn_121_215_state_evaluate
{
	int			evaluate_state;
};
struct bn_121_215_state_batch
{
	int			flag;
};

/* (121,215) cmd sequences */
struct batch_node_121_215
{
	int			state;

	struct bn_121_215_state_evaluate	evaluate;
	struct bn_121_215_state_batch		batch;
	
};



struct pack_batch_mgr
{
	
	
	struct batch_node_121_215	node_121_251;
};






#ifdef __cplusplus
}
#endif

#endif	/* __THINPUTER_CR_PATCH_BATCH_H */



