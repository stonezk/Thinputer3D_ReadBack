/*******************************************************************
 * app shared memory manager module
 * 
 * add by zhangrui 2017-9-19
 *
*******************************************************************/

#include <windows.h>
#include <winioctl.h>

#include "cr_error.h"

#include "smem.h"

#include "../../../../../WinDriver/win_shared_mem.h"

#define	MAX_WINDOW_COUNT	6	/* 一个应用最多打开多少个3D窗口 */



struct smem_mgr
{
	HANDLE				driver_handler;
	
	struct smem_node	nodes[MAX_WINDOW_COUNT];
	
};

static struct smem_mgr s_smem_mgr;

static struct smem_node *get_free_smem_node(struct smem_mgr *sm)
{
	int			i;

	for (i=0; i<MAX_WINDOW_COUNT; ++i) {
		struct smem_node *node = &sm->nodes[i];

		if (!smem_node_is_vaild(node)) {
			return node;
		}
	}

	return NULL;
}

static int smem_node_domap(struct smem_mgr *sm, struct smem_node *node)
{
	BOOL						ret;
	DWORD						count;
	struct drv_ioctl_map_param	param;

	if (smem_node_is_vaild(node)) {
		crDebug("##zr## smem : smem_node_domap Error already mapped");
		return -1;
	}
	if (sm->driver_handler == INVALID_HANDLE_VALUE) {
		return -1;
	}

	ret = DeviceIoControl(sm->driver_handler, WINMEM_IOCTL_DO_MAP_MEMORY, 
		&param, sizeof(param), &param, sizeof(param), &count, NULL);

	if (!ret) {
		crDebug("##zr## smem : smem_node_domap Error ioctl");
		return -1;
	}

	node->is_valid = 1;
	node->uva = param.ptr_uva;
	node->size = param.size;
	node->phy_addr.high_addr = param.phy_high_addr;
	node->phy_addr.low_addr = param.phy_low_addr;
	
	return 0;
}

static int smem_node_unmap(struct smem_mgr *sm, struct smem_node *node)
{
	BOOL						ret;
	DWORD						count;
	struct drv_ioctl_map_param	param;
	
	if (!smem_node_is_vaild(node)) {
		crDebug("##zr## smem : smem_node_unmap Error not mapped");
		return -1;
	}
	if (sm->driver_handler == INVALID_HANDLE_VALUE) {
		return -1;
	}

	param.ptr_uva = node->uva;
	param.size = node->size;
	param.phy_high_addr = node->phy_addr.high_addr;
	param.phy_low_addr= node->phy_addr.low_addr;

	ret = DeviceIoControl(sm->driver_handler, WINMEM_IOCTL_UN_MAP_MEMORY, 
		&param, sizeof(param), NULL, 0, &count, NULL);

	memset(node, 0, sizeof(*node));

	return 0;
}


static int smem_mgr_init(struct smem_mgr *sm)
{
	memset(sm, 0, sizeof(*sm));

	sm->driver_handler = CreateFile( USER_MODE_SYS_LINK_NAME, GENERIC_READ|GENERIC_WRITE, 
		FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	
	if (sm->driver_handler == INVALID_HANDLE_VALUE) {
		crDebug("##zr## smem : smem_mgr_init Error : sm %p Cant Open Dirver %p ,INVALID_HANDLE_VALUE %x", 
			sm, sm->driver_handler, INVALID_HANDLE_VALUE);
		return -1;
	}
	
	return 0;
}

static void smem_mgr_clear_nodes(struct smem_mgr *sm)
{
	int			i;

	for (i=0; i<MAX_WINDOW_COUNT; ++i) {
		struct smem_node *node = &sm->nodes[i];

		if (smem_node_is_vaild(node)) {
			crDebug("##zr## smem (WARNING) : smem_mgr_clear_nodes some node is need unmap");
			smem_node_unmap(sm, node);
		}
	}
}

static void smem_mgr_clean(struct smem_mgr *sm)
{
	smem_mgr_clear_nodes(sm);

	crDebug("##zr## smem : smem_mgr_clean : sm %p Handler %p", 
			sm, sm->driver_handler);
	
	if (sm->driver_handler != INVALID_HANDLE_VALUE) {
		crDebug("##zr## smem : smem_mgr_clean do close: sm %p Handler %p", 
			sm, sm->driver_handler);
		
		CloseHandle(sm->driver_handler);
	}

	memset(sm, 0, sizeof(*sm));
}

void smem_module_init()
{
	crDebug("##zr## smem : smem_module init %p", &s_smem_mgr);

	smem_mgr_init(&s_smem_mgr);
}

void smem_module_clean()
{
	crDebug("##zr## smem : smem_module clean %p", &s_smem_mgr);

	smem_mgr_clean(&s_smem_mgr);	
}

struct smem_node *smem_node_alloc()
{
	struct smem_node *node = get_free_smem_node(&s_smem_mgr);

	if (node == NULL) {
		crDebug("##zr## smem : smem_node_alloc get free smem_node Failed!");
		return NULL;
	}

	if (smem_node_domap(&s_smem_mgr, node)) {
		return NULL;
	}

	return node;
}

void smem_node_free(struct smem_node *node)
{
	if (node != NULL) {
		smem_node_unmap(&s_smem_mgr, node);
	}
}



