/* Copyright (c) 2001, Stanford University
 * All rights reserved
 *
 * See the file LICENSE.txt for information on redistributing this software.
 */

#include "packspu.h"
#include "cr_string.h"
#include "cr_error.h"
#include "cr_spu.h"
#include "cr_mem.h"

#include "../cr_helper.h"

#include <stdio.h>

char g_Host[64] = {0};
char client_ip[64] = {0};

static void __setDefaults( void )
{
    crMemZero(pack_spu.context, CR_MAX_CONTEXTS * sizeof(ContextInfo));
    pack_spu.numContexts = 0;

    crMemZero(pack_spu.thread, MAX_THREADS * sizeof(ThreadInfo));
    pack_spu.numThreads = 0;
}


static void set_emit( void *foo, const char *response )
{
    sscanf( response, "%d", &(pack_spu.emit_GATHER_POST_SWAPBUFFERS) );
}

static void set_swapbuffer_sync( void *foo, const char *response )
{
    sscanf( response, "%d", &(pack_spu.swapbuffer_sync) );
}



/* No SPU options yet. Well.. not really.. 
 */
SPUOptions packSPUOptions[] = {
    { "emit_GATHER_POST_SWAPBUFFERS", CR_BOOL, 1, "0", NULL, NULL, 
      "Emit a parameter after SwapBuffers", (SPUOptionCB)set_emit },

    { "swapbuffer_sync", CR_BOOL, 1, "1", NULL, NULL,
        "Sync on SwapBuffers", (SPUOptionCB) set_swapbuffer_sync },

    { NULL, CR_BOOL, 0, NULL, NULL, NULL, NULL, NULL },
};

void get_server_ip(char *src)
{
    char *data = NULL;
    crStrcpy(g_Host,"tcpip://");
	data = strtok(src, " ");
	if(data){
		data = strtok(NULL, " ");
		crStrcpy(g_Host+crStrlen("tcpip://"), data);
	}
}

void packspuSetVBoxConfiguration( const SPU *child_spu )
{
    __setDefaults();
    pack_spu.emit_GATHER_POST_SWAPBUFFERS = 0;
    pack_spu.swapbuffer_sync = 0;
    //pack_spu.name = crStrdup("vboxhgcm://llp:7000");
    
	crGetHostFromPipe(client_ip);
	get_server_ip(client_ip);
	//memcpy(g_Host + crStrlen("tcpip://"), client_ip + 16 + 1, 13);
	//memcpy(g_Host + crStrlen("tcpip://"), client_ip + 16 + 1, 16); // 16 is IP length
    pack_spu.name = g_Host;
    pack_spu.buffer_size = 5 * 1024 * 1024;
}
