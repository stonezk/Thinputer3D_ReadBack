/* Copyright (c) 2001, Stanford University
 * All rights reserved
 *
 * See the file LICENSE.txt for information on redistributing this software.
 */

#include "cr_packfunctions.h"
#include "cr_error.h"
#include "cr_net.h"
#include "packspu.h"
#include "packspu_proto.h"

#include "cr_spu.h"
#include "cr_mem.h" 


#if 0

void PACKSPU_APIENTRY packspu_SwapBuffers( GLint window, GLint flags )
{
    GET_THREAD(thread);
    if (pack_spu.swap)
    {
        crPackSwapBuffersSWAP( window, flags );
    }
    else
    {
        crPackSwapBuffers( window, flags );
    }
    packspuFlush( (void *) thread );
}


#else

void PACKSPU_APIENTRY packspu_SwapBuffers( GLint window, GLint flags, GLint phyLowAddr, GLint phyHighAddr)
{
	int write_back = 1;

    GET_THREAD(thread);

    if (pack_spu.swap)
    {
        crPackSwapBuffersSWAP( window, flags, phyLowAddr, phyHighAddr);
    }
    else
    {
        crPackSwapBuffers( window, flags, phyLowAddr, phyHighAddr);
    }

	/* note: 在Flush之前调用WriteBack命令,然后Flush，再Wait */
	write_back = 1;
	if (pack_spu.swap)
    {
    	crPackWritebackSWAP( (GLint *) &write_back );
    }
    else
    {
    	crPackWriteback( (GLint *) &write_back);
    }
    packspuFlush( (void *) thread );

	/* Wait */
	CRPACKSPU_WRITEBACK_WAIT(thread, write_back);
	

    if (!(thread->netServer.conn->actual_network))
    {
        /* no synchronization needed */
        return;
    }

	crDebug("#_# zr_swapbuff : packspu_SwapBuffers win %d, flags %d, sync: %d, t_wb: %d, pack_spu.swap %d, phy: %x-%x", 
		window, flags, pack_spu.swapbuffer_sync, thread->writeback, pack_spu.swap, phyHighAddr, phyLowAddr);

    if (pack_spu.swapbuffer_sync) {
        /* This won't block unless there has been more than 1 frame
         * since we received a writeback acknowledgement.  In the
         * normal case there's no performance penalty for doing this
         * (beyond the cost of packing the writeback request into the
         * stream and receiving the reply), but it eliminates the
         * problem of runaway rendering that can occur, eg when
         * rendering frames consisting of a single large display list
         * in a tight loop.
         *
         * Note that this is *not* the same as doing a sync after each
         * swapbuffers, which would force a round-trip 'bubble' into
         * the network stream under normal conditions.
         *
         * This is complicated because writeback in the pack spu is
         * overridden to always set the value to zero when the
         * reply is received, rather than decrementing it: 
         */
        switch( thread->writeback ) {
        case 0:
            /* Request writeback.
             */
            thread->writeback = 1;
            if (pack_spu.swap)
            {
                crPackWritebackSWAP( (GLint *) &thread->writeback );
            }
            else
            {
                crPackWriteback( (GLint *) &thread->writeback );
            }
            break;
        case 1:
            /* Make sure writeback from previous frame has been received.
             */
            CRPACKSPU_WRITEBACK_WAIT(thread, thread->writeback);
            break;
        }
    }

    /* want to emit a parameter here */
    if (pack_spu.emit_GATHER_POST_SWAPBUFFERS)
    {
        if (pack_spu.swap)
            crPackChromiumParameteriCRSWAP(GL_GATHER_POST_SWAPBUFFERS_CR, 1);
        else
            crPackChromiumParameteriCR(GL_GATHER_POST_SWAPBUFFERS_CR, 1);
    }
}

#endif
