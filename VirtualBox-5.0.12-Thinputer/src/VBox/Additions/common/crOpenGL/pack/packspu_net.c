/* Copyright (c) 2001, Stanford University
 * All rights reserved
 *
 * See the file LICENSE.txt for information on redistributing this software.
 */

#include "cr_pack.h"
#include "cr_mem.h"
#include "cr_net.h"
#include "cr_pixeldata.h"
#include "cr_protocol.h"
#include "cr_error.h"
#include "packspu.h"
#include "packspu_proto.h"
//#include <windows.h>


uint32_t g_u32VBoxHostCaps = 0;

/*typedef struct{    
    long imageSize;  
    long blank;  
    long startPosition;  
}BmpHead; 

typedef struct  {  
    long    Length;  
    long    width;  
    long    height;  
    WORD    colorPlane;  
    WORD    bitColor;  
    long    zipFormat;  
    long    realSize;  
    long    xPels;    
    long    yPels;  
    long    colorUse;  
    long    colorImportant;  
}InfoHead;*/



static int _gettimeofday(struct timeval * tp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970 
    static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime( &system_time );
    SystemTimeToFileTime( &system_time, &file_time );
    time =  ((uint64_t)file_time.dwLowDateTime )      ;
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
    tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
    return 0;
}


static bool hasLast = false;
static struct timeval lastCalcTime;
static int64_t waitTime=0;
static int 	waitCount = 0;

static bool hasBeforeWriteTime = false;
static struct timeval beforeWirteBackTime;

static int64_t TimeDiff(struct timeval *p1, struct timeval *p2)
{
	int sec = p2->tv_sec - p1->tv_sec;
	int us = p2->tv_usec - p1->tv_usec;

	return (int64_t)(sec * 1000000) + (int64_t)us;
}

static void CalcWaitTime(int64_t delta)
{
	struct timeval nowTime;
	int64_t id;

	
	
	if (!hasLast) {
		hasLast = true;
		_gettimeofday(&lastCalcTime);
		return;
	}

	_gettimeofday(&nowTime);

	waitTime += delta;
	waitCount++;

	//crDebug("#zr# ---- Enter CalcWaitTime %lld, last %d:%d, now %d:%d", delta,
	//	lastCalcTime.tv_sec, lastCalcTime.tv_usec, nowTime.tv_sec, nowTime.tv_usec);

	id = TimeDiff(&lastCalcTime, &nowTime) ;
	if (id >= 1000000) {
		float t = ((float)waitTime) / 1000000.0f;
		float d = ((float)id) / 1000000.0f;
		
		crDebug("#zr# ------------- : CR-WaitTime(%f s) is %f, count %d\n", d, t, waitCount);
		
		lastCalcTime = nowTime;
		waitTime = 0;
		waitCount = 0;
	}
}
void crBeforeWirteBackTest()
{
	
	hasBeforeWriteTime = true;

	_gettimeofday(&beforeWirteBackTime);

	crDebug("----spu_flush Enter crBeforeWirteBackTest");
}


static void packspuWriteback( const CRMessageWriteback *wb )
{
    int *writeback;
	struct timeval recvTime;
	
    /*DWORD wb_time;
    wb_time = GetTickCount();
    //LogPrint("In packspuWriteback time:%lu ms\n",wb_time);*/
    crMemcpy( &writeback, &(wb->writeback_ptr), sizeof( writeback ) );
    *writeback = 0;

	crDebug("packspuWriteback ---- Enter crNetRecvWriteback");

	if (hasBeforeWriteTime) {
		_gettimeofday(&recvTime);

		CalcWaitTime(TimeDiff(&beforeWirteBackTime, &recvTime));
	}
}

/**
 * XXX Note that this routine is identical to crNetRecvReadback except
 * we set *writeback=0 instead of decrementing it.  Hmmm.
 */
static void
packspuReadback( const CRMessageReadback *rb, unsigned int len )
{
    /* minus the header, the destination pointer, 
     * *and* the implicit writeback pointer at the head. */

    int payload_len = len - sizeof( *rb );
    int *writeback;
    void *dest_ptr;
    /*DWORD rb_time;
    rb_time = GetTickCount();
    //LogPrint("In packspuReadback time:%lu ms\n",rb_time);*/
    crMemcpy( &writeback, &(rb->writeback_ptr), sizeof( writeback ) );
    crMemcpy( &dest_ptr, &(rb->readback_ptr), sizeof( dest_ptr ) );

    *writeback = 0;
    crMemcpy( dest_ptr, ((char *)rb) + sizeof(*rb), payload_len );

	crDebug("#zr# ---- Enter packspuReadback payload_len: %d", payload_len);
}

static void
packspuReadPixels( const CRMessageReadPixels *rp, unsigned int len )
{
    crNetRecvReadPixels( rp, len );
    --pack_spu.ReadPixels;
}

/*static void
packspuSavePixels( const CRMessageSavePixels *sp )
{
    char szFilename[32];
    FILE *f;
    int x,y;
    int width;
    int height;
    void *pixels;
    char *buf;
    char *temp;
    int msg_len;
    char bfType[2];
    BmpHead m_BMPHeader; 
    InfoHead  m_BMPInfoHeader; 

    static int cnt = 0;
    if(cnt > 9)
        cnt = 0;
    x = sp->x;
    y = sp->y;
    width = sp->width;
    height = sp->height;
    msg_len = sp->msg_len;
    pixels = sp + 1;
    sprintf(szFilename,"C:\\frame\\frame%d.bmp",cnt++);
    LogPrint("the szFilename path %s",szFilename);
    f = fopen( szFilename,"wb" );
    if( !f ) return;

    buf = temp = pixels;
    bfType[0] = 'B';
    bfType[1] = 'M';
    m_BMPHeader.imageSize=3*width*height+54;  
    m_BMPHeader.blank=0;  
    m_BMPHeader.startPosition=54;

    fwrite(bfType,1,sizeof(bfType),f);  
    fwrite(&m_BMPHeader.imageSize,1,sizeof(m_BMPHeader.imageSize),f);  
    fwrite(&m_BMPHeader.blank,1,sizeof(m_BMPHeader.blank),f);  
    fwrite(&m_BMPHeader.startPosition,1,sizeof(m_BMPHeader.startPosition),f);

    m_BMPInfoHeader.Length=40;  
    m_BMPInfoHeader.width=width;  
    m_BMPInfoHeader.height=height;  
    m_BMPInfoHeader.colorPlane=1;  
    m_BMPInfoHeader.bitColor=24;  
    m_BMPInfoHeader.zipFormat=0;  
    m_BMPInfoHeader.realSize=3*width*height;    
    m_BMPInfoHeader.xPels=0;  
    m_BMPInfoHeader.yPels=0;  
    m_BMPInfoHeader.colorUse=0;  
    m_BMPInfoHeader.colorImportant=0;

    fwrite(&m_BMPInfoHeader.Length,1,sizeof(m_BMPInfoHeader.Length),f);  
    fwrite(&m_BMPInfoHeader.width,1,sizeof(m_BMPInfoHeader.width),f);  
    fwrite(&m_BMPInfoHeader.height,1,sizeof(m_BMPInfoHeader.height),f);  
    fwrite(&m_BMPInfoHeader.colorPlane,1,sizeof(m_BMPInfoHeader.colorPlane),f);  
    fwrite(&m_BMPInfoHeader.bitColor,1,sizeof(m_BMPInfoHeader.bitColor),f);  
    fwrite(&m_BMPInfoHeader.zipFormat,1,sizeof(m_BMPInfoHeader.zipFormat),f);  
    fwrite(&m_BMPInfoHeader.realSize,1,sizeof(m_BMPInfoHeader.realSize),f); 
    fwrite(&m_BMPInfoHeader.xPels,1,sizeof(m_BMPInfoHeader.xPels),f);  
    fwrite(&m_BMPInfoHeader.yPels,1,sizeof(m_BMPInfoHeader.yPels),f);  
    fwrite(&m_BMPInfoHeader.colorUse,1,sizeof(m_BMPInfoHeader.colorUse),f);  
    fwrite(&m_BMPInfoHeader.colorImportant,1,sizeof(m_BMPInfoHeader.colorImportant),f);  
    //fwrite(pixels,msg_len,1,f);
    for(x = 0; x < height; x++){
        for(y = 0; y < width; y++){
            buf = *temp;
            *temp = *(temp + 2);
            *(temp+ 2) = buf;
            temp += 3;
        }
    }
    for( y = height - 1; y >= 0; y--)
            fwrite((char *)pixels + y *width * 3, width, 3, f );
   
    fclose( f );

    HBITMAP hBitmap = LoadImage(NULL, "C:\\frame\\frame0.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
    CBITMAP 
    
}*/

 


static int
packspuReceiveData( CRConnection *conn, CRMessage *msg, unsigned int len )
{
    if (msg->header.type == CR_MESSAGE_REDIR_PTR)
        msg = (CRMessage*) msg->redirptr.pMessage;

    //crDebug("##Into packspuReceiveData() and Msg Type:%x", msg->header.type);
    switch( msg->header.type )
    {
        case CR_MESSAGE_READ_PIXELS:
            packspuReadPixels( &(msg->readPixels), len );
            break;
        /*case CR_MESSAGE_SAVE_PIXELS:
            LogPrint("stone the message type CR_MESSAGE_SAVE_PIXELS!");
            packspuSavePixels(&(msg->savePixels));
            break;*/
        case CR_MESSAGE_WRITEBACK:
            packspuWriteback( &(msg->writeback) );
            break;
        case CR_MESSAGE_READBACK:
            packspuReadback( &(msg->readback), len );
            break;
        default:
            /*crWarning( "Why is the pack SPU getting a message of type 0x%x?", msg->type ); */
			LogPrint("##Not Handled Msg type in packspuReceiveData()");
            return 0; /* NOT HANDLED */
    }
    return 1; /* HANDLED */
}

static CRMessageOpcodes *
__prependHeader( CRPackBuffer *buf, unsigned int *len, unsigned int senderID )
{
    int num_opcodes;
    CRMessageOpcodes *hdr;

    CRASSERT( buf );
    CRASSERT( buf->opcode_current < buf->opcode_start );
    CRASSERT( buf->opcode_current >= buf->opcode_end );
    CRASSERT( buf->data_current > buf->data_start );
    CRASSERT( buf->data_current <= buf->data_end );

    num_opcodes = buf->opcode_start - buf->opcode_current;
    hdr = (CRMessageOpcodes *) 
        ( buf->data_start - ( ( num_opcodes + 3 ) & ~0x3 ) - sizeof(*hdr) );

    CRASSERT( (void *) hdr >= buf->pack );

    if (pack_spu.swap)
    {
        hdr->header.type = (CRMessageType) SWAP32(CR_MESSAGE_OPCODES);
        hdr->numOpcodes  = SWAP32(num_opcodes);
    }
    else
    {
        hdr->header.type = CR_MESSAGE_OPCODES;
        hdr->numOpcodes  = num_opcodes;
    }

    *len = buf->data_current - (unsigned char *) hdr;

    return hdr;
}


/*
 * This is called from either the Pack SPU and the packer library whenever
 * we need to send a data buffer to the server.
 */
void packspuFlush(void *arg )
{
    ThreadInfo *thread = (ThreadInfo *) arg;
    ContextInfo *ctx;
    unsigned int len;
    CRMessageOpcodes *hdr;
    CRPackBuffer *buf;
	static int flag = 600;

	//crDebug("#zr# : packspuFlush enter 1");
	crBeforeWirteBackTest();
	//crDebug("#zr# : packspuFlush enter 2");
    /* we should _always_ pass a valid <arg> value */
    CRASSERT(thread && thread->inUse);
#ifdef CHROMIUM_THREADSAFE
    CR_LOCK_PACKER_CONTEXT(thread->packer);
#endif
    ctx = thread->currentContext;
    buf = &(thread->buffer);
    CRASSERT(buf);

    if (ctx && ctx->fCheckZerroVertAttr)
        crStateCurrentRecoverNew(ctx->clientState, &thread->packer->current);

    /* We're done packing into the current buffer, unbind it */
    crPackReleaseBuffer( thread->packer );

    /*
    printf("%s thread=%p thread->id = %d thread->pc=%p t2->id=%d t2->pc=%p packbuf=%p packbuf=%p\n",
           __FUNCTION__, (void*) thread, (int) thread->id, thread->packer,
           (int) t2->id, t2->packer,
           buf->pack, thread->packer->buffer.pack);
    */

    if ( buf->opcode_current == buf->opcode_start ) {
           /*
           printf("%s early return\n", __FUNCTION__);
           */
           /* XXX these calls seem to help, but might be appropriate */
           crPackSetBuffer( thread->packer, buf );
           crPackResetPointers(thread->packer);
#ifdef CHROMIUM_THREADSAFE
           CR_UNLOCK_PACKER_CONTEXT(thread->packer);
#endif
           return;
    }

    hdr = __prependHeader( buf, &len, 0 );

    CRASSERT( thread->netServer.conn );

    if ( buf->holds_BeginEnd )
    {
        /*crDebug("crNetBarf %d, (%d)", len, buf->size);*/
        crNetBarf( thread->netServer.conn, &(buf->pack), hdr, len );
    }
    else
    {
		    if(0){
				LogPrint("stone conn:%d Send data use VIO In packspuFlush() and len %d", 
					thread->netServer.conn->tcp_socket, len);
		        crNetSend_VIO(thread->netServer.conn, &(buf->pack), hdr, len );
		    }else{
			    crNetSend( thread->netServer.conn, &(buf->pack), hdr, len );
		    }
			
    }

    buf->pack = crNetAlloc( thread->netServer.conn );

    /* The network may have found a new mtu */
    buf->mtu = thread->netServer.conn->mtu;

    crPackSetBuffer( thread->packer, buf );

    crPackResetPointers(thread->packer);

#ifdef CHROMIUM_THREADSAFE
    CR_UNLOCK_PACKER_CONTEXT(thread->packer);
#endif
}


/**
 * XXX NOTE: there's a lot of duplicate code here common to the
 * pack, tilesort and replicate SPUs.  Try to simplify someday!
 */
void packspuHuge( CROpcode opcode, void *buf )
{
    GET_THREAD(thread);
    unsigned int          len;
    unsigned char        *src;
    CRMessageOpcodes *msg;

    CRASSERT(thread);

    /* packet length is indicated by the variable length field, and
       includes an additional word for the opcode (with alignment) and
       a header */
    len = ((unsigned int *) buf)[-1];
    if (pack_spu.swap)
    {
        /* It's already been swapped, swap it back. */
        len = SWAP32(len);
    }
    len += 4 + sizeof(CRMessageOpcodes);

    /* write the opcode in just before the length */
    ((unsigned char *) buf)[-5] = (unsigned char) opcode;

    /* fix up the pointer to the packet to include the length & opcode
       & header */
    src = (unsigned char *) buf - 8 - sizeof(CRMessageOpcodes);

    msg = (CRMessageOpcodes *) src;

    if (pack_spu.swap)
    {
        msg->header.type = (CRMessageType) SWAP32(CR_MESSAGE_OPCODES);
        msg->numOpcodes  = SWAP32(1);
    }
    else
    {
        msg->header.type = CR_MESSAGE_OPCODES;
        msg->numOpcodes  = 1;
    }

    CRASSERT( thread->netServer.conn );
    crNetSend( thread->netServer.conn, NULL, src, len );
}

static void packspuFirstConnectToServer( CRNetServer *server
#if defined(VBOX_WITH_CRHGSMI) && defined(IN_GUEST)
                , struct VBOXUHGSMI *pHgsmi
#endif
        )
{
    crNetInit( packspuReceiveData, NULL );
    crNetServerConnect( server
#if defined(VBOX_WITH_CRHGSMI) && defined(IN_GUEST)
                , pHgsmi
#endif
            );
    if (server->conn)
    {
        crNetSetPid(server->conn,
#ifdef RT_OS_WINDOWS
                    GetCurrentProcessId()
#else
                    getpid()
#endif
                    );
        g_u32VBoxHostCaps = crNetHostCapsGet();
        crPackCapsSet(g_u32VBoxHostCaps);
    }
}

void packspuConnectToServer( CRNetServer *server
#if defined(VBOX_WITH_CRHGSMI) && defined(IN_GUEST)
                , struct VBOXUHGSMI *pHgsmi
#endif
        )
{
    if (pack_spu.numThreads == 0) {
        packspuFirstConnectToServer( server
#if defined(VBOX_WITH_CRHGSMI) && defined(IN_GUEST)
                , pHgsmi
#endif
                );
        if (!server->conn) {
            crError("packspuConnectToServer: no connection on first create!");
            return;
        }
        pack_spu.swap = server->conn->swap;
    }
    else {
        /* a new pthread */
        crNetNewClient(pack_spu.thread[0].netServer.conn, server
#if defined(VBOX_WITH_CRHGSMI) && defined(IN_GUEST)
                , pHgsmi
#endif
        );
    }
}
