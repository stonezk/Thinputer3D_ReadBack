#include "cr_packfunctions.h"
#include "cr_error.h"
#include "cr_net.h"
#include "packspu.h"
#include "packspu_proto.h"

#include "cr_spu.h"
#include "cr_mem.h" 


// Hook 215 : 
void PACKSPU_APIENTRY hook_packspu_Vertex3f( GLfloat x, GLfloat y, GLfloat z )
{
	crDebug("##zr## Hook : hook_packspu_Vertex3f");

	packspu_Vertex3f(x, y, z);
}

void PACKSPU_APIENTRY hook_packspu_Vertex3fv( const GLfloat * v )
{
	crDebug("##zr## Hook : hook_packspu_Vertex3fv");
	
	return packspu_Vertex3fv(v);
}



