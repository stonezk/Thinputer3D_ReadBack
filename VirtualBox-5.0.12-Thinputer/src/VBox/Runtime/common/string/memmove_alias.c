/* $Id: memmove_alias.c $ */
/** @file
 * IPRT - No-CRT memmove() alias for gcc.
 */

/*
 * Copyright (C) 2006-2015 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL) only, as it comes in the "COPYING.CDDL" file of the
 * VirtualBox OSE distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 */


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#include <iprt/nocrt/string.h>
#undef memmove

#if defined(RT_OS_DARWIN) || defined(RT_OS_WINDOWS)
# ifndef __MINGW32__
#  pragma weak memmove
# endif

/* No alias support here (yet in the ming case). */
extern void *(memmove)(void *pvDst, const void *pvSrc, size_t cb)
{
    return RT_NOCRT(memmove)(pvDst, pvSrc, cb);
}

#elif __GNUC__ >= 4
/* create a weak alias. */
__asm__(".weak memmove\t\n"
        " .set memmove," RT_NOCRT_STR(memmove) "\t\n");
#else
/* create a weak alias. */
extern __typeof(RT_NOCRT(memmove)) memmove __attribute__((weak, alias(RT_NOCRT_STR(memmove))));
#endif

