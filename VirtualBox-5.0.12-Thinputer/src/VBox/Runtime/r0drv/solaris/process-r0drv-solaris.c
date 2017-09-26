/* $Id: process-r0drv-solaris.c $ */
/** @file
 * IPRT - Process Management, Ring-0 Driver, Solaris.
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
#include "the-solaris-kernel.h"
#include "internal/iprt.h"
#include <iprt/process.h>



RTDECL(RTPROCESS) RTProcSelf(void)
{
    return ddi_get_pid();
}


RTR0DECL(RTR0PROCESS) RTR0ProcHandleSelf(void)
{
    proc_t *pProcess = NULL;
    drv_getparm(UPROCP, &pProcess);
    return (RTR0PROCESS)pProcess;
}
