/* Author: QH
 * Date  : 2015.06.12
 * 
 * This file provide extra function
 *
 */

#ifndef __CR_HELPER_H__
#define __CR_HELPER_H__

#define LOG_DEBUG(str) OutputDebugString(str)
#define PIPE_NAME TEXT("\\\\.\\pipe\\mynamedpipe")
#ifdef RT_OS_WINDOWS

#include <windows.h>
#include <stdio.h>

#include "chromium.h"

#define FILE_IP
//#define CLIENT_3D
#define RGE_PATH_LENGTH 64
#define IFLE_PATH_LENGTH 60


int Is64BitSystem()
{
	SYSTEM_INFO si;
	int    is64bit  = 0;
	HINSTANCE handle;
	FARPROC  func;

	handle = LoadLibraryA("kernel32.dll");
	if (handle)
	{
		func = GetProcAddress(handle,"GetNativeSystemInfo");
		if (func)
		{
			func(&si);
		}
		else
		{
			GetSystemInfo(&si);
		}
		FreeLibrary(handle);
	}
	else
	{
		GetSystemInfo(&si);
	}
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
			 si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ) 
	{ 
			//64 位操作系统 
			is64bit = 1;
	} 
	else 
	{ 
			// 32 位操作系统 
			is64bit = 0;
	}
	return is64bit ;

}

int GetGuestToolsFilePath( char * filename, char * path)
{
     LONG lRet;
     HKEY hKey;
     DWORD dwBuflen = RGE_PATH_LENGTH;
     char regpath[RGE_PATH_LENGTH] = {0};
	 char toolspath[RGE_PATH_LENGTH] = {0};

     if ( NULL == path )
     {
         LOG_DEBUG("The path in GetGuestToolsFilePath is Error");
         return -1;
     }
	 if(Is64BitSystem()){ 
		if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SOFTWARE\\Wow6432Node\\GUEST TOOLS",0,KEY_QUERY_VALUE,&hKey)!= ERROR_SUCCESS)
     	{
        	LOG_DEBUG("##Open the Reg Get WhiteList Path Error##");
        	return -1;
     	}
	 }else{
     	if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SOFTWARE\\GUEST TOOLS",0,KEY_QUERY_VALUE,&hKey)!= ERROR_SUCCESS)
     	{
        	LOG_DEBUG("##Open the Reg Get WhiteList Path Error##");
        	return -1;
     	}
	 }
     lRet = RegQueryValueExA(hKey,"InstallPath",NULL,NULL,(LPBYTE)regpath,&dwBuflen);
     if(lRet != ERROR_SUCCESS)
     {
         //LOG_DEBUG("Failed to get the Reg Value!!");
         LogPrint("##Failed to get the Reg Value From:%s and error:%lu", toolspath, GetLastError());
         return -1;
     }
     RegCloseKey(hKey);
     
     if ('\0' == regpath[0] || RGE_PATH_LENGTH <= strlen(regpath))
     {
         LOG_DEBUG("The regpath is Error!!");
         return -1;
     }
     strcpy(path,regpath);
     
     if ( NULL != filename && 
        (IFLE_PATH_LENGTH - RGE_PATH_LENGTH) > strlen(filename))
     {
         strcat(path,filename);
     }
     LOG_DEBUG("##Get IP Config File Path Success##");
     return 0;
}


GLboolean crGetHostFromPipe(void * pOut)
{
    HANDLE hReadNamePipe;
    DWORD dwRead = 0;
    int   pathRet = -1;
    char  filePath[IFLE_PATH_LENGTH] = {0};
    char  fileName[16] = "\\ip.txt";
    
    if(!pOut)
        return false;

    pathRet = GetGuestToolsFilePath( fileName, filePath);
	if ( 0 != pathRet )
	{
        LOG_DEBUG("##GetGuestToolsFilePath Faild !!!");
        return false;
    }
#ifdef CLIENT_3D
    if(!WaitNamedPipe(PIPE_NAME,NMPWAIT_WAIT_FOREVER))
    {
        LOG_DEBUG("Instance of the namedpipe is not existed");
        return false;
    }
    hReadNamePipe = CreateFile(PIPE_NAME,GENERIC_READ | GENERIC_WRITE,
        0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
#endif
#ifdef FILE_IP
    /* 
    LOG_DEBUG("stone yy goto CreateFileA iptxt!");
    hReadNamePipe = CreateFileA("C:\\ip.txt",GENERIC_READ,FILE_SHARE_READ,
        NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        */
    hReadNamePipe = CreateFileA(filePath,GENERIC_READ,FILE_SHARE_READ,
        NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);     
    if(hReadNamePipe == INVALID_HANDLE_VALUE)
    {
        //LOG_DEBUG("Failed to open the NamedPipe!");
        LogPrint("##Failed to open IP config file and error:%lu", GetLastError());
        return false;
    }
#endif
    if(!ReadFile(hReadNamePipe,pOut,64,&dwRead,NULL))
    {
        //LOG_DEBUG("Failed to get the data from PIPE");
        LogPrint("##Read IP config file failed and error:%lu", GetLastError());
        return false;
    }
    CloseHandle(hReadNamePipe);
    return true;
}

GLboolean crGetClientIP(void * pOut)
{
    HANDLE hReadNamePipe;
    DWORD dwRead = 0;
    
    if(!pOut)
        return false;

    if(!WaitNamedPipe(PIPE_NAME,NMPWAIT_WAIT_FOREVER))
    {
        LOG_DEBUG("Instance of the namedpipe is not existed");
        return false;
    }
    hReadNamePipe = CreateFile(PIPE_NAME,GENERIC_READ | GENERIC_WRITE,
        0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    
    if(!ReadFile(hReadNamePipe,pOut,64,&dwRead,NULL))
    {
        LOG_DEBUG("Failed to get the data from PIPE");
        return false;
    }
    LOG_DEBUG("Success to get the IP in Vdagent PIPE data!");
    CloseHandle(hReadNamePipe);
    
    //#endif
    return true;
}
#endif

#endif // __CR_HELPER_H__


