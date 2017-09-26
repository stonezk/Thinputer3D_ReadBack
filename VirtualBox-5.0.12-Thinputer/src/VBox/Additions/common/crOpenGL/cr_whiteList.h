/*   Author : HYJ
 *   Date:    2015.09.24
 *   test APP is in the process list
 */
#ifndef    __CR_WHITELIST_H_
#define    __CR_WHITELIST_H_ 

#include <windows.h>
#include <stdio.h>

#ifndef DEBUG_MODE
#define DEBUG_MODE
#define LOG_DEBUG(str) OutputDebugString(str)
#endif

#define PATH_LENGTH 64
BOOL CompareProcessWith3DList(char * src,char list[])
{
     int i = 0,length=0;
	 if(!src)
	    return FALSE;
	 if(!(length=strlen(src)))
	    return FALSE;
	/*length-4 to avoid ".exe" */
	 for(i;i<length-4;i++)
	 {
	    if((*(src+i) != list[i])&&(*(src+i) != list[i]-32)&&(*(src+i)!= list[i]+32))
		{
		 return FALSE;
		}
	 }
	 return TRUE;
	 
}

int SystemIs64Bit()
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
			//system is 64bit 
			is64bit = 1;
	} 
	else 
	{ 
			//system is 32bit
			is64bit = 0;
	}
	return is64bit ;

}
char* GetWhiteListPath()
{
     LONG lRet;
     HKEY hKey;
     DWORD dwBuflen = PATH_LENGTH;
     char * path;
     char regpath[PATH_LENGTH];
     char * listpath = "\\whitelist3D.ini";
	 if(SystemIs64Bit()){ 
		if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SOFTWARE\\Wow6432Node\\GUEST TOOLS",0,KEY_QUERY_VALUE,&hKey)!= ERROR_SUCCESS)
     	{
        	LOG_DEBUG("##Open the Reg Get WhiteList Path Error##");
        	return NULL;
     	}
	 }else{
     	if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SOFTWARE\\GUEST TOOLS",0,KEY_QUERY_VALUE,&hKey)!= ERROR_SUCCESS)
     	{
        	LOG_DEBUG("##Open the Reg Get WhiteList Path Error##");
        	return NULL;
     	}
	 }
     lRet = RegQueryValueExA(hKey,"InstallPath",NULL,NULL,(LPBYTE)regpath,&dwBuflen);
     if(lRet != ERROR_SUCCESS)
     {
         LOG_DEBUG("##Failed to get the WhiteList path##");
         return 0;
     }
     RegCloseKey(hKey);
     path=(char*)malloc(strlen(regpath)+strlen(listpath)+1);
	 if(!path)
         LOG_DEBUG("##malloc mem for WhiteList path failed##");
     strcpy(path,regpath);
     strcat(path,listpath);
     return path; 
}
BOOL checkAppInwhitelist()
{
    
    FILE *fp;
    char *temp="0";
	char *appName="0";
	char appPath[MAX_PATH]={0};
	char *file_path = NULL;
	//char *file_path = GetWhiteListPath();
    char whiteList[MAX_PATH]={0};
	BOOL result = FALSE;

	if(!GetModuleFileNameA(NULL,appPath,MAX_PATH))
    { 
	   LOG_DEBUG("##Failed to Get 3D process path##");
       return FALSE;
    }
    temp = strtok(appPath,"\\");
    while(temp)
    {
        appName = temp;
        temp =strtok(NULL,"\\");
    }
#ifdef DEBUG_MODE
    //appName = "DEBUG_MODE";
#endif
	file_path = GetWhiteListPath();
	if(file_path){
		if(GetPrivateProfileInt("DEBUG", "support", 0, file_path)){
			LogPrint("##This is DEBUG_MODE##");
			free(file_path);
			return TRUE;
		}else{
			if(GetPrivateProfileInt(appName, "support", 0, file_path)){
				LogPrint("##Currently Support APP:%s", appName);
				free(file_path);
				return TRUE;
			}else{
	    		LogPrint("##Currently not support 3D APP:%s and error:%lu##", appName, GetLastError());
				free(file_path);
				return FALSE;
			}
		}
	}else{
		LogPrint("##Get config file whitelist3D.ini's path Failed##");
		return FALSE;
	}
    if((fp=fopen(file_path,"r"))==NULL)
    {
	    LOG_DEBUG("##Failed to open the whitelist3D##");
        return FALSE;
    }
    while(fgets(whiteList,MAX_PATH,fp)!=NULL)
    {
       int templength=0;
       // DEBUG_MODE can run the 3D without 3Dlist
#ifdef DEBUG_MODE
       if(CompareProcessWith3DList("DEBUG_MODE",whiteList))
       {
        return TRUE;
       }
#endif
       //compare length
       templength = strlen(appName);
       if((strlen(whiteList)==templength-4)||(whiteList[templength-4]==0x0a))
       {
        result = CompareProcessWith3DList(appName,whiteList);
        if(result)
            break;
       }else
       {
        LOG_DEBUG("appName is different with whiteList!");
        continue;
       }
    }
	fclose(fp);               
	if(result)
     return TRUE;
	LOG_DEBUG("Currently not support 3D acceleartor!!!");
    return FALSE;
}
#endif  
