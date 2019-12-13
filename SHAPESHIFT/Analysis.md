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
