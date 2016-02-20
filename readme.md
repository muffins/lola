## CSAW High School Forensics Challenge - Lola Malware

### This code was written for the 2015 CSAW High School Forensics Prelims

### About


Lola should be pretty strait forward to use.  Just running lola.exe

The first step in lola's execution is to 'hide' from the user.  Lola accomplishes this by copying herself to the users local roaming application data folder, C:\\Users\\<user>\\AppData\\Roaming\\, and sets the hidden attribute.  it will then delete the currently running location.

After Lola has hidden, she will then attempt to persist across reboots.  She does this by setting the registry key HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.  We do this as this registry key does not require administrative priviledges to set.  We set this key to be the application data location from the 'hide' phase of lola.

Once this phase is complete, Lola will attempt to beacon out to the C2 domain.  Lola will continue to beacon out while she is executing, and currently her only execution is to open a picture of Lola that is downloaded from the C2 server.  Grabs some local host data which she sends out to the C2, currently this data is the machines local IP address, as well as the machines MAC address, and an encrypted 'flag' value.  All of this data is sent over InternetOpenA, which at the time of the challenge was HTTPS as the server hosting the C2 data was running HTTPS.  

Lola will download a file from the C2 server and read the configuration data, and then return to the primary malware loop.


### Uninstallation

To remove lola from your system, simply delete the registry key described above, remove the lola.exe 'hidden' file from the Romain APPDATA folder, and kill the lola.exe process int he task manager.
