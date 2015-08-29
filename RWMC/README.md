#Disclaimer

Any actions and or activities related to the material contained within this blog is solely your responsibility.The misuse of the information in this website can result in criminal charges brought against the persons in question. The authors will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this website to break the law.

This script is published for educational use only. I am no way responsible for any misuse of the information.

This article is related to Computer Security and I am not promote hacking / cracking / software piracy.

This article is not a GUIDE of Hacking. It is only provide information about the legal ways of retrieving the passwords. You shall not misuse the information to gain unauthorised access. However you may try out these hacks on your own computer at your own risk. Performing hack attempts (without permission) on computers that you do not own is illegal.

#RWMC
Powershell - Reveal Windows Memory Credentials

The purpose of this script is to make a proof of concept of how retrieve Windows credentials with Powershell and CDB Command-Line Options (Windows Debuggers)

It allows to retrieve credentials from windows 2003 to 2012 and Windows 10 (it was tested on 2003, 2008r2, 2012, 2012r2 and Windows 7 - 32 and 64 bits, Windows 8 and Windows 10 Home edition).

It works even if you are on another architecture than the system targeted.

#How to use it ?
http://sysadminconcombre.blogspot.ca/2015/07/how-to-hack-windows-password.html

#Quick usage
Launch the script (example for a D:\2008_20150618154432\lsass.dmp from a 2008r2 server)

\ \ /\ Follow the white Rabbit :-) ( ) Pierre-Alexandre Braeken .( @ ).

Local computer, Remote computer or from a dump file ? (local, remote, dump): local [enter]

--> a notepad open with the credentials found

#Features
* it's fully PowerShell
* it can work locally, remotely or from a dump file collected on a machine
* it does not use the operating system .dll to locate credentials address in memory but a simple Microsoft debugger
* it does not use the operating system .dll to decypher passwords collected --> it is does in the PowerShell (AES, TripleDES, DES-X)
* it breaks undocumented Microsoft DES-X
* it works even if you are on a different architecture than the target
* it leaves no trace in memoryless

#How to use it for Windows 2012R2 or Windows 10?
1) Retrieve remotely: 

	* Launch the script 
	* Local computer, Remote computer or from a dump file ? (local, remote, dump): remote [enter]
	* serverName [enter] 

2) From a dump: if you have to dump the lsass process of a target machine, you can execute the script with option ( ! name you lsass dump "lsass.dmp" and don't enter the name for the option you enter, only the directory !) :

	* Launch the script 
	* Local computer, Remote computer or from a dump file ? (local, remote, dump): dump [enter]
	* d:\directory_of_the_dump [enter] 

3) Locally :

	* Launch the script 
	* Local computer, Remote computer or from a dump file ? (local, remote, dump): local [enter]

#Never ever give administrator access to your user
Always audit what you sysadmin or provider are doing on your systems
To run effectively this script you need two things :

#To run effectively this script you need :

* PowerShell 3
* Allow PowerShell script on you machine, example : Set-ExecutionPolicy Unrestricted -force
* An Internet connection
* The script was tested on a 7 and on a 8 machine to retrieve password from Windows Server 2003,2008R2,2012,2012R2,7 and 8 and 10.

#Get local Administrator password from Group Policy Preferences
Launch Get-LocalAdminGPPAccess.ps1 script