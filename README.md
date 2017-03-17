![BlackHat Briefings 2017](https://img.shields.io/badge/BlackHat-Briefings%202017-orange.svg?style=flat) ![BlackHat Arsenal 2016](https://img.shields.io/badge/BlackHat-Arsenal%202016-yellow.svg?style=flat)
![License](https://img.shields.io/badge/License-BSD%203-red.svg?style=flat) ![PowerShell](https://img.shields.io/badge/Language-PowerShell-blue.svg?style=flat) ![Twitter](https://img.shields.io/badge/twitter-@pabraeken-blue.svg?style=flat)
# PowerMemory
Exploit the credentials present in files and memory

PowerMemory levers Microsoft signed binaries to hack Microsoft operating systems.

## What's New?
The method is totally new. It proves that it can be extremely easy to get credentials or any other information from Windows memory without needing to code in C-type languages. In addition, with this method we can modify the user land and kernel land behavior without being caught by antivirus or new defending techniques.
 
It can actually be done with 4GL language-type or with a script language like PowerShell which is installed everywhere. 
 
With that being said, this technique implies that the detection is made hard due to the fact that we can do pretty much what we want by sending and receiving bytes.

## User land attacks
- Once the Debugger is initialized, PowerMemory interacts with it thanks to PowerShell.

### User land deatures:
* it's fully written in PowerShell
* it can work locally as well as remotely
* it can get the passwords of virtual machines without having any access to them (works for Hyper-V and VMware)
* it does not use the operating system .dll to locate credentials address in memory but a Microsoft Signed Debugger
* it does not use the operating system .dll to decipher passwords collected. PowerMemory maps the keys in the memory and cracks everything by itself (AES, TripleDES, DES-X)
* it breaks undocumented Microsoft DES-X
* it works even if you are on a different architecture than the target architecture
* it leaves no trace in memory
* a pull request is waiting to be integrated in PowerShell Empire (https://github.com/PowerShellEmpire/Empire/pull/298)
* it can manipulate memory to fool software and operating system
* it can write the memory to execute shellcode without making any API call, it only sends bytes to write at specific addresses

### Advanced shellcode writings
- PowerMemory executes code by injecting bytes into a remote process and without help of API.

## Hypervisor attacks
- A hypervisor (VMWare or Microsoft Hyper-v) operator who does not own any rights into the Virtual Machines managed by the Hypervisor is, actually, the most powerful person in your organization. PowerMemory can get all the Virtual Machines passwords and lever the concept to get Domain Admin credentials.

## Kernel land attacks
- PowerMemory modifies Kernel structures to get advantages of the Operating System in order to achieve advanced persistence or elevate our privileges.

## Real world – weaponization
- You can use the module waiting to be integrated to leave Wonder Land and launch a crafted advanced attack with PowerShell Empire serving as the vector. 
