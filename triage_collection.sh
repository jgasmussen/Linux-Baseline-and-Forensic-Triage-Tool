#!/bin/bash

######################################################
#  Linux Baseline & Forensic Triage Collection Tool  #
#----------------------------------------------------#
#           Written by: John G. Asmussen             #
#         EGA Technology Specialists, LLC.           #
#                     (c) 2021                       #
######################################################

#List of file(s) to collect:

FILES="/boot /etc /home /root /var/lib /var/log"



#Destination location of collected info/file(s).

DEST="$DEST"



#Create the file name of collection file(s).

day=$(date +"%m-%d-%Y")
hostname=$(hostname -s)
FULL_collection="$hostname.$day"
memory_image="$hostname$day.mem"


#Create a log file of the collection process.

echo "Creating Log File..."
FULL_log="$FULL_collection.log"
touch $DEST/$FULL_log
echo "Creating Log File...DONE!"


#Print start message to screen and log file.

echo "******************************************************" >> $DEST/$FULL_log
echo "*  Linux Baseline & Forensic Triage Collection Tool  *" >> $DEST/$FULL_log
echo "*----------------------------------------------------*" >> $DEST/$FULL_log
echo "*           Written by: John G. Asmussen             *" >> $DEST/$FULL_log
echo "*         EGA Technology Specialists, LLC.           *" >> $DEST/$FULL_log
echo "*                     (c) 2021                       *" >> $DEST/$FULL_log
echo "******************************************************" >> $DEST/$FULL_log
echo " " >> $DEST/$FULL_log
echo " " >> $DEST/$FULL_log
echo " " >> $DEST/$FULL_log
echo "STARTING TRIAGE COLLECTION..." | tee -a $DEST$FULL_log
date +"%m/%d/%Y %T" | tee -a $DEST$FULL_log
echo "**************************************************************************************" >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log


#Collect Linux Memory Image using Microsoft's AVML tool.

echo "COLLECTING MEMORY IMAGE WITH MICROSOFT'S AVML..." | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
./avml $DEST$memory_image | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "Starting MD5 HASH of the collected AVML Memory File: $memory_image ..." | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "md5sum=$(md5sum $DEST/$memory_image)" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "COLLECTING MEMORY IMAGE...DONE!" | tee -a $DEST$FULL_log
echo "**************************************************************************************" >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log


#Collect Linux System Information

echo "COLLECTING SYSTEM INFORMATION..." | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List the host name of machine:" >> $DEST$FULL_log
echo "hostnamectl:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
hostnamectl | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "Linux version and kernel information:" >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "uname -a:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
uname -a | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of system date/time/timezone:" >> $DEST$FULL_log
echo "timedatectl:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
timedatectl | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List uptime of machine:" >> $DEST$FULL_log
echo "uptime:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
uptime | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of system memory information:" >> $DEST$FULL_log
echo "free:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
free | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of system memory information:" >> $DEST$FULL_log
echo "cat /proc/meminfo:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
cat /proc/meminfo | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List last reboot time of machine:" >> $DEST$FULL_log
echo "last reboot:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
last reboot | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of users currently logged on:" >> $DEST$FULL_log
echo "who -H:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
who -H | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of ALL accounts on the machine:" >> $DEST$FULL_log
echo "cat /etc/passwd:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
cat /etc/passwd | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of ALL groups used by the user:" >> $DEST$FULL_log
echo "cat /etc/group:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
cat /etc/group | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "Sudoers config file and a list of users with sudo access:" >> $DEST$FULL_log
echo "cat /etc/sudoers:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
cat /etc/sudoers | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of ALL accounts on the machine:" >> $DEST$FULL_log
echo "cat /etc/crontab:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
cat /etc/crontab | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of hardware properties as reported by OS (Double Check This Info!):" >> $DEST$FULL_log
echo "lshw:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
lshw | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of CPU's properties and architecture as reported by OS (Double Check This Info!):" >> $DEST$FULL_log
echo "lscpu:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
lscpu | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of all block devices:" >> $DEST$FULL_log
echo "lsblk -a:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
lsblk -a | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of USB devices and properties:" >> $DEST$FULL_log
echo "lsusb -v:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
lsusb -v | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of PCI devices and properties:" >> $DEST$FULL_log
echo "lspci -v:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
lspci -v | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of SCSI devices and properties:" >> $DEST$FULL_log
echo "lsscsi -s:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
lsscsi -s | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of hard drives and properties:" >> $DEST$FULL_log
echo "fdisk -l:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
fdisk -l | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of mountable partitions by GRUB:" >> $DEST$FULL_log
echo "blkid:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
blkid | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of mounted file systems:" >> $DEST$FULL_log
echo "df -h:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
df -h | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of ALL mount points on the machine:" >> $DEST$FULL_log
echo "cat /proc/mounts:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
cat /proc/mounts | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "COLLECTING SYSTEM INFORMATION... DONE!" | tee -a $DEST$FULL_log
echo "**************************************************************************************" >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log


#Collect Running Processes.

echo "**************************************************************************************" >> $DEST$FULL_log
echo "COLLECTING LIST OF PROCESSES..." >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of running processes with PID and numerically sorted:" >> $DEST$FULL_log
echo "pstree -pn" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
pstree -p -n | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of running processes in tree format w/ command line arguments:" >> $DEST$FULL_log
echo "pstree -a" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
pstree -a | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List running processes:" >> $DEST$FULL_log
echo "ps -auxwf" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
ps -auxwf | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List all processes running from /tmp or /dev directory:" >> $DEST$FULL_log
echo "ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev"" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of deleted binaries still running:" >> $DEST$FULL_log
echo "ls -alR /proc/*exe 2> /dev/null | grep deleted" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
ls -alR /proc/*/exe 2> /dev/null | grep deleted | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List process command name:" >> $DEST$FULL_log
echo "strings /proc/*/comm" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
strings /proc/*/comm | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List process commandline:" >> $DEST$FULL_log
echo "strings /proc/*/cmdline" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
strings /proc/*/cmdline | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List process working directory:" >> $DEST$FULL_log
echo "ls -alR /proc/*/cwd" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
ls -alR /proc/*/cwd | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List process path:" >> $DEST$FULL_log
echo "ls -al /proc/*/exe" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
ls -al /proc/*/exe | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of startup services at boot:" >> $DEST$FULL_log
echo "systemctl list-unit-files --type=service" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
systemctl list-unit-files --type=service | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of services and their status:" >> $DEST$FULL_log
echo "service --status-all:" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
service --status-all | tee -a  $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "COLLECTING LIST OF PROCESSES... DONE!" >> $DEST$FULL_log
echo "**************************************************************************************" >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log


#Collect Network Information.

echo "**************************************************************************************" >> $DEST$FULL_log
echo "COLLECTING NETWORK INFORMATION..." | tee -a $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of network interfaces:" >> $DEST$FULL_log
echo "ifconfig -a" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
ifconfig -a | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of UFW ('uncomplicated firewall') rules:" >> $DEST$FULL_log
echo "ufw status verbose" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
ufw status verbose | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of iptables (packet filter rules for the Linux Kernel firewall):" >> $DEST$FULL_log
echo "iptables -L" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
iptables -L | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of open files on the system and the process ID that opened them:" >> $DEST$FULL_log
echo "lsof" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
lsof | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of open network ports or raw sockets:" >> $DEST$FULL_log
echo "ss -a -e -i" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
ss -a -e -i | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of network connections:" >> $DEST$FULL_log
echo "netstat -a" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
netstat -a | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of network connections:" >> $DEST$FULL_log
echo "netstat -i" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
netstat -i | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of network connections:" >> $DEST$FULL_log
echo "netstat -r" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
netstat -r | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of network connections:" >> $DEST$FULL_log
echo "netstat -nalp" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
netstat -nalp | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of network connections:" >> $DEST$FULL_log
echo "netstat -plant" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
netstat -plant | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of the ARP table cache (Address Resolution Protocol):" >> $DEST$FULL_log
echo "arp -a" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
arp -a | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "COLLECTING NETWORK INFORMATION... DONE!" | tee -a $DEST$FULL_log
echo "**************************************************************************************" >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log


#Create a directory listing of ALL files.

echo "**************************************************************************************" >> $DEST/$FULL_log
echo "CREATING DIRECTORY LISTING OF FILES..." | tee -a $DEST/$FULL_log
echo "======================================================================================" >> $DEST/$FULL_log
echo "List of ALL files and directories:" >> $DEST/$FULL_log
echo "ls -l -a -h -i -R /" >> $DEST/$FULL_log
echo " " >> $DEST/$FULL_log
touch $DEST/$hostname-Directory_Listing.txt
echo "******************************************************" >> $hostname-Directory_Listing.txt
echo "*  Linux Baseline & Forensic Triage Collection Tool  *" >> $hostname-Directory_Listing.txt
echo "*----------------------------------------------------*" >> $hostname-Directory_Listing.txt
echo "*           Written by: John G. Asmussen             *" >> $hostname-Directory_Listing.txt
echo "*         EGA Technology Specialists, LLC.           *" >> $hostname-Directory_Listing.txt
echo "*                     (c) 2021                       *" >> $hostname-Directory_Listing.txt
echo "******************************************************" >> $hostname-Directory_Listing.txt
echo " " >> $hostname-Directory_Listing.txt
echo "DIRECTORY LISTING OF $FAST_collection" >> $hostname-Directory_Listing.txt
echo " " >> $hostname-Directory_Listing.txt
hostnamectl  >> $DEST/$hostname-Directory_Listing.txt
date +"%m/%d/%Y %T" >> $DEST/$hostname-Directory_Listing.txt
echo " " >> $DEST/$hostname-Directory_Listing.txt
echo "CREATE LIST OF ALL FILES AND DIRECTORIES ON $hostname:" >> $DEST/$hostname-Directory_Listing.txt
ls -l -a -h -R / >> $DEST/$hostname-Directory_Listing.txt
echo " " >> $DEST/$hostname-Directory_Listing.txt
echo "DONE! " >> $DEST/$hostname-Directory_Listing.txt
date +"%m/%d/%Y %T" >> $DEST/$hostname-Directory_Listing.txt
echo "See $hostname-Directory_Listing.txt for a complete directory listing." >> /mnt/FORENSISCS/$FULL_log
echo " " >> $DEST/$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List ALL hidden directories:" >> $DEST$FULL_log
echo "find / -type d -name '\.*'" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
find / -type d -name "\.*" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of immutable files and directories:" >> $DEST$FULL_log
echo "lsattr / -R 2> /dev/null | grep "\----i"" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
lsattr / -R 2> /dev/null | grep "\----i" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of SUID/SGID files:" >> $DEST$FULL_log
echo "find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls-lg {} \;" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls-lg {} \; | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of files/directories with no user/group name:" >> $DEST$FULL_log
echo "find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List of MD5 hash for all executable files:" >> $DEST$FULL_log
echo "find /usr/bin -type f -exec file "{}" \; | grep -i "elf" | cut -f1 -d: | xargs -I "{}" -n 1 md5sum {} " | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
find /usr/bin -type f -exec file "{}" \; | grep -i "elf" | cut -f1 -d: | xargs -I "{}" -n 1 md5sum {} | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "List ALL log files that contain binary code inside:" >> $DEST$FULL_log
echo "grep [[:cntrl:]] /var/log/*.log" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
grep [[:cntrl:]] /var/log/*.log | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "CREATING DIRECTORY LISTING OF FILES... DONE!" | tee -a $DEST$FULL_log
echo "**************************************************************************************" >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log


#Create a forensic image of specific files

echo "**************************************************************************************" >> $DEST$FULL_log
echo "COPYING FORENSIC TRIAGE FILES..." | tee -a $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "tar -create --verbose --verbose --verbose --preserve-permissions --acls --xattrs --atime-preserve=system --full-time -f $FULL_collection.tar $FILES" | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
tar -c -vvv -p --acls --xattrs --atime-preserve=system --full-time -f $DEST$FULL_collection.tar $FILES | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "Starting  MD5 HASH of Triage Collection File: $FULL_collection.tar ..." | tee -a $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo "md5sum=$(md5sum $DEST/$FULL_collection)" | tee -a $DEST/$FULL_log
echo " " >> $DEST$FULL_log
echo "======================================================================================" >> $DEST$FULL_log
echo "COPYING FORENSIC TRIAGE FILES... DONE!" | tee -a $DEST$FULL_log
echo "**************************************************************************************" >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log
echo " " >> $DEST$FULL_log


#Print finish message to screen and log.
echo "FULL COLLECTION COMPLETE!" | tee -a $DEST$FULL_log
date +"%m/%d/%Y %T" | tee -a $DEST$FULL_log
exit
