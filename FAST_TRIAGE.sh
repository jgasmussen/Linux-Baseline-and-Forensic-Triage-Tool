#!/bin/bash

######################################################
#  Linux Baseline & Forensic Triage Collection Tool  #
#----------------------------------------------------#
#           Written by: John G. Asmussen             #
#         EGA Technology Specialists, LLC.           #
#                     (c) 2021                       #
######################################################



#List of file(s) to collect:

FILES="/home /var/log"



#Destination location of collected info/file(s).

DEST="/mnt/FORENSICS/"



#Create the file name of collection file(s).

day=$(date +"%m-%d-%Y")
hostname=$(hostname -s)
FAST_collection="$hostname.$day"
memory_image="$hostname$day.mem"
md5=$(md5sum $DEST/$memory_image)

#Create a log file of the collection process.

echo "Creating Log File..."
FAST_log="$FAST_collection.log"
touch $DEST/$FAST_log
echo "Creating Log File...DONE!"


#Print start message to screen and log file.

echo "******************************************************" >> $DEST/$FAST_log
echo "*  Linux Baseline & Forensic Triage Collection Tool  *" >> $DEST/$FAST_log
echo "*----------------------------------------------------*" >> $DEST/$FAST_log
echo "*           Written by: John G. Asmussen             *" >> $DEST/$FAST_log
echo "*         EGA Technology Specialists, LLC.           *" >> $DEST/$FAST_log
echo "*                     (c) 2021                       *" >> $DEST/$FAST_log
echo "******************************************************" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "STARTING FAST TRIAGE COLLECTION..." | tee -a $DEST/$FAST_log
date +"%m/%d/%Y %T" | tee -a $DEST/$FAST_log
echo "**************************************************************************************" >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log


#Collect Linux Memory Image using Microsoft's AVML tool.

echo "COLLECTING MEMORY IMAGE WITH MICROSOFT'S AVML..." | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
./avml $DEST/$memory_image | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "DONE!" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
sleep 5
echo "Starting MD5 HASH of the collected AVML Memory File: $memory_image ..." | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "md5sum=$(md5sum /mnt/FORENSICS/*.mem)" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "COLLECTING MEMORY IMAGE...DONE!" | tee -a $DEST/$FAST_log
sleep 5
echo "**************************************************************************************" >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log


#Collect Linux System Information

echo "COLLECTING SYSTEM INFORMATION..." | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List the host name of machine:" >> $DEST/$FAST_log
echo "hostnamectl:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
hostnamectl | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "Linux version and kernel information:" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "uname -a:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
uname -a | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of system date/time/timezone:" >> $DEST/$FAST_log
echo "timedatectl:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
timedatectl | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List uptime of machine:" >> $DEST/$FAST_log
echo "uptime:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
uptime | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List last reboot time of machine:" >> $DEST/$FAST_log
echo "last reboot:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
last reboot | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of system memory information:" >> $DEST/$FAST_log
echo "free:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
free | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of system memory information:" >> $DEST/$FAST_log
echo "cat /proc/meminfo:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
cat /proc/meminfo | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of users currently logged on:" >> $DEST/$FAST_log
echo "who -H:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
who -H | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of ALL accounts on the machine:" >> $DEST/$FAST_log
echo "cat /etc/passwd:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
cat /etc/passwd | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of ALL groups:" >> $DEST/$FAST_log
echo "cat /etc/group:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
cat /etc/group | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "Sudoers config file:" >> $DEST/$FAST_log
echo "cat /etc/sudoers:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
cat /etc/sudoers | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "Crontab config file:" >> $DEST/$FAST_log
echo "cat /etc/crontab:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
cat /etc/crontab | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of hardware properties as reported by OS (Double Check This Info!):" >> $DEST/$FAST_log
echo "lshw:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
lshw | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of CPU's properties and architecture as reported by OS (Double Check This Info!):" >> $DEST/$FAST_log
echo "lscpu:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
lscpu | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of all block devices:" >> $DEST/$FAST_log
echo "lsblk -a:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
lsblk -a | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of USB devices and properties:" >> $DEST/$FAST_log
echo "lsusb -v:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
lsusb -v | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of PCI devices and properties:" >> $DEST/$FAST_log
echo "lspci -v:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
lspci -v | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of SCSI devices and properties:" >> $DEST/$FAST_log
echo "lsscsi -s:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
lsscsi -s | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of hard drives and properties:" >> $DEST/$FAST_log
echo "fdisk -l:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
fdisk -l | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of mountable partitions by GRUB:" >> $DEST/$FAST_log
echo "blkid:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
blkid | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of mounted file systems:" >> $DEST/$FAST_log
echo "df -h:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
df -h | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of ALL mount points on the machine:" >> $DEST/$FAST_log
echo "cat /proc/mounts:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
cat /proc/mounts | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "COLLECTING SYSTEM INFORMATION... DONE!" | tee -a $DEST/$FAST_log
echo "**************************************************************************************" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log


#Collect Running Processes.

echo "**************************************************************************************" >> $DEST/$FAST_log
echo "COLLECTING LIST OF PROCESSES..." >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List running processes:" >> $DEST/$FAST_log
echo "ps -auxwf" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
ps -auxwf | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List all processes running from /tmp or /dev directory:" >> $DEST/$FAST_log
echo "ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev"" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of deleted binaries still running:" >> $DEST/$FAST_log
echo "ls -alR /proc/*exe 2> /dev/null | grep deleted" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
ls -alR /proc/*/exe 2> /dev/null | grep deleted | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List process command name:" >> $DEST/$FAST_log
echo "strings /proc/*/comm" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
strings /proc/*/comm | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List process commandline:" >> $DEST/$FAST_log
echo "strings /proc/*/cmdline" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
strings /proc/*/cmdline | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List process working directory:" >> $DEST/$FAST_log
echo "ls -alR /proc/*/cwd" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
ls -alR /proc/*/cwd | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List process path:" >> $DEST/$FAST_log
echo "ls -al /proc/*/exe" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
ls -al /proc/*/exe | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of startup services at boot:" >> $DEST/$FAST_log
echo "systemctl list-unit-files --type=service" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
systemctl list-unit-files --type=service | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of services and their status:" >> $DEST/$FAST_log
echo "service --status-all:" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
service --status-all | tee -a  $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "COLLECTING LIST OF PROCESSES... DONE!" >> $DEST/$FAST_log
echo "**************************************************************************************" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log


#Collect Network Information.

echo "**************************************************************************************" >> $DEST/$FAST_log
echo "COLLECTING NETWORK INFORMATION..." | tee -a $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of network interfaces:" >> $DEST/$FAST_log
echo "ifconfig -a" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
ifconfig -a | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of UFW ('uncomplicated firewall') rules:" >> $DEST/$FAST_log
echo "ufw status verbose" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
ufw status verbose | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of iptables (packet filter rules for the Linux Kernel firewall):" >> $DEST/$FAST_log
echo "iptables -L" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
iptables -L | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of open files on the system and the process ID that opened them:" >> $DEST/$FAST_log
echo "lsof" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
lsof | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of open network ports or raw sockets:" >> $DEST/$FAST_log
echo "ss -a -e -i" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
ss -a -e -i | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of network connections:" >> $DEST/$FAST_log
echo "netstat -nalp" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
netstat -nalp | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of network connections:" >> $DEST/$FAST_log
echo "netstat -plant" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
netstat -plant | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of the ARP table cache (Address Resolution Protocol):" >> $DEST/$FAST_log
echo "arp -a" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
arp -a | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "COLLECTING NETWORK INFORMATION... DONE!" | tee -a $DEST/$FAST_log
echo "**************************************************************************************" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log


#Create a directory listing of ALL files.

echo "**************************************************************************************" >> $DEST/$FAST_log
echo "CREATING DIRECTORY LISTING OF FILES..." | tee -a $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of ALL files and directories:" >> $DEST/$FAST_log
echo "ls -l -a -h -i -R /" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
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
echo "See $hostname-Directory_Listing.txt for a complete directory listing." >> /mnt/FORENSISCS/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List ALL hidden directories:" >> $DEST/$FAST_log
echo "find / -type d -name '\.*'" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
find / -type d -name "\.*" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of immutable files and directories:" >> $DEST/$FAST_log
echo "lsattr / -R 2> /dev/null | grep "\----i"" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
lsattr / -R 2> /dev/null | grep "\----i" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of SUID/SGID files:" >> $DEST/$FAST_log
echo "find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls-lg {} \;" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls-lg {} \; | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of files/directories with no user/group name:" >> $DEST/$FAST_log
echo "find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List of MD5 hash for all executable files:" >> $DEST/$FAST_log
echo "find /usr/bin -type f -exec file "{}" \; | grep -i "elf" | cut -f1 -d: | xargs -I "{}" -n 1 md5sum {} " | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
find /usr/bin -type f -exec file "{}" \; | grep -i "elf" | cut -f1 -d: | xargs -I "{}" -n 1 md5sum {} | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "List ALL log files that contain binary code inside:" >> $DEST/$FAST_log
echo "grep [[:cntrl:]] /var/log/*.log" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
grep [[:cntrl:]] /var/log/*.log | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "CREATING DIRECTORY LISTING OF FILES... DONE!" | tee -a $DEST/$FAST_log
echo "**************************************************************************************" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log


Create a forensic image of specific files

echo "**************************************************************************************" >> $DEST/$FAST_log
echo "COPYING FORENSIC TRIAGE FILES..." | tee -a $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "tar -create --verbose --verbose --verbose --preserve-permissions --acls --xattrs --atime-preserve=system --full-time -f $FAST_collection.tar $FILES" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
tar -c -vvv -p --acls --xattrs --atime-preserve=system --full-time -f $DEST/$FAST_collection.tar $FILES | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "Starting MD5 HASH of Triage Collection File: $FAST_collection.tar ..." | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "md5sum=$(md5sum /mnt/FORENSICS/*.tar)" | tee -a $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo "======================================================================================" >> $DEST/$FAST_log
echo "COPYING FORENSIC TRIAGE FILES... DONE!" | tee -a $DEST/$FAST_log
echo "**************************************************************************************" >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log
echo " " >> $DEST/$FAST_log



#Print finish message to screen and log.

echo "FAST TRIAGE COLLECTION COMPLETE!" | tee -a $DEST/$FAST_log
date +"%m/%d/%Y %T" | tee -a $DEST/$FAST_log
exit
