#!/bin/bash

######################################################
#  Linux Baseline & Forensic Triage Collection Tool  #
#----------------------------------------------------#
#           Written by: John G. Asmussen             #
#         EGA Technology Specialists, LLC.           #
#                     (c) 2021                       #
######################################################

#Variables

DEST="/mnt/FORENSICS/"



#Create the file name of collection file(s).

day=$(date +"%m-%d-%Y")
hostname=$(hostname -s)
collection="$hostname.$day"



#Create a log file of the collection process.

echo "Creating Log File..."
baseline_collection_log="$collection.BASELINE.log"
touch $DEST/$baseline_collection_log



#Print start message to screen and log file.

echo "******************************************************" >> $DEST/$baseline_collection_log
echo "*  Linux Baseline & Forensic Triage Collection Tool  *" >> $DEST/$baseline_collection_log
echo "*----------------------------------------------------*" >> $DEST/$baseline_collection_log
echo "*           Written by: John G. Asmussen             *" >> $DEST/$baseline_collection_log
echo "*         EGA Technology Specialists, LLC.           *" >> $DEST/$baseline_collection_log
echo "*                     (c) 2021                       *" >> $DEST/$baseline_collection_log
echo "******************************************************" >> $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "STARTING BASELINE COLLECTION PROCESS..." | tee -a $DEST/$baseline_collection_log
date +"%m/%d/%Y %T" | tee -a $DEST/$baseline_collection_log
echo "**************************************************************************************" >> $DEST/$baseline_collection_log



#Collect Linux Memory Image using Microsoft's AVML tool.

echo " " >> $DEST/$baseline_collection_log
echo "COLLECTING SYSTEM INFORMATION..." | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List the host name of machine:" >> $DEST/$baseline_collection_log
echo "hostnamectl:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
hostnamectl | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "Linux version and kernel information:" >> $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "uname -a:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
uname -a | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of system date/time/timezone:" >> $DEST/$baseline_collection_log
echo "timedatectl:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
timedatectl | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List uptime of machine:" >> $DEST/$baseline_collection_log
echo "uptime:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
uptime | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of system memory information:" >> $DEST/$baseline_collection_log
echo "free:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
free | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of system memory information:" >> $DEST/$baseline_collection_log
echo "cat /proc/meminfo:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
cat /proc/meminfo | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List last reboot time of machine:" >> $DEST/$baseline_collection_log
echo "last reboot:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
last reboot | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of users currently logged on:" >> $DEST/$baseline_collection_log
echo "who -H:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
who -H | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List last system boot time:" >> $DEST/$baseline_collection_log
echo "who -b:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
who -b | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of ALL accounts on the machine:" >> $DEST/$baseline_collection_log
echo "cat /etc/passwd:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
cat /etc/passwd | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of ALL groups used by the user:" >> $DEST/$baseline_collection_log
echo "cat /etc/group:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
cat /etc/group | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "Sudoers config file and a list of users with sudo access:" >> $DEST/$baseline_collection_log
echo "cat /etc/sudoers:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
cat /etc/sudoers | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of ALL accounts on the machine:" >> $DEST/$baseline_collection_log
echo "cat /etc/crontab:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
cat /etc/crontab | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of hardware properties as reported by OS (Double Check This Info!):" >> $DEST/$baseline_collection_log
echo "lshw:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
lshw | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of CPU's properties and architecture as reported by OS (Double Check This Info!):" >> $DEST/$baseline_collection_log
echo "lscpu:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
lscpu | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of all block devices:" >> $DEST/$baseline_collection_log
echo "lsblk -a:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
lsblk -a | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of USB Devices and properties:" >> $DEST/$baseline_collection_log
echo "lsusb -v:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
lsusb -v | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of PCI devices and properties:" >> $DEST/$baseline_collection_log
echo "lspci -v:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
lspci -v | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of SCSI devices and properties:" >> $DEST/$baseline_collection_log
echo "lsscsi -s:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
lsscsi -s | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of hard drives and properties:" >> $DEST/$baseline_collection_log
echo "fdisk -l:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
fdisk -l | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of mountable partitions by GRUB:" >> $DEST/$baseline_collection_log
echo "blkid:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
blkid | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of mounted file systems:" >> $DEST/$baseline_collection_log
echo "df -h:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
df -h | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of ALL mount points on the machine:" >> $DEST/$baseline_collection_log
echo "cat /proc/mounts:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
cat /proc/mounts | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "COLLECTING SYSTEM INFORMATION... DONE!" | tee -a $DEST/$baseline_collection_log
echo "**************************************************************************************" >> $DEST/$baseline_collection_log



#Collect Running Processes.

echo " " >> $DEST/$baseline_collection_log
echo "**************************************************************************************" >> $DEST/$baseline_collection_log
echo "COLLECTING LIST OF PROCESSES..." >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List running processes with PID and numerically sorted:" >> $DEST/$baseline_collection_log
echo "pstree -pn" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
pstree -p -n | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List running processes in tree format w/ command line arguments:" >> $DEST/$baseline_collection_log
echo "pstree -a" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
pstree -a | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List running processes:" >> $DEST/$baseline_collection_log
echo "ps -axu" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
ps -axu | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List all processes running from /tmp or /dev directory:"
echo "ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev"" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of deleted binaries still running:"
echo "ls -alR /proc/*exe 2> /dev/null | grep deleted" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
ls -alR /proc/*/exe 2> /dev/null | grep deleted | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of startup services at boot:"
echo "systemctl list-unit-files --type=service" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
systemctl list-unit-files --type=service | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of services and their status:" >> $DEST/$baseline_collection_log
echo "service --status-all:" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
service --status-all | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "COLLECTING LIST OF PROCESSES... DONE!" >> $DEST/$baseline_collection_log
echo "**************************************************************************************" >> $DEST/$baseline_collection_log



#Collect Network Information.

echo " " >> $DEST/$baseline_collection_log
echo "**************************************************************************************" >> $DEST/$baseline_collection_log
echo "COLLECTING NETWORK INFORMATION..." | tee -a $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of network devices:" >> $DEST/$baseline_collection_log
echo "ifconfig -a" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
ifconfig -a | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of UFW ('uncomplicated firewall') rules:" >> $DEST/$baseline_collection_log
echo "ufw status verbose" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
ufw status verbose | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of iptables (packet filter rules for the Linux Kernel firewall):" >> $DEST/$baseline_collection_log
echo "iptables -L" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
iptables -L | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of open files on the system and the process ID that opened them:" >> $DEST/$baseline_collection_log
echo "lsof" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
lsof | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of network connections:" >> $DEST/$baseline_collection_log
echo "netstat -a" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
netstat -a | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of network interfaces:" >> $DEST/$baseline_collection_log
echo "netstat -i" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
netstat -i | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of kernel network routing table:" >> $DEST/$baseline_collection_log
echo "netstat -r" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
netstat -r | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of network connections:" >> $DEST/$baseline_collection_log
echo "netstat -nalp" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
netstat -nalp | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of Network Connections:" >> $DEST/$baseline_collection_log
echo "netstat -plant" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
netstat -plant | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of the ARP table cache (Address Resolution Protocol):" >> $DEST/$baseline_collection_log
echo "arp -a" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
arp -a | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "COLLECTING NETWORK INFORMATION... DONE!" | tee -a $DEST/$baseline_collection_log
echo "**************************************************************************************" >> $DEST/$baseline_collection_log



#Create a directory listing of ALL files.

echo " " >> $DEST/$baseline_collection_log
echo "**************************************************************************************" >> $DEST/$baseline_collection_log
echo "CREATING DIRECTORY LISTING OF FILES..." | tee -a $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "FULL DIRECTORY LISTING: " >> $DEST/$baseline_collection_log
echo "ls -l -h -A -R /" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
ls -l -A -h -R / | tee -a  $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List ALL hidden directories:" >> $DEST/$baseline_collection_log
echo "find / -type d -name '\.*'" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
find / -type d -name "\.*" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of files/directories with no user/group name:" >> $DEST/$baseline_collection_log
echo "find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List of MD5 hash for all executable files:" >> $DEST/$baseline_collection_log
echo "find /usr/bin -type f -exec file "{}" \; | grep -i "elf" | cut -f1 -d: | xargs -I "{}" -n 1 md5sum {} " | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
find /usr/bin -type f -exec file "{}" \; | grep -i "elf" | cut -f1 -d: | xargs -I "{}" -n 1 md5sum {} | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "======================================================================================" >> $DEST/$baseline_collection_log
echo "List ALL log files that contain binary code inside:" >> $DEST/$baseline_collection_log
echo "grep [[:cntrl:]] /var/log/*.log" | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
grep [[:cntrl:]] /var/log/*.log | tee -a $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo "CREATING DIRECTORY LISTING OF FILES... DONE!" | tee -a $DEST/$baseline_collection_log
echo "**************************************************************************************" >> $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
echo " " >> $DEST/$baseline_collection_log
#Print finish message to screen and log.
echo "BASELINE COLLECTION COMPLETE!" | tee -a $DEST/$baseline_collection_log
date +"%m/%d/%Y %T" | tee -a $DEST/$baseline_collection_log
sleep 5
exit
