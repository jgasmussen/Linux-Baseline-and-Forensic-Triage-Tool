# BETA Linux Baseline & Forensic Triage Tool BETA
  - #### **No more cheatsheets.**
  - #### **No more mistakes typing out long commands.**
  - #### **Run a few basic commands and done!**
  - #### **Live incident response + least user interaction with the machine = best forensic practice.**


## _***About***_

The **Linux Baseline & Forensic Triage** tool is a BASH shell script designed to give system administrators and incident responders a simple and easy to use tool for LIVE Linux machines. The script uses native commands to most Unix/Linux distributions to help establish a baseline of "normalcy" for the system. The baseline collection reports can be compared to the forensic triage collections to help quickly identify abnormalities or evidence of system compromise. The Linux Baseline & Forensic Triage tool is designed to be run from a removable USB storage device and the report(s), log file(s), and collected triage files are stored OFF-LINE away from the system/network. Ideally, the script would be run after the machine has been setup and configured but before the machine is deployed into the production environment. For best results, the script should be re-run regularly thereafter. The report files are saved in a "Hostname"."Date".log file name format allowing the reports to be kept for historical/comparative analysis of the machine. This tool IS NOT designed to replace normal log file collection and retention. The tool IS designed to supplement log file analysis by giving a quick and easy way to identify any changes based on historical baseline collections and compared to the current collection.   

**The BASELINE script** gathers useful information about the system:
  1. Operating system information and statistics.
  2. Specific hardware information. 
  3. Networking configurations and statistics.
  4. List of running processes.
  5. List of users, groups, and privileges. 
  6. Complete directory listing of all files.

The Linux Baseline & Forensics Triage tool is easily customizable and can be modified to collect data and log files that are specific to your environment. The script can be configured to run other tools to generate or collect information related to your system or environment. For instance, both the FAST and FULL Forensic Triage collection scripts can be used with Microsoft's AVML (Acquire Volatile Memory for Linux) memory collection tool (which can be found here: https://github.com/microsoft/avml). ***Note: Microsoft's AVML is NOT included with this script and must be downloaded separately.***

## _***HOW TO USE THE BASELINE SCRIPT***_ 
  1.  On a separate system, format the USB flash drive using "ExFAT" and re-name the drive to "FORENSICS" (CASE SENSITIVE and without the quotes).
  2.  Copy all of the scripts from this repository along with any other programs or scripts needed (i.e. AVML) to the USB flash drive.
  3.  Connect the USB flash drive to the machine.
  4.  Open a terminal / shell / command line window.
  5.  Using "root" and/or "sudo" privileges create the mount point for the USB flash drive using the following command: 
  
       `$ sudo mkdir /mnt/FORENSICS`
  
  6.  Using "root" or "sudo" privileges find the device name of the USB flash drive or USB external hard drive: 
  
       `$ sudo fdisk -l | grep FORENSICS`
  
  7.  Once you have identified your device path from the output of Step 6, mount the device using the following command: 
  
       `$ sudo mount /dev/sdb1 /mnt/FORENSICS`  
       ###### NOTICE: Your device path may be different! ######
  
  8.  Change directories to the USB flash drive: 
 
       `$ cd /mnt/FORENSICS`
  
  9.  Run the following command:
  
       `$ ./bcft.sh`
  
  10. From the menu screen select option 1. "Check for correct mount location."
      This option checks to make sure the script and destination USB flash drive are properly mounted at "/mnt/FORENSICS/".
      If everything worked correctly you will be given a success message and are returned to the main menu.
      If the mount point location is incorrect you will be given an error message and you should unmount the drive and repeat steps 5 - 10.
  
  11. From the menu screen select option 2. "Check for root / sudo privileges."
      This option checks to make sure the script was run with root or sudo privileges. 
      If correct you will be given a success message and returned to the main menu.
      If you ran the script without root or sudo privileges you will be given an error message and you should quit the script (option 0) and start over with root /       sudo privileges.
  
  12. If the above two options worked without incident, select option 3, for "BASELINE COLLECTION." 
      The baseline collection process will begin and most information is displayed to the screen but is also being written to log file located on the USB flash           drive. Please be patient and allow the script to completely finish. Once the script has finished running you will be returned to the main menu.
  
  13. From the menu screen select option 0, to exit the script.
  
  14. Using "root" or "sudo" privileges, unmount the USB flash drive using the following command:
  
      `$ sudo umount /dev/FORENSICS`
  
  15. Remove the USB flash drive from the machine and review the collection on a separate machine.

  
  
  
  
  
  
  
