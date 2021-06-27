# BETA Linux Baseline & Forensic Triage Tool BETA
BETA - Linux Baseline & Forensic Triage Tool - BETA


The **Linux Baseline & Forensic Triage** tool is a simple script designed to give system administrators and incident responders a simple tool to use before, during, or after a suspected compromise. The script uses commands native to the Linux OS to help establish a baseline of normalcy for the system and to collect and compare this information later should the system be suspected of compromise. The baseline collection reports can be compared to the forensic triage collection to help quickly identify abnormalities or evidence of system compromise. The script is designed to be run from a removable USB storage device and the log files created stored off of the machine. Idealy, the script should be run once the machine has been setup and deployed into a production environment and then regularly thereafter.

The script gathers basic information about the system:
  1. Operating system information.
  2. Specific hardware information installed on the machine. 
  3. Netwoking configurations and statistics. 
  4. List of users, groups, and privileges. 
  5. Complete directory listing of all files.

The Linux Baseline & Forensics Triage tool is easily customizable and can be modified to collect data and log files that are specific to your environment. The script can also be configured to run other tools to generate or collect information related to your system or environment. For instance, both the FAST and FULL Forensic Triage collection scripts can be use with Microsoft's AVML (Acquire Volatile Memory for Linux) memory collection tool (which can be found here: https://github.com/microsoft/avml. 

The script gathers basic information about the system:
1. Operating system information.
2. Specific hardware information installed on the machine. 
3. Netwoking configurations and statistics. 
4. List of users, groups, and privileges. 
5. Complete directory listing of all files.