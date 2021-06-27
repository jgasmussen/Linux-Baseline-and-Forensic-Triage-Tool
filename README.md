# BETA Linux Baseline & Forensic Triage Tool BETA
BETA - Linux Baseline & Forensic Triage Tool - BETA


The **Linux Baseline & Forensic Triage** tool is a BASH shell script designed to give system administrators and incident responders a simple tool to use before, during, and after a suspected system compromise. The script uses native commands to most Unix/Linux distributions to help establish a baseline of "normalcy" for the system. The baseline collection reports can be compared to the forensic triage collections to help quickly identify abnormalities or evidence of system compromise. The script is designed to be run from a removable USB storage device and the collected files and logs stored OFF of the machine. Idealy, the script should be run once the machine has been setup and configured but before the machine is deployed into a production environment. For best results, the script should be re-run regularly thereafter. The report files are saved in a "Hostname"."Date".log file allowing the reports to be kept for historical analysis of the machine. This tool IS NOT designed to replace normal log file collection and retention. The tool IS designed to supplemnt log file analysis by giving a quick and easy way to identify any changes based on historical baseline collections and compared to the currrent collection.   


The BASELINE script gathers basic information about the system:
  1. Operating system information.
  2. Specific hardware information installed on the machine. 
  3. Netwoking configurations and statistics. 
  4. List of users, groups, and privileges. 
  5. Complete directory listing of all files.

The Linux Baseline & Forensics Triage tool is easily customizable and can be modified to collect data and log files that are specific to your environment. The script can be configured to run other tools to generate or collect information related to your system or environment. For instance, both the FAST and FULL Forensic Triage collection scripts can be use with Microsoft's AVML (Acquire Volatile Memory for Linux) memory collection tool (which can be found here: https://github.com/microsoft/avml. 

The script gathers basic information about the system:
1. Operating system information.
2. Specific hardware information installed on the machine. 
3. Netwoking configurations and statistics. 
4. List of users, groups, and privileges. 
5. Complete directory listing of all files.
