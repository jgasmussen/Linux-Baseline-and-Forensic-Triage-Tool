# BETA Linux Baseline & Forensic Triage Tool BETA
*No more cheatsheets. No more mistakes typing out long commands. Run one command and done!*

The **Linux Baseline & Forensic Triage** tool is a BASH shell script designed to give system administrators and incident responders a simple and easy tool to use before and during a suspected system compromise. No more cheatsheets. No more mistakes typing out long commands. Less user interaction with the machine = best forensic practices. The script uses native commands to most Unix/Linux distributions to help establish a baseline of "normalcy" for the system. The baseline collection reports can be compared to the forensic triage collections to help quickly identify abnormalities or evidence of system compromise. The Linux Baseline & Forensic Triage tool is designed to be run from a removable USB storage device and the report(s), log file(s), and collected triage files are stored OFF-LINE away from the system/network. Idealy, the script would be run after the machine has been setup and configured but before the machine is deployed into the production environment. For best results, the script should be re-run regularly thereafter. The report files are saved in a "Hostname"."Date".log file name format allowing the reports to be kept for historical/comparative analysis of the machine. This tool IS NOT designed to replace normal log file collection and retention. The tool IS designed to supplemnt log file analysis by giving a quick and easy way to identify any changes based on historical baseline collections and compared to the currrent collection.   

**The BASELINE script**: gathers basic information about the system:
  1. Operating system information.
  2. Specific hardware information installed on the machine. 
  3. Netwoking configurations and statistics. 
  4. List of users, groups, and privileges. 
  5. Complete directory listing of all files.

The Linux Baseline & Forensics Triage tool is easily customizable and can be modified to collect data and log files that are specific to your environment. The script can be configured to run other tools to generate or collect information related to your system or environment. For instance, both the FAST and FULL Forensic Triage collection scripts can be used with Microsoft's AVML (Acquire Volatile Memory for Linux) memory collection tool (which can be found here: https://github.com/microsoft/avml. ***Note: Microsofts AVML is not included with this software and must be downloaded separately.***

