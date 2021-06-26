#!/bin/bash

######################################################
#  Linux Baseline & Forensic Triage Collection Tool  #
#----------------------------------------------------#
#           Written by: John G. Asmussen             #
#         EGA Technology Specialists, LLC.           #
#                     (c) 2021                       #
######################################################

#CHECKING FOR CORRECT MOUNT LOCATION:

if cat /proc/mounts | grep "/mnt/FORENSICS"; then
     echo " "
     echo " "
     echo "Destination Drive is mounted and ready..." 
else
     echo "Destination Drive is NOT mounted at '/mnt/FORENSICS/' ... EXITING!" && exit
fi
