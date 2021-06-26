#!/bin/bash

######################################################
#  Linux Baseline & Forensic Triage Collection Tool  #
#----------------------------------------------------#
#           Written by: John G. Asmussen             #
#         EGA Technology Specialists, LLC.           #
#                     (c) 2021                       #
######################################################

#CHECKING FOR CORRECT MOUNT LOCATION:

if whoami | grep "root"; then
     echo " "
     echo " "
     echo "Congratulations! You have root/sudo privileges..." 
else
     echo "!!! YOU ARE NOT ROOT !!!    PLEASE QUIT AND RE-RUN THIS SCRIPT WITH ROOT PRIVILIGES!" && exit
fi
