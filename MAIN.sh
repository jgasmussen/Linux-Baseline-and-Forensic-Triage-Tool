#!/bin/bash

######################################################
#  Linux Baseline & Forensic Triage Collection Tool  #
#----------------------------------------------------#
#           Written by: John G. Asmussen             #
#         EGA Technology Specialists, LLC.           #
#                     (c) 2021                       #
######################################################

server_name=$(hostname)

function mount_location_check() {
    echo ""
	echo "Check current mount location on ${server_name} is: "
        echo ""
	/mnt/FORENSICS/./mount_location.sh
    echo ""
}

function check_root() {
    echo ""
        echo "Checking for root/sudo priviliges: "
        echo ""
	/mnt/FORENSICS/./root_check.sh
    echo ""
}

function server_baseline_tool() {
    echo ""
        echo "Create Baseline Information for ${server_name}: "
        echo ""
        /mnt/FORENSICS/./baseline.sh
    echo ""
}

function fast_triage_collection_tool() {
    echo ""
        echo "Create Forensic Triage Collection from ${server_name}: "
        echo ""
        /mnt/FORENSICS/./FAST_TRIAGE.sh
    echo ""
}

function forensic_triage_collection_tool() {
    echo ""
	echo "Create Forensic Triage Collection from ${server_name}: "
        echo ""
	/mnt/FORENSICS/./triage_collection.sh
    echo ""
}

##
# Color  Variables
##
red='\e[31m'
green='\e[32m'
blue='\e[34m'
clear='\e[0m'

##
# Color Functions
##

ColorGreen(){
	echo -ne $green$1$clear
}
ColorBlue(){
	echo -ne $blue$1$clear
}
ColorRed(){
        echo -ne $red$1$clear
}

menu(){
clear
echo -ne "

$blue
++++++++++++++++++++++++++++++++++++++++++++++++++++++
+                                                    +
+$clear                  Linux Baseline &         $blue         +
+$clear           Forensic Triage Collection Tool$blue          +
+$blue  ________________________________________________  $blue+
+                                                    +
+$clear             Written by: John G. Asmussen   $blue        +
+$clear           EGA Technology Specialists, LLC. $blue        +
+$clear                      (c) 2021$blue                      +
+                                                    +
++++++++++++++++++++++++++++++++++++++++++++++++++++++


$(ColorBlue '1)') Check USB Mount Location

$(ColorBlue '2)') Check root/sudo privileges

$(ColorBlue '3)') Create Baseline System File

$(ColorBlue '4)') Run Fast Triage Collection

$(ColorBlue '5)') Run Full Triage Collection

$(ColorBlue '0)') Exit

$(ColorBlue 'Choose an option:') "
        read a
        case $a in
	        1) mount_location_check; sleep 5; clear; menu;;
	        2) check_root; sleep 5; clear; menu;;
	        3) server_baseline_tool; sleep 5; clear; menu ;;
		4) fast_triage_collection_tool; sleep 5; clear; menu ;;
		5) forensic_triage_collection_tool; sleep 5; clear; menu ;;
		0) clear; exit 0;;
		*) echo -e $red"Wrong option."$clear; WrongCommand;;
        esac
}

# Call the menu function
menu
