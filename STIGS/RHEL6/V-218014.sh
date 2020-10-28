#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the screensaver mode to blank-only conceals the contents of the display from passersby.

#STIG Identification
GrpID="V-218014"
GrpTitle="SRG-OS-000031"
RuleID="SV-218014r505923_rule"
STIGID="RHEL-06-000260"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

###Check###

if rpm -q GConf2 >> $Results; then
 if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode 2>>/dev/null)" == "blank-only" ]; then
  gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode 2>>/dev/null >> $Results
  echo "Pass" >> $Results
 else
  echo "Setting not set" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Pass" >> $Results
fi
