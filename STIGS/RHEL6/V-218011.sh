#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the idle delay controls when the screensaver will start, and can be combined with screen locking to prevent access from passersby.

#STIG Identification
GrpID="V-218011"
GrpTitle="SRG-OS-000029"
RuleID="SV-218011r603264_rule"
STIGID="RHEL-06-000257"
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
 if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay 2>>/dev/null)" == "15" ]; then
  gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay 2>>/dev/null >> $Results
  echo "Pass" >> $Results
else 
  echo "Setting not set" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "NA" >> $Results
fi
