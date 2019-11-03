#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Enabling the activation of the screen lock after an idle period ensures password entry will be required in order to access the system, preventing access by passersby.

#STIG Identification
GrpID="V-38638"
GrpTitle="SRG-OS-000029"
RuleID="SV-50439r3_rule"
STIGID="RHEL-06-000259"
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
 if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled 2>>/dev/null)" == "true" ]; then
  gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled 2>>/dev/null >> $Results
  echo "Pass" >> $Results
 else 
  echo "Setting not set" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Pass" >> $Results
fi