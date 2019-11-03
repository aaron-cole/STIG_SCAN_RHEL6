#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The ability to lock graphical desktop sessions manually allows users to easily secure their accounts should they need to depart from their workstations temporarily.

#STIG Identification
GrpID="V-38474"
GrpTitle="SRG-OS-000030"
RuleID="SV-50274r2_rule"
STIGID="RHEL-06-000508"
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
 if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver 2>>/dev/null)" == "<Control><Alt>l" ]; then
  gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver | sed 's/[<>]/ /g' 2>>$Results >> $Results
  echo "Pass" >> $Results
 else 
  echo "Setting not set" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Pass" >> $Results
fi
