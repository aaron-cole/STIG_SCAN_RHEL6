#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.

#STIG Identification
GrpID="V-218062"
GrpTitle="SRG-OS-000024"
RuleID="SV-218062r505923_rule"
STIGID="RHEL-06-000324"
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
 if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable 2>>/dev/null)" == "true" ]; then 
  gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable 2>>/dev/null >> $Results
  echo "Pass" >> $Results
 else 
  echo "Setting not set" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Pass" >> $Results
fi
