#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Leaving the user list enabled is a security risk since it allows anyone with physical access to the system to quickly enumerate known user accounts without logging in.

#STIG Identification
GrpID="V-218105"
GrpTitle="SRG-OS-000480"
RuleID="SV-218105r505923_rule"
STIGID="RHEL-06-000527"
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
 if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/disable_user_list 2>>/dev/null)" == "true" ]; then 
  gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/disable_user_list 2>>/dev/null >> $Results
  echo "Pass" >> $Results
 else 
  echo "Setting not set" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Pass" >> $Results
fi
