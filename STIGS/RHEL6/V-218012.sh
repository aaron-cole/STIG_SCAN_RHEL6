#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Enabling idle activation of the screen saver ensures the screensaver will be activated after the idle delay. Applications requiring continuous, real-time screen display (such as network management products) require the login session does not have administrator rights and the display station is located in a controlled-access area.

#STIG Identification
GrpID="V-218012"
GrpTitle="SRG-OS-000029"
RuleID="SV-218012r603264_rule"
STIGID="RHEL-06-000258"
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
 if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled 2>>/dev/null)" == "true" ]; then
  gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled 2>>/dev/null >> $Results
  echo "Pass" >> $Results
 else 
  echo "Setting not set" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "Pass" >> $Results
fi
