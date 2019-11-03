#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#A locally logged-in user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

#STIG Identification
GrpID="V-38668"
GrpTitle="SRG-OS-999999"
RuleID="SV-50469r4_rule"
STIGID="RHEL-06-000286"
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
if [ -e /etc/init/control-alt-delete.override ]; then
 if grep "^exec /usr/bin/logger -p " /etc/init/control-alt-delete.override | egrep -i "Ctrl-|Control-" | grep -i "Alt-Delete pressed" >> $Results; then 
  echo "Pass" >> $Results
 elif grep "^exec /usr/bin/logger" /etc/init/control-alt-delete.override >> $Results; then
  echo "Pass" >> $Results
 else
  cat /etc/init/control-alt-delete.override >> $Results
 fi
else
 echo "OverRide file does not exist" >> $Results
 echo "Fail" >> $Results
fi
