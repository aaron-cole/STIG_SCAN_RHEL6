#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Log files can contain valuable information regarding system configuration. If the system log files are not protected, unauthorized users could change the logged data, eliminating their forensic value.

#STIG Identification
GrpID="V-217940"
GrpTitle="SRG-OS-000206"
RuleID="SV-217940r505923_rule"
STIGID="RHEL-06-000135"
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
scorecheck=0

for fn in $(grep -v "^#" /etc/rsyslog.conf | sed s/^[^\/]*// | grep "^/" | cut -f1 -d" " | grep -v "/var/log/boot.log"); do 
 if [ -f $fn ]; then
  stat -c %n-%a $fn >> $Results 
  if [ "$(stat -c %a $fn)" -gt "600" ]; then 
   ((scorecheck+=1))
  fi 
 fi 
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
