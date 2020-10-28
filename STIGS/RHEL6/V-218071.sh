#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Earlier versions of SNMP are considered insecure, as they potentially allow unauthorized access to detailed system management information.

#STIG Identification
GrpID="V-218071"
GrpTitle="SRG-OS-000480"
RuleID="SV-218071r505923_rule"
STIGID="RHEL-06-000340"
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

if rpm -q net-snmp >> $Results; then
 if [ -e /etc/snmp/snmpd.conf ]; then 
  if egrep "v1|v2c|com2sec" /etc/snmp/snmpd.conf | grep -v "^#" >> $Results; then 
   echo "Fail" >> $Results
  else
   echo "File Exists and settings not found" >> $Results 
   echo "Pass" >> $Results
  fi
 else
  echo "/etc/snmp/snmpd.conf doesn't exist" >> $Results
  echo "Pass" >> $Results
 fi
else
 echo "NA" >> $Results
fi
