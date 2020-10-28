#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Presence of the default SNMP password enables querying of different system aspects and could result in unauthorized knowledge of the system.

#STIG Identification
GrpID="V-218072"
GrpTitle="SRG-OS-000480"
RuleID="SV-218072r505923_rule"
STIGID="RHEL-06-000341"
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
  if $(grep -v "^#" /etc/snmp/snmpd.conf| grep public); then 
   echo "Fail" >> $Results
  else
   echo "public string not found" >> $Results
   echo "Pass" >> $Results
  fi
 else
  echo "/etc/snmp/snmpd.conf doesn't exist" >> $Results  
  echo "Pass" >> $Results
 fi
else
 echo "NA" >> $Results
fi
 
