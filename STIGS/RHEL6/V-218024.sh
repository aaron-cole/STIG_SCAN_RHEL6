#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.

#STIG Identification
GrpID="V-218024"
GrpTitle="SRG-OS-000480"
RuleID="SV-218024r603264_rule"
STIGID="RHEL-06-000272"
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

if [ -e /etc/samba/smb.conf ]; then 
 if grep -i "client signing = mandatory" /etc/samba/smb.conf >> $Results; then 
  echo "Pass" >> $Results
 else
  grep -i "client signing" /etc/samba/smb.conf >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/etc/snmp/snmpd.conf doesn't exist" >> $Results 
 echo "Pass" >> $Results
fi
