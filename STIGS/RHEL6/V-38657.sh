#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.

#STIG Identification
GrpID="V-38657"
GrpTitle="SRG-OS-999999"
RuleID="SV-50458r2_rule"
STIGID="RHEL-06-000273"
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

if rpm -q samba >> $Results; then 
 if [ "$(grep cifs /etc/fstab /etc/mtab | wc-l)" -gt "0" ]; then 
  if grep cifs /etc/fstab /etc/mtab | grep sec | egrep "krb5i|ntlmv2i" >> $Results; then 
   echo "Pass" >> $Results
  else
   echo "cifs mounts in use without security" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "No cifs mounts found" >> $Results
  echo "Pass" >> $Results
 fi
else
 echo "NA" >> $Results
fi