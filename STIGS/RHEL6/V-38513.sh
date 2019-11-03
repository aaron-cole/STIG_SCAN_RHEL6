#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.

#STIG Identification
GrpID="V-38513"
GrpTitle="SRG-OS-000231"
RuleID="SV-50314r2_rule"
STIGID="RHEL-06-000120"
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

echo "File - $(grep "^:INPUT DROP \[" /etc/sysconfig/iptables)" >> $Results
echo "Running Status - $(service iptables status | grep INPUT | grep DROP)" >> $Results

if [ "$(grep "^:INPUT DROP \[" /etc/sysconfig/iptables)" ] && [ "$(service iptables status | grep INPUT | grep DROP)" ];then 
 echo "Pass" >> $Results
else 
  echo "Fail" >> $Results
fi