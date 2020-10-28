#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the SELinux policy to "targeted" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services. 

#STIG Identification
GrpID="V-217863"
GrpTitle="SRG-OS-000324"
RuleID="SV-217863r505923_rule"
STIGID="RHEL-06-000023"
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

if awk '/^SELINUXTYPE=targeted/' /etc/selinux/config >> $Results; then 
 echo "Pass" >> $Results
else
 awk '/^SELINUXTYPE/' /etc/selinux/config >> $Results
 echo "Fail" >> $Results
fi
