#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.

#STIG Identification
GrpID="V-81443"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-96157r1_rule"
STIGID="RHEL-06-000533"
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

if rpm -q ISecTP >> $Results; then
 echo "McAfee ENSL Status - $(systemctl state isectpd 2>> $Results)" >> $Results
 /opt/isec/ens/threatprevention/bin/isecav --version >> $Results
 echo "Pass" >> $Results
else
 echo "McAfee ENSL is not installed" >> $Results
 echo "Fail" >> $Results
fi
