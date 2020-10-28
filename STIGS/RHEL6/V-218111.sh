#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems. 

#STIG Identification
GrpID="V-218111"
GrpTitle="SRG-OS-000480"
RuleID="SV-218111r505923_rule"
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
