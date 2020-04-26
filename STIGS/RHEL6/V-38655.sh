#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise.

#STIG Identification
GrpID="V-38655"
GrpTitle="SRG-OS-000035"
RuleID="SV-50456r2_rule"
STIGID="RHEL-06-000271"
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

if egrep -v "ext|#|swap|gfs" /etc/fstab | grep "^\/" >> $Results; then 
 if [ "$(egrep -v "ext|#|swap|gfs" /etc/fstab | grep "^\/" | wc -l)" == "$(egrep -v "ext|#|swap|gfs" /etc/fstab | grep "^\/" | grep noexec | wc -l)" ]; then 
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else 
 echo "Pass" >> $Results
fi
