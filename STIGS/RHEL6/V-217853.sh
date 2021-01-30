#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Although systems management and patching is extremely important to system security, management by a system outside the enterprise enclave is not desirable for some environments. However, if the system is being managed by RHN or RHN Satellite Server the "rhnsd" daemon can remain on.

#STIG Identification
GrpID="V-217853"
GrpTitle="SRG-OS-000096"
RuleID="SV-217853r603264_rule"
STIGID="RHEL-06-000009"
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

if [ -e /etc/sysconfig/rhn/systemid ] && [ "$(grep "system_id ID" /etc/sysconfig/rhn/systemid | grep -v "^#")" ]; then
 echo "System is registered to Satellite" >> $Results
 echo "Pass" >> $Results
elif [ "$(chkconfig rhnsd --list 2>>$Results | grep -i "on" >> $Results 2>>$Results)" ] || [ "$(ps -ef | grep rhnsd 2>>$Results | grep -v grep >> $Results 2>>$Results)" ] ; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi



