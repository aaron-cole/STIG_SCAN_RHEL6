#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.

#STIG Identification
GrpID="V-218054"
GrpTitle="SRG-OS-000480"
RuleID="SV-218054r505923_rule"
STIGID="RHEL-06-000308"
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

if [ -e /etc/security/limits.conf ] && [ "$(grep "^\*.*hard.*core" /etc/security/limits.conf | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^\*.*hard.*core/ {
	if($4 == 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/security/limits.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi
