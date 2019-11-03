#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Limiting simultaneous user logins can insulate the system from denial of service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.

#STIG Identification
GrpID="V-38684"
GrpTitle="SRG-OS-000027"
RuleID="SV-50485r2_rule"
STIGID="RHEL-06-000319"
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

if [ -e /etc/security/limits.conf ] && [ "$(grep "^\*.*hard.*maxlogins" /etc/security/limits.conf | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^\*.*hard.*maxlogins/ {
	if($4 <= 10) {
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