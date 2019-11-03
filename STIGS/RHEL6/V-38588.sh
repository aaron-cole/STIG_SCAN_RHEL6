#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Using interactive boot, the console user could disable auditing, firewalls, or other services, weakening system security.

#STIG Identification
GrpID="V-38588"
GrpTitle="SRG-OS-000080"
RuleID="SV-50389r1_rule"
STIGID="RHEL-06-000070"
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

#Not Going to process any more than 1 lines
#Check will fail automatically if set twice
if [ -e /etc/sysconfig/init ] && [ "$(grep "^PROMPT" /etc/sysconfig/init | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" -F= '/^PROMPT/ {
	if($2 == "no") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/sysconfig/init
else
 echo "Setting not defined or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi