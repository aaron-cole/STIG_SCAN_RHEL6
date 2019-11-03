#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action.

#STIG Identification
GrpID="V-38680"
GrpTitle="SRG-OS-000046"
RuleID="SV-50481r1_rule"
STIGID="RHEL-06-000313"
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
if [ -e /etc/audit/auditd.conf ] && [ "$(grep "^action_mail_acct " /etc/audit/auditd.conf | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^action_mail_acct / {
	if($3 >= "root") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/audit/auditd.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi