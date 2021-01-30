#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.

#STIG Identification
GrpID="V-217947"
GrpTitle="SRG-OS-000480"
RuleID="SV-217947r603264_rule"
STIGID="RHEL-06-000159"
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
if [ -e /etc/audit/auditd.conf ] && [ "$(grep "^num_logs" /etc/audit/auditd.conf | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^num_logs/ {
	if($3 >= 5) {
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
