#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise.

#STIG Identification
GrpID="V-38520"
GrpTitle="SRG-OS-000215"
RuleID="SV-50321r1_rule"
STIGID="RHEL-06-000136"
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

if [ -e /etc/rsyslog.conf ] && [ "$(grep "@" /etc/rsyslog.conf | grep -v "^#")" ]; then 
awk -v opf="$Results" '/^\*.*\@/ {
	if(length($2)>8) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/rsyslog.conf
else 
 echo "Fail" >> $Results
fi