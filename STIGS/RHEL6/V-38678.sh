#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.

#STIG Identification
GrpID="V-38678"
GrpTitle="SRG-OS-000048"
RuleID="SV-50479r2_rule"
STIGID="RHEL-06-000311"
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

KBtotalsize=$(df --total /var/log/audit | grep total | awk '{print $2}' | grep -v "block")
MBtotalsize=$(((KBtotalsize+512)/1024))
factor=".25"

MBspace=$(echo $MBtotalsize*$factor | bc | cut -f 1 -d ".")

if [ -e /etc/audit/auditd.conf ] && [ "$(grep "^space_left =" /etc/audit/auditd.conf | wc -l)" -eq 1 ]; then 
awk -v spa="$MBspace" -v opf="$Results" -F= '/^space_left =/ {
	if($2 >= spa) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print spa >> opf
	 print "Fail" >> opf
	}
}' /etc/audit/auditd.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi