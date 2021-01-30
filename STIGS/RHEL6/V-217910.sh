#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range.

#STIG Identification
GrpID="V-217910"
GrpTitle="SRG-OS-000480"
RuleID="SV-217910r603264_rule"
STIGID="RHEL-06-000079"
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

sysctl kernel.exec-shield  | awk -v opf="$Results" '/^kernel.exec-shield/ {
	if($3 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
