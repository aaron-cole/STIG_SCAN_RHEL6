#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The addition/removal of kernel modules can be used to alter the behavior of the kernel and potentially introduce malicious code into kernel space. It is important to have an audit trail of modules that have been introduced into the kernel.

#STIG Identification
GrpID="V-38580"
GrpTitle="SRG-OS-000064"
RuleID="SV-50381r3_rule"
STIGID="RHEL-06-000202"
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
scorecheck=0
files="\/sbin\/insmod \/sbin\/rmmod \/sbin\/modprobe"
modules="init_module delete_module"

for file in $files; do
 if ! auditctl -l | awk '/^-w '"$file"' -p x/' >> $Results; then
  ((scorecheck+=1))
 fi
done

for module in $modules; do
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S .*[^-F key=]'"$module"'/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S .*[^-F key=]'"$module"'/' >> $Results; then
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
