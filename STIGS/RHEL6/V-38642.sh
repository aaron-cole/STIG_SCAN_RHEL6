#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The umask influences the permissions assigned to files created by a process at run time. An unnecessarily permissive umask could result in files being created with insecure permissions.

#STIG Identification
GrpID="V-38642"
GrpTitle="SRG-OS-999999"
RuleID="SV-50443r1_rule"
STIGID="RHEL-06-000346"
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

for fn in $(grep -i "umask" /etc/init.d/functions | grep -v "#" | awk '{print $2}'); do 
 if [ "$fn" -eq 022 ] || [ "$fn" -eq 027 ]; then 
  echo "UMASK $fn" >> $Results
 else
  echo "UMASK $fn" >> $Results 
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]
then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi