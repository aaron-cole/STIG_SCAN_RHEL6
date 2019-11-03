#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.

#STIG Identification
GrpID="V-38651"
GrpTitle="SRG-OS-999999"
RuleID="SV-50452r1_rule"
STIGID="RHEL-06-000342"
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

for fn in $(grep "umask" /etc/bashrc | grep -v "#" | awk '{print $2}'); do 
 echo "UMASK $fn" >> $Results
 if [ "$fn" != "077" ]; then 
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]
then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
