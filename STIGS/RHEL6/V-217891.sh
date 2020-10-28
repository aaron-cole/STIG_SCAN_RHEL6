#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Any password, no matter how complex, can eventually be cracked. Therefore, system and application account passwords need to be changed periodically. If an organization fails to change the system and application account passwords at least annually, there is the risk that the account passwords could be compromised.

#STIG Identification
GrpID="V-217891"
GrpTitle="SRG-OS-000076"
RuleID="SV-217891r505923_rule"
STIGID="RHEL-06-000055"
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

for user in $(cut -f1 -d ":" /etc/shadow); do
 if [[ "$(grep "^$user:" /etc/shadow | cut -f 2 -d ":")" =~ ^\$6* ]]; then
  if [[ "$(grep "^$user:" /etc/shadow | cut -f 5 -d ":")" -le 365 ]] && [[ "$(grep "^$user:" /etc/shadow | cut -f 5 -d ":")" -gt 60 ]]; then
   echo "$user is greater than or equal to 365, is it a documented account?" >> $Results
  elif [[ "$(grep "^$user:" /etc/shadow | cut -f 5 -d ":")" -gt 365 ]]; then 
   echo "Fix $user - greater than 365 and is is a documented account?" >> $Results
  else
   echo "$user is like a normal account, less than or equal to 60" >> $Results
  fi
 else
  echo "No Password assigned - $user" >> $Results
 fi
done
echo "Fail" >> $Results


   
