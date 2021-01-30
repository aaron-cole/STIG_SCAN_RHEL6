#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Privileged programs are subject to escalation-of-privilege attacks, which attempt to subvert their normal role of providing some necessary but limited capability. As such, motivation exists to monitor these programs for unusual activity.

#STIG Identification
GrpID="V-217976"
GrpTitle="SRG-OS-000327"
RuleID="SV-217976r603264_rule"
STIGID="RHEL-06-000198"
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


for f in b32 b64; do
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S execve -C uid!=euid -F euid=0" >> $Results; then
  echo "$f uid rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
 if ! auditctl -l | grep "\-a always,exit -F arch=$f -S execve -C gid!=egid -F egid=0" >> $Results; then
  echo "$f gid rule does not exist" >> $Results
  ((scorecheck+=1))
 fi
done

if [ $scorecheck -gt 0 ]; then
 scorecheck=0
 for fn in $(for p in $(mount | egrep -i "ext|xfs|btrfs|hpfs" | cut -f3 -d" "); do 
  find $p -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null; done); do 
   if [[ $fn == *.pid ]]; then 
    echo "" >>/dev/null; 
   else
    if ! auditctl -l | grep $fn | grep "auid>=500" | grep "auid!=-1" | grep "perm=x" >> $Results; then 
     echo "$fn audit rule not found" >> $Results
	 ((scorecheck+=1))
    fi
   fi
 done
fi

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
