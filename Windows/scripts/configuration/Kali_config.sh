#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set kali_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set controller_ip [lindex $argv 4]
set controller_username [lindex $argv 5]
set controller_pass [lindex $argv 6]
set controller_path [lindex $argv 7]
set path "/root/Desktop"

set timeout 30

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$kali_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# update time
expect "#"
send "apt -y install ntp\r"
expect "#"
send "apt -y install ntpdate\r"
expect "#"
send "sudo ntpdate ntp.ubuntu.com\r"

#config dns
expect "#"
send "rm ~/.ssh/known_hosts\r"
expect "#"
send "scp -r $controller_user@$controller_ip:$controller_path $path\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"

expect "#"
send "chmod +x $path/*.py \r"

expect "#"
send "exit\r"

