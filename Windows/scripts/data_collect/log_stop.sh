#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set ip "192.168.1.110"
set username "testbed_2"
set password "qsefthuk"

set timeout 45

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*>"
send "wevtutil epl Security C:\\Users\\Public\\Sec_log.evtx\r"
expect "*>"
send "wevtutil epl System C:\\Users\\Public\\Sys_log.evtx\r"
expect "*>"
send "cd desktop\r"
expect "*>"
send "cd config_client\r"
expect "*>"
send "cd EvtxExplorer\r"
expect "*>"
send ".\\EvtxECmd.exe\r"
expect "*>"
send "evtxecmd.exe -d C:\\Users\\Public --csv C:\\Users\\Public\\data\\ --csvf log_out.csv\r"
expect "*>"
send "exit\r"


