#!/usr/bin/expect -f
# ~/Desktop/datalogi/CompSys/Afleveringer/A3/src/start-peer-expect.sh

set timeout 10
log_user 1

set own_ip [lindex $argv 0]
set own_port [lindex $argv 1]
set password [lindex $argv 2]
set remote_ip [lindex $argv 3]
set remote_port [lindex $argv 4]

spawn ./peer $own_ip $own_port

# Password
expect -re ".*:"
send "$password\r"

sleep 0.5

# IP
expect -re ".*:"
send "$remote_ip\r"

sleep 0.5

# Port
expect -re ".*:"
send "$remote_port\r"

# Vent på filename prompt
expect -re ".*:"

# Nu GÅ FULDT INTERAKTIV - giv brugeren fuld kontrol
interact
