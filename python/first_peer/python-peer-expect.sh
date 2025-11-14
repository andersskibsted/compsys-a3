#!/usr/bin/expect -f
# ~/peer-scripts/start-peer-expect.sh

# set own_ip [lindex $argv 0]
# set own_port [lindex $argv 1]
# set password [lindex $argv 2]
# set remote_ip [lindex $argv 3]
# set remote_port [lindex $argv 4]
set password "mypass123"

spawn python3 peer_proper_salting.py -d 127.0.0.1 12345

# Håndter password prompt fra python peer
expect -re "(?i).*password.*:"
send "$password\r"

# Gå interaktiv så brugeren kan taste filename
interact
