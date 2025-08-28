####

Running on OpenBSD
1) clone repo to /root/dfirewall
2) example rc script

router# cat /etc/rc.d/dfirewall                                                                                                                                
#!/bin/ksh

daemon="/root/dfirewall/run.sh"

. /etc/rc.d/rc.subr

rc_start() {
  nohup ${rcexec} "${daemon}"
}

rc_cmd $1 


3) make a "run.sh" script in /root/dfirewall, here's an example
#!/bin/sh

cd /root/dfirewall

export UPSTREAM=127.0.0.1:53
export REDIS=redis://127.0.0.1:6379
export WEB_UI_PORT=8080
export DAEMON=true
export PID_FILE=/var/run/dfirewall.pid
export DNS_BIND_IP=0.0.0.0
export WEBUI_BIND_IP=.0.0.0.0
export INVOKE_SCRIPT=/root/dfirewall/scripts/invoke_pf.sh
export EXPIRE_SCRIPT=/root/dfirewall/scripts/expire_pf.sh
export SYNC_SCRIPT_EXECUTION=1
#export DEBUG=1
export ENABLE_AAAA_PROCESSING=0
./dfirewall-openbsd-arm64

4) Example rules for pf
table <allowed-ips>
pass out log on $wan from $wan to <allowed-ips> modulate state
pass in  log on $lan from any to <allowed-ips> modulate state

