#!/bin/sh

pfctl -t allowed-ips -T delete "$DFIREWALL_RESOLVED_IP"
