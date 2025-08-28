#!/bin/sh

pfctl -t allowed-ips -T add "$DFIREWALL_RESOLVED_IP"
