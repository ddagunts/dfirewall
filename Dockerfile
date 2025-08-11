from golang:1.24 as build

workdir /app

copy go.mod go.sum ./
run go mod download

copy *.go ./

run CGO_ENABLED=0 GOOS=linux go build -o /dfirewall

from debian:bookworm
workdir /

run apt -y update && apt -y upgrade && \
apt -y --no-install-recommends install ipset iptables

copy --from=build /dfirewall /dfirewall

copy scripts scripts

# UDP and TCP DNS
expose 53
# HTTP Web UI
expose 8080

user nobody:nogroup

entrypoint ["/dfirewall"]
