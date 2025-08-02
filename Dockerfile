from golang:1.24 as build

workdir /app

copy go.mod go.sum ./
run go mod download

copy *.go ./
run go mod tidy

# Run tests to ensure code quality
#run go test -v ./...

run CGO_ENABLED=0 GOOS=linux go build -o /dfirewall

from debian:bookworm
workdir /

run apt -y update && apt -y upgrade && \
apt -y --no-install-recommends install ipset iptables redis

copy --from=build /dfirewall /dfirewall

copy scripts scripts
copy config config

# UDP and TCP
expose 53

user nobody:nogroup

entrypoint ["/dfirewall"]
