# pfcp-kitchen-sink

Embryionic N4 protocol simulator/tester for N4 interface that can simulate PFCP messages as defined by 3GPP standards.
Main purpose is to test a 5G UPF.

To (re)enerate go files:
```
go get  github.com/alvaroloes/enumer
go generate ./pkg/pfcp
```
To build pfcpclient:
```
go build -o pfcpclient cmd/pfcpclient/main.go
```
Example usage:
```
pfcpclient -l 172.21.16.99:8805    -r 172.21.16.1:8805 -s examples/sessions.yaml
```
This command launches a PFCP client on local address 172.21.16.99 (port 8805) and sets up an association with a UPF whose PFCP endpoint address is 172.21.16.1 (port 8805). It then creates all the PFCP sessions defined in the provided YAML file.

