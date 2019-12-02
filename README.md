# pfcp-kitchen-sink

To (re)enerate go files:
```
go get  github.com/alvaroloes/enumer
go generate ./pkg/pfcp
```
To build pfcpclient:
```
go build -o pfcpclient cmd/pfcpclient/main.go
```

