module github.com/nox-hq/nox-plugin-taint-analysis

go 1.25.6

require (
	github.com/nox-hq/nox v0.5.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260504160031-60b97b32f348 // indirect
)

replace github.com/nox-hq/nox => ../..
