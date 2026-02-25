module github.com/nox-hq/nox-plugin-grc

go 1.25.6

require (
	github.com/felixgeelhaar/agent-go/contrib/planner-llm v0.0.0-20260224191135-7365d0008bf3
	github.com/nox-hq/nox v0.5.0
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/felixgeelhaar/agent-go v0.6.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
)

replace github.com/nox-hq/nox => ../..

replace github.com/felixgeelhaar/agent-go => ../../../agent-go

replace github.com/felixgeelhaar/agent-go/contrib/planner-llm => ../../../agent-go/contrib/planner-llm
