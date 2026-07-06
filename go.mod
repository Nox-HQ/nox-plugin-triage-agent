module github.com/nox-hq/nox-plugin-triage-agent

go 1.26.2

require (
	github.com/nox-hq/nox v1.7.1
	google.golang.org/grpc v1.82.0
	google.golang.org/protobuf v1.36.11
)

require go.klarlabs.de/agent v0.15.0 // indirect

require (
	go.klarlabs.de/agent/contrib/planner-llm v0.4.0
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260504160031-60b97b32f348 // indirect
)
