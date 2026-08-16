module conectar-gateway

go 1.22

require (
	github.com/webview/webview_go v0.0.0-20240831120633-6173450d4dd6
	golang.org/x/crypto v0.25.0
)

require github.com/kr/fs v0.1.0 // indirect

require (
	github.com/coder/websocket v1.8.12
	github.com/pkg/sftp v1.13.6
	golang.org/x/sys v0.22.0 // indirect
)

replace (
	golang.org/x/crypto => github.com/golang/crypto v0.25.0
	golang.org/x/sys => github.com/golang/sys v0.22.0
	golang.org/x/term => github.com/golang/term v0.22.0
)

replace golang.org/x/net => github.com/golang/net v0.21.0

replace golang.org/x/text => github.com/golang/text v0.16.0

replace gopkg.in/yaml.v3 => github.com/go-yaml/yaml v0.0.0-20220521103104-8f96da9f5d5e

replace golang.org/x/tools => github.com/golang/tools v0.21.0

replace golang.org/x/mod => github.com/golang/mod v0.17.0

replace golang.org/x/sync => github.com/golang/sync v0.7.0

replace golang.org/x/telemetry => github.com/golang/telemetry v0.0.0-20240521205824-bda55230c457

replace gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20201130134442-10cb98267c6c
