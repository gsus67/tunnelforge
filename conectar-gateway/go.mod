module conectar-gateway

go 1.22

require golang.org/x/crypto v0.25.0

require golang.org/x/sys v0.22.0 // indirect

replace (
	golang.org/x/crypto => github.com/golang/crypto v0.25.0
	golang.org/x/sys => github.com/golang/sys v0.22.0
	golang.org/x/term => github.com/golang/term v0.22.0
)
