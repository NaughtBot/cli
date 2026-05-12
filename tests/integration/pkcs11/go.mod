module github.com/naughtbot/cli/tests/integration/pkcs11

go 1.26.0

require (
	github.com/miekg/pkcs11 v1.1.1
	github.com/naughtbot/cli/tests/integration/shared v0.0.0
)

replace github.com/naughtbot/cli/tests/integration/shared => ../shared
