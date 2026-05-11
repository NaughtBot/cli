// Package config provides configuration management for the oobsign CLI.
package config

// Environment contains URLs for a deployment environment.
type Environment struct {
	RelayURL  string
	IssuerURL string
	BlobURL   string
}

// Predefined environments
var (
	// Production is the production environment.
	Production = Environment{
		RelayURL:  "https://relay.oobsign.com",
		IssuerURL: "https://login.oobsign.com",
		BlobURL:   "https://blob.oobsign.com",
	}

	// Sandbox is the sandbox environment.
	Sandbox = Environment{
		RelayURL:  "https://relay.sandbox.oobsign.com",
		IssuerURL: "https://login.sandbox.oobsign.com",
		BlobURL:   "https://blob.sandbox.oobsign.com",
	}

	// LocalDev is the local development environment.
	LocalDev = Environment{
		RelayURL:  "http://127.0.0.1:8080",
		IssuerURL: "http://127.0.0.1:4455",
		BlobURL:   "http://127.0.0.1:8082",
	}
)
