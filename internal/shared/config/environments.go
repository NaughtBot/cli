// Package config provides configuration management for the nb CLI.
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
		RelayURL:  "https://relay.naughtbot.com",
		IssuerURL: "https://login.naughtbot.com",
		BlobURL:   "https://blob.naughtbot.com",
	}

	// Sandbox is the sandbox environment.
	Sandbox = Environment{
		RelayURL:  "https://relay.sandbox.naughtbot.com",
		IssuerURL: "https://login.sandbox.naughtbot.com",
		BlobURL:   "https://blob.sandbox.naughtbot.com",
	}

	// LocalDev is the local development environment.
	LocalDev = Environment{
		RelayURL:  "http://127.0.0.1:8080",
		IssuerURL: "http://127.0.0.1:4455",
		BlobURL:   "http://127.0.0.1:8082",
	}
)
