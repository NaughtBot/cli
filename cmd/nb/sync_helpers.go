package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/naughtbot/cli/crypto"
	"github.com/naughtbot/cli/internal/shared/client"
	"github.com/naughtbot/cli/internal/shared/config"
	sharedsync "github.com/naughtbot/cli/internal/shared/sync"
)

var syncKeysFunc = sharedsync.SyncKeys

func attestationEnvironmentForIssuerURL(issuerURL string) crypto.AttestationEnvironment {
	if parsedURL, err := url.Parse(strings.TrimSpace(issuerURL)); err == nil {
		host := strings.ToLower(parsedURL.Hostname())
		switch {
		case host == "localhost" || host == "127.0.0.1":
			return crypto.EnvDevelopment
		case strings.Contains(host, "sandbox"):
			return crypto.EnvSandbox
		}
	}

	normalized := strings.TrimRight(strings.ToLower(strings.TrimSpace(issuerURL)), "/")
	switch normalized {
	case strings.TrimRight(strings.ToLower(config.LocalDev.IssuerURL), "/"):
		return crypto.EnvDevelopment
	case strings.TrimRight(strings.ToLower(config.Sandbox.IssuerURL), "/"):
		return crypto.EnvSandbox
	default:
		return crypto.EnvProduction
	}
}

func resolveAcceptSoftwareApproverKeys(explicit bool) bool {
	if explicit {
		return true
	}

	switch strings.ToLower(os.Getenv("OOBSIGN_ACCEPT_SOFTWARE_APPROVER_KEYS")) {
	case "1", "true":
		return true
	default:
		return false
	}
}

func syncSigningKeys(
	cfg *config.Config,
	c *client.Client,
	userID, accessToken string,
	attestationEnv crypto.AttestationEnvironment,
	acceptSoftware bool,
) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := syncKeysFunc(ctx, cfg, c, userID, accessToken, sharedsync.SyncOptions{
		VerifyAttestation:          true,
		AttestationEnv:             attestationEnv,
		AcceptSoftwareApproverKeys: acceptSoftware,
	})
	if err != nil {
		return 0, err
	}

	for _, device := range result.Devices {
		if device.IsAttested {
			attestLabel := "hardware"
			if device.AttestationType != "" {
				attestLabel = string(device.AttestationType)
			}
			fmt.Printf("  ✓ %s (%s)\n", device.DeviceName, attestLabel)
			continue
		}
		if device.VerificationErr != nil {
			fmt.Printf("  ✗ %s (verification failed: %v)\n", device.DeviceName, device.VerificationErr)
			continue
		}
		fmt.Printf("  ○ %s (software fallback)\n", device.DeviceName)
	}

	return result.KeyCount(), nil
}
