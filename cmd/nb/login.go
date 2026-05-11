//go:build legacy_api

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	authapi "github.com/naughtbot/api/auth"
	"github.com/naughtbot/cli/crypto"
	"github.com/naughtbot/cli/internal/ptr"
	"github.com/naughtbot/cli/internal/shared/client"
	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/display"
	"github.com/naughtbot/cli/internal/shared/log"
	"github.com/naughtbot/cli/internal/shared/sysinfo"
)

var (
	loginLocaldev                   bool
	loginSandbox                    bool
	loginRelayURL                   string
	loginIssuerURL                  string
	loginDeviceName                 string
	loginShowConfig                 bool
	loginListKeys                   bool
	loginLogout                     bool
	loginForce                      bool
	loginAcceptSoftwareApproverKeys bool
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with NaughtBot via QR code",
	Run:   runLogin,
}

func init() {
	f := loginCmd.Flags()
	f.BoolVar(&loginLocaldev, "localdev", false, "Use local development environment (localhost)")
	f.BoolVar(&loginSandbox, "sandbox", false, "Use sandbox environment")
	f.StringVar(&loginRelayURL, "relay", "", "Override relay server URL")
	f.StringVar(&loginIssuerURL, "issuer", "", "Override OIDC issuer URL")
	f.StringVar(&loginDeviceName, "device-name", "", "Device name for this CLI (defaults to hostname)")
	f.BoolVar(&loginShowConfig, "config", false, "Show current configuration")
	f.BoolVar(&loginListKeys, "keys", false, "List enrolled keys")
	f.BoolVar(&loginLogout, "logout", false, "Logout from user account")
	f.BoolVarP(&loginForce, "force", "f", false, "Force re-login on existing profile")
	f.BoolVar(&loginAcceptSoftwareApproverKeys, "accept-software-approver-keys", false, "Accept devices with software-only attestation (less secure)")
}

func runLogin(cmd *cobra.Command, args []string) {
	profileOverride := profile

	log.Info("login: invoked (profile=%q localdev=%v sandbox=%v show-config=%v list-keys=%v logout=%v force=%v)",
		profileOverride, loginLocaldev, loginSandbox, loginShowConfig, loginListKeys, loginLogout, loginForce)

	// Validate mutually exclusive flags
	if loginLocaldev && loginSandbox {
		die("--localdev and --sandbox are mutually exclusive")
	}

	// Resolve environment defaults (production is default)
	env := config.Production
	if loginLocaldev {
		env = config.LocalDev
	} else if loginSandbox {
		env = config.Sandbox
	}
	log.Debug("login: resolved env relay=%s issuer=%s blob=%s", env.RelayURL, env.IssuerURL, env.BlobURL)

	// Apply overrides if provided
	relayURL := loginRelayURL
	issuerURL := loginIssuerURL
	if relayURL == "" {
		relayURL = env.RelayURL
	}
	if issuerURL == "" {
		issuerURL = env.IssuerURL
	}
	blobURL := env.BlobURL

	if loginShowConfig {
		showConfiguration(profileOverride)
		return
	}

	if loginLogout {
		doLogout(profileOverride)
		return
	}

	if loginListKeys {
		if err := showEnrolledKeys(profileOverride); err != nil {
			die("%v", err)
		}
		return
	}

	login(relayURL, issuerURL, blobURL, loginDeviceName, profileOverride, loginForce)
}

func showConfiguration(profileOverride string) {
	cfg := loadConfigWithProfile(profileOverride)

	fmt.Println("Configuration:")
	fmt.Printf("  Config file: %s\n", config.ConfigPath())
	fmt.Printf("  Profiles dir: %s\n", config.ProfilesDir())
	fmt.Printf("  Device ID: %s\n", cfg.DeviceID)
	fmt.Printf("  Device Name: %s\n", cfg.DeviceName)
	fmt.Printf("  Active Profile: %s\n", cfg.ActiveProfile)
	effectiveProfile := cfg.EffectiveProfile()
	if effectiveProfile != cfg.ActiveProfile {
		fmt.Printf("  Using Profile: %s (via --profile or NB_PROFILE)\n", effectiveProfile)
	}
	fmt.Printf("  Relay URL: %s\n", cfg.RelayURL())
	p, _ := cfg.GetActiveProfile()
	if p != nil && p.BlobURL != "" {
		fmt.Printf("  Blob URL: %s\n", p.BlobURL)
	}

	if cfg.IsLoggedIn() {
		userAccount := cfg.UserAccount()
		fmt.Println("\nUser Account:")
		fmt.Printf("  User ID: %s\n", userAccount.UserID)
		fmt.Printf("  Logged In: %s\n", userAccount.LoggedInAt.Format(time.RFC3339))
		fmt.Printf("  SAS Verified: %v\n", userAccount.SASVerified)
		fmt.Printf("  Devices: %d\n", len(userAccount.Devices))
		for i, dev := range userAccount.Devices {
			fmt.Printf("    %d. %s\n", i+1, dev.DeviceName)
		}
	} else {
		fmt.Println("\nStatus: Not logged in")
	}

	keys := cfg.Keys()
	fmt.Printf("\nEnrolled Keys: %d\n", len(keys))
	for i, key := range keys {
		fmt.Printf("  %d. %s (%s)\n", i+1, key.Label, truncateFingerprint(key.Hex()))
	}
}

func doLogout(profileOverride string) {
	log.Info("logout: invoked profile=%q", profileOverride)
	cfg := loadConfigWithProfile(profileOverride)

	if !cfg.IsLoggedIn() {
		fmt.Println("Not currently logged in.")
		return
	}

	fmt.Print("This will remove your login and all enrolled keys. Continue? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer != "y" && answer != "yes" {
		fmt.Println("Cancelled.")
		return
	}

	if err := clearActiveProfileLoginState(cfg); err != nil {
		die("Error clearing login state: %v", err)
	}
	if err := cfg.Save(); err != nil {
		die("Error saving config: %v", err)
	}
	log.Info("logout: complete profile=%s", cfg.EffectiveProfile())

	fmt.Println("Logged out successfully.")
}

func showEnrolledKeys(profileOverride string) error {
	cfg := loadConfigWithProfile(profileOverride)
	if !cfg.IsLoggedIn() {
		return fmt.Errorf("not logged in: run 'nb login' first")
	}
	display.PrintEnrolledKeys(os.Stdout, cfg.Keys())
	return nil
}

func login(relayURL, issuerURL, blobURL, deviceNameFlag, profileOverride string, force bool) {
	var cfg *config.Config
	var targetProfile string

	if profileOverride != "" {
		// Load config without applying profile override (since it might not exist)
		var err error
		cfg, err = config.Load()
		if err != nil {
			die("Error loading config: %v", err)
		}

		// Check if the specified profile exists, create if not
		if _, err := cfg.GetProfile(profileOverride); err != nil {
			// Profile doesn't exist, create it
			if err := cfg.CreateProfile(profileOverride, relayURL, issuerURL); err != nil {
				die("Error creating profile: %v", err)
			}
		}
		targetProfile = profileOverride

		// Set working profile now that it exists
		if err := cfg.SetWorkingProfile(profileOverride); err != nil {
			die("Error: %v", err)
		}
	} else {
		// No profile override, use loadConfigOrDie which uses active profile
		cfg = loadConfigOrDie()
		targetProfile = cfg.EffectiveProfile()
	}

	// Get the target profile for login
	profileCfg, err := cfg.GetProfile(targetProfile)
	if err != nil {
		die("Error: %v", err)
	}

	// Check if profile already has login credentials (require --force to overwrite)
	if profileCfg.IsLoggedIn() {
		if !force {
			die("Profile '%s' is already logged in. Use --force to re-login or --logout to remove.", targetProfile)
		}
		fmt.Printf("Re-logging in to profile '%s' (currently has %d device(s))...\n", targetProfile, len(profileCfg.UserAccount.Devices))
	}

	// Update URLs in the target profile
	profileCfg.RelayURL = relayURL
	profileCfg.IssuerURL = issuerURL
	profileCfg.BlobURL = blobURL

	// Determine device name
	deviceName := deviceNameFlag
	if deviceName == "" {
		deviceName = cfg.DeviceName
	}

	// Generate our X25519 identity key pair
	log.Debug("login: generating X25519 identity key pair")
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		die("Failed to generate key pair: %v", err)
	}
	log.Debug("login: generated identity key pair pub_len=%d priv_len=%d", len(keyPair.PublicKey), len(keyPair.PrivateKey))

	log.Debug("login: creating auth client issuer=%s device=%s", issuerURL, cfg.DeviceID)
	authClient, err := client.NewClient(issuerURL, cfg.DeviceID)
	if err != nil {
		die("Failed to create API client: %v", err)
	}

	log.Info("login: starting QR-code flow profile=%s device=%s", targetProfile, deviceName)
	loginWithQRCode(cfg, authClient, issuerURL, deviceName, keyPair, targetProfile)
}

// loginWithQRCode performs QR-code based login.
// The CLI displays a QR code that the user scans with their iOS device to authenticate.
func loginWithQRCode(cfg *config.Config, authClient *client.Client, issuerURL string, deviceName string, keyPair *crypto.KeyPair, targetProfile string) {
	fmt.Println("QR Code Login")
	fmt.Println("=============")
	fmt.Println()
	fmt.Printf("Device: %s\n", deviceName)
	fmt.Println()

	ctx := context.Background()

	// 1. Create requester session (no username required)
	fmt.Println("Creating login session...")
	log.Debug("login: creating requester session issuer=%s", issuerURL)
	createReq := &client.CreateRequesterSessionRequest{
		RequesterPublicKeyHex: hex.EncodeToString(keyPair.PublicKey[:]),
		// Device name is now passed in QR code URL for iOS display
	}

	createResp, err := authClient.CreateRequesterSession(ctx, createReq)
	if err != nil {
		die("Failed to create login session: %v", err)
	}
	log.Info("login: requester session created sid=%s expires_at=%s",
		createResp.SessionId, createResp.ExpiresAt.Format(time.RFC3339))

	// 2. Generate QR code with session ID, public key, device name, and username
	// Device name and username are passed in URL for iOS to display during SAS verification
	// Uses HTTPS URL format for Universal Links / App Links support
	username := sysinfo.GetCurrentUsername()
	qrData := fmt.Sprintf("%s/link/login?sid=%s&pk=%s&dn=%s&un=%s",
		issuerURL,
		createResp.SessionId,
		base64.RawURLEncoding.EncodeToString(keyPair.PublicKey[:]),
		url.QueryEscape(deviceName),
		url.QueryEscape(username))

	// 3. Display QR code
	fmt.Println()
	fmt.Println("Scan this QR code with any camera app:")
	fmt.Println()
	displayQRCode(qrData)
	fmt.Println()
	fmt.Printf("Or paste this URL in the app: %s\n", qrData)
	fmt.Printf("Session expires at: %s\n", createResp.ExpiresAt.Local().Format("15:04:05"))
	fmt.Println()

	// 4. Poll for session to be claimed and verified
	fmt.Println("Waiting for QR code scan...")
	log.Debug("login: QR code displayed, polling sid=%s for scan+approval (timeout=5m)", createResp.SessionId)

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer pollCancel()

	pollCfg := client.DefaultPollConfig()

	// First, wait for the session to be claimed and SAS to become available.
	var sasDisplayed bool
	var verified bool
	var status *authapi.GetRequesterSessionStatusResponse
	var lastStatus string

	for !verified {
		status, err = authClient.GetRequesterSessionStatus(pollCtx, createResp.SessionId)
		if err != nil {
			if err == client.ErrExpired {
				die("Login session expired. Please try again.")
			}
			die("Failed to check status: %v", err)
		}

		// If session is claimed (has approver keys) but not yet verified, compute and display SAS locally.
		if status.ApproverKeys != nil && len(*status.ApproverKeys) > 0 && !sasDisplayed {
			log.Debug("login: session claimed sid=%s approver_keys=%d", createResp.SessionId, len(*status.ApproverKeys))
			keys := *status.ApproverKeys
			approverKeys := make([]crypto.SASDeviceKey, 0, len(keys))
			for _, ak := range keys {
				encryptionPublicKeyHex := ptr.DerefString(ak.EncryptionPublicKeyHex)
				if encryptionPublicKeyHex == "" {
					continue
				}
				encPubKey, err := hex.DecodeString(encryptionPublicKeyHex)
				if err != nil {
					die("Failed to decode approver encryption key: %v", err)
				}
				approverKeys = append(approverKeys, crypto.SASDeviceKey{
					ApproverId:             ptr.DerefString(ak.ApproverId),
					EncryptionPublicKeyHex: encryptionPublicKeyHex,
					PublicKey:              encPubKey,
				})
			}
			if len(approverKeys) == 0 {
				die("Session claimed but no approver encryption keys were available for SAS verification")
			}

			log.Debug("login: computing SAS locally approver_count=%d", len(approverKeys))
			sasResult := crypto.ComputeSAS(keyPair.PublicKey[:], approverKeys)
			log.Info("login: SAS computed words=%s", sasResult.WordString)

			fmt.Println()
			fmt.Println("Device connected! Verify these symbols match your iOS device:")
			fmt.Println()
			fmt.Printf("  Emoji: %s\n", sasResult.EmojiString)
			fmt.Printf("  Words: %s\n", sasResult.WordString)
			fmt.Println()
			fmt.Println("Waiting for approval on iOS device...")
			sasDisplayed = true
		}

		// Check final status
		statusStr := ""
		if status.Status != nil {
			statusStr = string(*status.Status)
		}
		if statusStr != lastStatus {
			log.Debug("login: sid=%s status transition %q -> %q", createResp.SessionId, lastStatus, statusStr)
			lastStatus = statusStr
		}
		switch statusStr {
		case "verified":
			log.Info("login: session verified sid=%s", createResp.SessionId)
			verified = true
		case "rejected":
			die("Login was rejected by device.")
		case "expired":
			die("Login session expired. Please try again.")
		case "pending", "claimed":
			// Continue polling (claimed = device scanned, waiting for approval)
		default:
			die("Unexpected status: %s", statusStr)
		}

		if !verified {
			select {
			case <-pollCtx.Done():
				die("Login timed out. Please try again.")
			case <-time.After(pollCfg.InitialInterval):
			}
		}
	}

	// 5. Get OIDC tokens
	fmt.Println()
	fmt.Println("Login approved! Fetching tokens...")

	requesterID, err := verifiedRequesterID(status)
	if err != nil {
		die("%v", err)
	}
	log.Debug("login: fetching OIDC tokens sid=%s requester_id=%s", createResp.SessionId, requesterID)

	tokens, err := authClient.GetSessionTokens(ctx, createResp.SessionId, createResp.TokenClaimSecret)
	if err != nil {
		die("Failed to get tokens: %v", err)
	}
	log.Info("login: OIDC tokens received user_id=%s expires_in=%ds refresh=%v",
		tokens.UserId, tokens.ExpiresIn, tokens.RefreshToken != nil)

	// 6. Fetch devices list (now that we have tokens)
	log.Debug("login: listing user devices user_id=%s", tokens.UserId)
	devices, err := authClient.ListUserDevices(ctx, tokens.UserId, tokens.AccessToken)
	if err != nil {
		die("Failed to list devices: %v", err)
	}
	log.Debug("login: listed %d device(s)", len(devices))

	if len(devices) == 0 {
		die("No devices found in your account. Please register a device via the iOS app first.")
	}

	approverKeys, err := authClient.GetApproverKeys(ctx, tokens.UserId, tokens.AccessToken)
	if err != nil {
		die("Failed to fetch approver keys: %v", err)
	}
	keysByApproverID := make(map[string]string, len(approverKeys))
	for _, key := range approverKeys {
		approverID := ptr.DerefString(key.ApproverId)
		encryptionKey := ptr.DerefString(key.EncryptionPublicKeyHex)
		if approverID == "" || encryptionKey == "" {
			continue
		}
		keysByApproverID[approverID] = encryptionKey
	}
	if len(keysByApproverID) == 0 {
		die("No approver device keys found in your account. Please register a device via the iOS app first.")
	}

	fmt.Printf("Found %d device(s) in your account.\n", len(devices))

	// 7. Store tokens and devices
	configDevices := make([]config.UserDevice, 0, len(devices))
	existingAuthKeys := make(map[string][]byte)
	if activeProfile, profileErr := cfg.GetProfile(targetProfile); profileErr == nil && activeProfile.UserAccount != nil {
		for _, existing := range activeProfile.UserAccount.Devices {
			if existing.ApproverId != "" && len(existing.AuthPublicKey) > 0 {
				existingAuthKeys[existing.ApproverId] = append([]byte(nil), existing.AuthPublicKey...)
			}
		}
	}
	for _, dev := range devices {
		approverID := ptr.DerefString(dev.ApproverId)
		encPubKey, _ := hex.DecodeString(keysByApproverID[approverID])
		var attestPubKey []byte
		if dev.Attestation != nil && dev.Attestation.AttestationPublicKeyHex != nil {
			attestPubKey, _ = hex.DecodeString(*dev.Attestation.AttestationPublicKeyHex)
		}
		log.Debug("Device from API: approverId=%s, name=%s, publicKey len=%d, attestationPublicKey len=%d",
			approverID, ptr.DerefString(dev.DeviceName), len(encPubKey), len(attestPubKey))
		authPublicKey := existingAuthKeys[approverID]
		configDevices = append(configDevices, config.UserDevice{
			ApproverId:           approverID,
			AuthPublicKey:        append([]byte(nil), authPublicKey...),
			DeviceName:           ptr.DerefString(dev.DeviceName),
			PublicKey:            encPubKey,
			AttestationPublicKey: attestPubKey,
		})
	}

	// Calculate token expiration
	expiresAt := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)

	// Convert refresh token pointer to string
	refreshToken := ""
	if tokens.RefreshToken != nil {
		refreshToken = *tokens.RefreshToken
	}

	if err := cfg.SetUserAccount(targetProfile, tokens.UserId, requesterID, tokens.AccessToken, refreshToken, expiresAt, configDevices, keyPair.PrivateKey[:], keyPair.PublicKey[:]); err != nil {
		die("Failed to store credentials: %v", err)
	}
	cfg.VerifySASForProfile(targetProfile)

	if err := cacheApprovalProofConfigForProfile(ctx, cfg, targetProfile, authClient, tokens.AccessToken); err != nil {
		die("Failed to fetch approval proof config: %v", err)
	}
	log.Debug("Fetched approval proof verifier config for profile %s", targetProfile)

	// Update device name if provided
	if deviceName != cfg.DeviceName {
		cfg.DeviceName = deviceName
	}

	// 8. Sync signing keys from devices
	log.Debug("login: syncing signing keys user_id=%s accept_software=%v",
		tokens.UserId, resolveAcceptSoftwareApproverKeys(loginAcceptSoftwareApproverKeys))
	syncedKeys, err := syncSigningKeys(
		cfg,
		authClient,
		tokens.UserId,
		tokens.AccessToken,
		attestationEnvironmentForIssuerURL(issuerURL),
		resolveAcceptSoftwareApproverKeys(loginAcceptSoftwareApproverKeys),
	)
	if err != nil {
		die("Failed to sync signing keys: %v", err)
	}

	validDeviceCount, err := validatedApproverDeviceCount(cfg)
	if err != nil {
		if clearErr := clearActiveProfileLoginState(cfg); clearErr != nil {
			log.Warn("failed to roll back login state after device sync failure: %v", clearErr)
		}
		die("%v", err)
	}

	if err := cfg.Save(); err != nil {
		die("Failed to save configuration: %v", err)
	}
	log.Info("login: complete profile=%s devices=%d synced_keys=%d", targetProfile, validDeviceCount, syncedKeys)

	printLoginSuccess(validDeviceCount, syncedKeys)
}

// clearActiveProfileLoginState moved to login_state.go (ungated) so its
// regression coverage can run in default builds.

func cacheApprovalProofConfigForProfile(
	ctx context.Context,
	cfg *config.Config,
	profileName string,
	authClient *client.Client,
	accessToken string,
) error {
	if authClient == nil {
		return fmt.Errorf("auth client is required")
	}
	authClient.SetAccessToken(accessToken)

	remoteConfig, err := authClient.GetApprovalProofConfig(ctx)
	if err != nil {
		return err
	}

	profile, err := cfg.GetProfile(profileName)
	if err != nil {
		return err
	}

	issuerKeys := make([]config.ApprovalProofIssuerKey, 0, len(remoteConfig.IssuerKeys))
	for _, issuerKey := range remoteConfig.IssuerKeys {
		issuerKeys = append(issuerKeys, config.ApprovalProofIssuerKey{
			KeyID:        issuerKey.KeyId,
			PublicKeyHex: issuerKey.PublicKeyHex,
		})
	}

	profile.ApprovalProofConfig = &config.ApprovalProofVerifierConfig{
		AttestationVersion:      remoteConfig.AttestationVersion,
		ProofVersion:            remoteConfig.ProofVersion,
		CircuitIDHex:            remoteConfig.CircuitIdHex,
		ActiveKeyID:             remoteConfig.ActiveKeyId,
		IssuerKeys:              issuerKeys,
		PolicyVersion:           uint32(remoteConfig.PolicyVersion),
		AttestationLifetimeSecs: int64(remoteConfig.AttestationLifetimeSeconds),
	}
	if remoteConfig.AllowedAppIdHashesHex != nil {
		profile.ApprovalProofConfig.AllowedAppIDHashesHex = append(
			[]string(nil),
			(*remoteConfig.AllowedAppIdHashesHex)...,
		)
	}

	return nil
}

func verifiedRequesterID(status *authapi.GetRequesterSessionStatusResponse) (string, error) {
	if status == nil {
		return "", errors.New("login succeeded but no session status was returned")
	}

	requesterID := ptr.DerefString(status.RequesterId)
	if requesterID == "" {
		return "", errors.New("login succeeded but no requester ID was returned; please try again")
	}

	return requesterID, nil
}

// validatedApproverDeviceCount moved to login_state.go (ungated).
