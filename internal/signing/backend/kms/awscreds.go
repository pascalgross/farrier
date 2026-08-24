package kms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// imdsBase is the EC2 instance metadata service.
//
// A constant rather than a setting: an address a caller could change is a way to hand a signing tool
// somebody else's credentials. Tests reach the credential chain by supplying a credential directly
// rather than by redirecting this.
const imdsBase = "http://169.254.169.254"

// awsCredentials finds a credential, in the order an operator would expect.
//
// Environment first, then the shared credentials file, then the instance metadata service. The order
// matters on a laptop, where the metadata address does not refuse a connection but black-holes it: a
// chain that asked the network first would spend its whole budget discovering nothing.
//
// Four flows are deliberately absent — SSO, credential_process, source_profile role assumption, and
// web identity federation — because between them they are most of what an SDK's config package
// contains, and the escape hatch is one command:
//
//	eval "$(aws configure export-credentials --profile ops --format env)"
//
// which turns any of them into the three variables read below. That is documented in docs/INSTALL.md
// rather than implemented here.
func awsCredentials(ctx context.Context) (awsCredential, error) {
	if cred, ok := awsCredentialFromEnv(); ok {
		return cred, nil
	}
	cred, err := awsCredentialFromFile()
	if err != nil {
		return awsCredential{}, err
	}
	if cred.accessKeyID != "" {
		return cred, nil
	}
	return awsCredentialFromIMDS(ctx)
}

// awsCredentialFromEnv reads the three standard variables.
func awsCredentialFromEnv() (awsCredential, bool) {
	id, secret := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")
	if id == "" || secret == "" {
		return awsCredential{}, false
	}
	return awsCredential{
		accessKeyID:     id,
		secretAccessKey: secret,
		sessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}, true
}

// awsCredentialFromFile reads ~/.aws/credentials, honouring AWS_PROFILE.
//
// A hand-rolled INI reader rather than the TOML package already in go.mod, because the AWS credentials
// file is not TOML: its values are unquoted, so a secret containing a "#" or a "=" parses differently
// under the two, and the one that is wrong is the one that fails at signing time with an opaque
// signature mismatch.
//
// A missing file is not an error — it is the ordinary state of a machine that uses environment
// variables or an instance role — so it returns an empty credential and lets the chain continue.
func awsCredentialFromFile() (awsCredential, error) {
	path := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			//nolint:nilerr // A machine with no home directory has no ~/.aws/credentials, which is
			// the ordinary state of a container rather than a fault. Returning the error here would
			// stop the chain before the metadata service, which is exactly where such a machine's
			// credential comes from.
			return awsCredential{}, nil
		}
		path = filepath.Join(home, ".aws", "credentials")
	}
	//nolint:gosec // G703 flags a path from the environment. That is the point: this is the AWS SDKs'
	// own AWS_SHARED_CREDENTIALS_FILE, read on behalf of the operator who set it, in a command they
	// ran themselves. There is no lower-privileged caller to protect from their own environment, and
	// the repository already excludes the same finding's older spelling for the same reason.
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return awsCredential{}, nil
	}
	if err != nil {
		return awsCredential{}, fmt.Errorf("kms: reading %s: %w", path, err)
	}

	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = "default"
	}

	var cred awsCredential
	inProfile := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// The AWS CLI writes "[profile name]" in config and a bare "[name]" in credentials.
			// Accepting both means one reader covers a file an operator may have written either way.
			name := strings.TrimSpace(strings.Trim(line, "[]"))
			name = strings.TrimPrefix(name, "profile ")
			inProfile = name == profile
			continue
		}
		if !inProfile {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "aws_access_key_id":
			cred.accessKeyID = strings.TrimSpace(value)
		case "aws_secret_access_key":
			cred.secretAccessKey = strings.TrimSpace(value)
		case "aws_session_token":
			cred.sessionToken = strings.TrimSpace(value)
		}
	}
	if cred.accessKeyID != "" && cred.secretAccessKey == "" {
		return awsCredential{}, fmt.Errorf("kms: the %s profile in %s has an access key id and no "+
			"secret access key", profile, path)
	}
	return cred, nil
}

// awsIMDSCredential is what the metadata service answers for a role.
type awsIMDSCredential struct {
	// AccessKeyId, SecretAccessKey and Token are the temporary credential.
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}

// awsCredentialFromIMDS asks the instance metadata service for the instance's role credentials.
//
// IMDSv2 only: the token-first protocol is what makes the metadata service unreachable from a confused
// deputy inside a container or behind a proxy, and falling back to v1 when v2 fails would undo that on
// exactly the hosts where somebody had turned v1 off deliberately.
func awsCredentialFromIMDS(ctx context.Context) (awsCredential, error) {
	token, err := imdsToken(ctx)
	if err != nil {
		return awsCredential{}, err
	}

	roles, err := imdsGet(ctx, token, "/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return awsCredential{}, err
	}
	role := strings.TrimSpace(strings.SplitN(strings.TrimSpace(roles), "\n", 2)[0])
	if role == "" {
		return awsCredential{}, errors.New("kms: this instance has no IAM role attached, and no AWS " +
			"credentials were found in the environment or in ~/.aws/credentials")
	}

	body, err := imdsGet(ctx, token, "/latest/meta-data/iam/security-credentials/"+role)
	if err != nil {
		return awsCredential{}, err
	}
	var parsed awsIMDSCredential
	if err := decodeJSONString(body, &parsed); err != nil {
		return awsCredential{}, fmt.Errorf("kms: the instance metadata service returned a credential "+
			"this build cannot read: %w", err)
	}
	if parsed.AccessKeyID == "" || parsed.SecretAccessKey == "" {
		return awsCredential{}, errors.New("kms: the instance metadata service returned an incomplete credential")
	}
	return awsCredential{
		accessKeyID:     parsed.AccessKeyID,
		secretAccessKey: parsed.SecretAccessKey,
		sessionToken:    parsed.Token,
	}, nil
}

// imdsToken takes an IMDSv2 session token.
func imdsToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, imdsBase+"/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")

	res, err := httpClient.Do(req)
	if err != nil {
		// The message names the whole chain rather than this step, because on a laptop this is where
		// "no credentials configured" actually surfaces: the address does not refuse, it black-holes,
		// and the useful sentence is the one that says what to set.
		return "", fmt.Errorf("kms: no AWS credentials in AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, "+
			"none in ~/.aws/credentials, and the instance metadata service did not answer: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	token, err := readBounded(res)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kms: the instance metadata service refused a session token: %d", res.StatusCode)
	}
	return token, nil
}

// imdsGet reads one metadata path with a session token.
func imdsGet(ctx context.Context, token, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsBase+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)

	res, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms: reading %s from the instance metadata service: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := readBounded(res)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kms: the instance metadata service answered %d for %s", res.StatusCode, path)
	}
	return body, nil
}
