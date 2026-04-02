package configmgr

// TODO: Delete this entire file once go-git v6 is released.
// go-git v6 adds full multi_ack/multi_ack_detailed pack-protocol support,
// which makes the system-git fallback for Azure DevOps unnecessary.
// Tracking: https://github.com/go-git/go-git/issues/64
// Merged to go-git main at commit 14eabbda76d37e2dfcfa25b3ac236f2365adb6da.
//
// When removing: delete this file and remove the three IsAzureDevOpsURL /
// gc.tempDir branches in Start(), schedule(), and Stop() in git.go.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	gitv5 "github.com/go-git/go-git/v5"
)

// IsAzureDevOpsURL reports whether rawURL points to an Azure DevOps
// repository. Azure DevOps is incompatible with go-git's pack-protocol
// negotiation, so these repos require a system-git fallback.
func IsAzureDevOpsURL(rawURL string) bool {
	return strings.Contains(rawURL, "dev.azure.com") ||
		strings.Contains(rawURL, "visualstudio.com")
}

// writeAskpassScript writes a minimal GIT_ASKPASS helper script to a temp
// file. Git calls the script with the prompt text as $1; the script replies
// with the username or password depending on the prompt, without ever
// exposing credentials in argv. The script is chmod 0o700 so only the
// current user can read or execute it. The caller is responsible for
// removing the file when done.
func writeAskpassScript(username, password string) (string, error) {
	f, err := os.CreateTemp("", "git-askpass-*.sh")
	if err != nil {
		return "", fmt.Errorf("failed to create askpass script: %w", err)
	}
	defer func() { _ = f.Close() }()
	// Git calls GIT_ASKPASS with the prompt text as $1.  We match on
	// "username" (case-insensitive) to return the right value for each prompt.
	script := "#!/bin/sh\ncase \"$1\" in\n  *[Uu]sername*) echo " +
		shellescape(username) + " ;;\n  *) echo " +
		shellescape(password) + " ;;\nesac\n"
	if _, err := f.WriteString(script); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("failed to write askpass script: %w", err)
	}
	if err := os.Chmod(f.Name(), 0o700); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("failed to chmod askpass script: %w", err)
	}
	return f.Name(), nil
}

// shellescape single-quote escapes a string for safe embedding in a POSIX
// shell script.
func shellescape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// cloneWithSystemGit clones the repository using the system git binary to a
// temporary directory. It is used as a fallback for hosts (e.g. Azure DevOps)
// that are incompatible with go-git's pack-protocol negotiation.
// The caller is responsible for removing the returned directory when done.
func (gc *gitConfigManager) cloneWithSystemGit(branch string) (string, *gitv5.Repository, error) {
	dir, err := os.MkdirTemp("", "orb-git-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir for git clone: %w", err)
	}

	cloneURL := gc.config.URL
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if gc.config.SkipTLS {
		env = append(env, "GIT_SSL_NO_VERIFY=true")
	}

	switch gc.config.Auth {
	case "basic":
		askpass, err := writeAskpassScript(gc.config.Username, gc.config.Password)
		if err != nil {
			_ = os.RemoveAll(dir)
			return "", nil, err
		}
		defer func() { _ = os.Remove(askpass) }()
		env = append(env,
			"GIT_ASKPASS="+askpass,
			"GIT_USERNAME="+gc.config.Username,
		)
	case "ssh":
		if gc.config.PrivateKey != "" {
			// NOTE: passphrase-protected keys are not supported in this fallback
			// path. BatchMode=yes disables prompting, and wiring SSH_ASKPASS for
			// passphrases requires OpenSSH >= 8.4 (SSH_ASKPASS_REQUIRE=force).
			// In practice ADO SSH keys are unprotected deploy keys; if a
			// passphrase is needed, unlock the key via ssh-agent before starting
			// the agent. This limitation goes away when go-git v6 is released.
			env = append(env,
				"GIT_SSH_COMMAND=ssh -i '"+gc.config.PrivateKey+
					"' -o StrictHostKeyChecking=no -o BatchMode=yes")
		}
	}

	args := []string{"clone"}
	if branch != "" {
		args = append(args, "--branch", branch, "--single-branch")
	}
	args = append(args, cloneURL, dir)

	cmd := exec.Command("git", args...)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("system git clone failed: %w\n%s", err, out)
	}

	repo, err := gitv5.PlainOpen(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("failed to open cloned repo: %w", err)
	}

	return dir, repo, nil
}

// fetchWithSystemGit runs "git fetch" with an explicit refspec to update
// refs/heads/<branch>. Used for scheduled updates when the system-git
// fallback is active.
func (gc *gitConfigManager) fetchWithSystemGit() error {
	if gc.tempDir == "" {
		return errors.New("system git fallback not initialized; clone must be called first")
	}
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if gc.config.SkipTLS {
		env = append(env, "GIT_SSL_NO_VERIFY=true")
	}

	fetchURL := gc.config.URL
	switch gc.config.Auth {
	case "basic":
		askpass, err := writeAskpassScript(gc.config.Username, gc.config.Password)
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(askpass) }()
		env = append(env,
			"GIT_ASKPASS="+askpass,
			"GIT_USERNAME="+gc.config.Username,
		)
	case "ssh":
		if gc.config.PrivateKey != "" {
			// See note in cloneWithSystemGit: passphrase-protected keys are not
			// supported without ssh-agent pre-unlocking the key.
			env = append(env,
				"GIT_SSH_COMMAND=ssh -i '"+gc.config.PrivateKey+
					"' -o StrictHostKeyChecking=no -o BatchMode=yes")
		}
	}

	refspec := "refs/heads/" + gc.config.Branch + ":refs/heads/" + gc.config.Branch
	cmd := exec.Command("git", "-C", gc.tempDir, "fetch", "--update-head-ok", fetchURL, refspec)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("system git fetch failed: %w\n%s", err, out)
	}
	return nil
}
