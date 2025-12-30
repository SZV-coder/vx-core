package sshhelper

import (
	"strings"
)

func (c *Client) GetServerOS() (string, error) {
	// Try /etc/os-release first (modern standard)
	output, err := c.CombinedOutput("grep '^PRETTY_NAME=' /etc/os-release | cut -d'=' -f2 | tr -d '\"'", false)
	if err == nil && output != "" {
		return output, nil
	}

	return c.CombinedOutput("uname -s", false)
}

// IsRoot checks if the current user is root (UID 0) or has sudo privileges
// Returns true if:
//   - The user is already root (id -u returns 0)
//
// Returns false otherwise
func (c *Client) IsRoot() (bool, error) {
	// First check if user is already root
	output, err := c.Output("id -u", false)
	if err == nil {
		uid := strings.TrimSpace(output)
		if uid == "0" {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) HasPasswordlessSudo() (bool, error) {
	// Check if user has passwordless sudo
	_, err := c.Output("sudo -n true", false)
	if err == nil {
		return true, nil
	}

	return false, nil
}
