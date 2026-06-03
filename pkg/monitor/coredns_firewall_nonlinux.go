//go:build !linux

package monitor

import "fmt"

// ensureCoreDNSFirewallRules returns an error on non-Linux platforms because
// nftables firewall rules are only supported on Linux.
func ensureCoreDNSFirewallRules() error {
	return fmt.Errorf("CoreDNS nftables firewall rules are only supported on Linux")
}

// cleanCoreDNSFirewallRules returns an error on non-Linux platforms because
// nftables firewall rules are only supported on Linux.
func cleanCoreDNSFirewallRules() error {
	return fmt.Errorf("CoreDNS nftables firewall rules are only supported on Linux")
}

// checkCoreDNSFirewallRules returns an error on non-Linux platforms because
// nftables firewall rules are only supported on Linux.
func checkCoreDNSFirewallRules() (bool, error) {
	return false, fmt.Errorf("CoreDNS nftables firewall rules are only supported on Linux")
}
