//go:build linux

package monitor

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	coreDNSTableName    = "ocp_coredns_filter"
	coreDNSChainName    = "coredns_input"
	coreDNSLocalComment = "OCP_COREDNS_LOCAL_ACCESS"
	coreDNSBlockComment = "OCP_COREDNS_BLOCK_EXTERNAL"
	dnsPort             = 53
)

// exprMatchSrcIP builds nftables expressions to match a source IP address.
func exprMatchSrcIP(srcIP string, family nftables.TableFamily) ([]expr.Any, error) {
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", srcIP)
	}

	var ipBytes []byte
	var offset uint32
	var length uint32

	if family == nftables.TableFamilyIPv4 {
		ipBytes = ip.To4()
		offset = 12 // IPv4 source address offset in IP header
		length = 4
	} else {
		ipBytes = ip.To16()
		offset = 8 // IPv6 source address offset in IPv6 header
		length = 16
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          length,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipBytes,
		},
	}, nil
}

// exprMatchL4Proto builds nftables expressions to match a Layer 4 protocol (TCP or UDP).
func exprMatchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},
	}
}

// exprMatchDNSPort builds nftables expressions to match destination port 53.
func exprMatchDNSPort() []expr.Any {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, dnsPort)

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // Destination port offset (same for TCP and UDP)
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     portBytes,
		},
	}
}

// buildCoreDNSAllowRule builds an nftables rule that accepts DNS traffic from a
// specific source IP for a given L4 protocol.
func buildCoreDNSAllowRule(table *nftables.Table, chain *nftables.Chain, srcIP string, family nftables.TableFamily, proto byte) (*nftables.Rule, error) {
	var exprs []expr.Any

	srcExprs, err := exprMatchSrcIP(srcIP, family)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, srcExprs...)
	exprs = append(exprs, exprMatchL4Proto(proto)...)
	exprs = append(exprs, exprMatchDNSPort()...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	}
	rule.UserData = userdata.AppendString(nil, userdata.TypeComment, coreDNSLocalComment)
	return rule, nil
}

// buildCoreDNSBlockRule builds an nftables rule that drops DNS traffic for a
// given L4 protocol (all sources).
func buildCoreDNSBlockRule(table *nftables.Table, chain *nftables.Chain, proto byte) *nftables.Rule {
	var exprs []expr.Any

	exprs = append(exprs, exprMatchL4Proto(proto)...)
	exprs = append(exprs, exprMatchDNSPort()...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	}
	rule.UserData = userdata.AppendString(nil, userdata.TypeComment, coreDNSBlockComment)
	return rule
}

// findCoreDNSTable looks up the CoreDNS filter table for the given family.
// Returns nil if the table does not exist.
func findCoreDNSTable(conn *nftables.Conn, family nftables.TableFamily) *nftables.Table {
	tables, err := conn.ListTablesOfFamily(family)
	if err != nil {
		return nil
	}
	for _, table := range tables {
		if table.Name == coreDNSTableName {
			return table
		}
	}
	return nil
}

// findCoreDNSChain looks up the CoreDNS input chain within the given table.
// Returns nil if the chain does not exist.
func findCoreDNSChain(conn *nftables.Conn, table *nftables.Table) *nftables.Chain {
	chains, err := conn.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return nil
	}
	for _, chain := range chains {
		if chain.Table.Name == table.Name && chain.Name == coreDNSChainName {
			return chain
		}
	}
	return nil
}

// coreDNSRulesExistForFamily checks whether the CoreDNS blocking rules are
// present for a given IP family. It looks for the OCP_COREDNS_BLOCK_EXTERNAL
// comment on rules in the chain.
func coreDNSRulesExistForFamily(conn *nftables.Conn, family nftables.TableFamily) bool {
	table := findCoreDNSTable(conn, family)
	if table == nil {
		return false
	}
	chain := findCoreDNSChain(conn, table)
	if chain == nil {
		return false
	}
	rule, _ := findRuleByComment(conn, chain, coreDNSBlockComment)
	return rule != nil
}

// ensureCoreDNSFirewallRulesForFamily creates the nftables table, chain, and
// rules to block external DNS access for a single IP family (IPv4 or IPv6).
// The function is idempotent: if rules already exist, it returns immediately.
func ensureCoreDNSFirewallRulesForFamily(family nftables.TableFamily, localhostIP string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to create nftables connection: %v", err)
	}
	defer conn.CloseLasting()

	// Check if rules already exist
	if coreDNSRulesExistForFamily(conn, family) {
		return nil
	}

	// Delete old table if it exists (clean up partial state)
	if existing := findCoreDNSTable(conn, family); existing != nil {
		conn.DelTable(existing)
	}

	// Create table
	table := conn.AddTable(&nftables.Table{
		Family: family,
		Name:   coreDNSTableName,
	})

	// Create input filter chain
	chain := conn.AddChain(&nftables.Chain{
		Name:     coreDNSChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	// Add allow rules first (order matters: allow localhost before blocking all)
	// Allow TCP from localhost
	allowTCP, err := buildCoreDNSAllowRule(table, chain, localhostIP, family, unix.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("failed to build allow TCP rule: %v", err)
	}
	conn.AddRule(allowTCP)

	// Allow UDP from localhost
	allowUDP, err := buildCoreDNSAllowRule(table, chain, localhostIP, family, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("failed to build allow UDP rule: %v", err)
	}
	conn.AddRule(allowUDP)

	// Block all external TCP to DNS port
	conn.AddRule(buildCoreDNSBlockRule(table, chain, unix.IPPROTO_TCP))

	// Block all external UDP to DNS port
	conn.AddRule(buildCoreDNSBlockRule(table, chain, unix.IPPROTO_UDP))

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables changes: %v", err)
	}

	log.WithFields(logrus.Fields{
		"table":  coreDNSTableName,
		"family": family,
	}).Info("Applied CoreDNS external access blocking rules")

	return nil
}

// ensureCoreDNSFirewallRules ensures nftables rules are in place to block
// external DNS access on port 53, allowing only localhost (127.0.0.1 and ::1).
// Rules are applied for both IPv4 and IPv6 families.
func ensureCoreDNSFirewallRules() error {
	if err := ensureCoreDNSFirewallRulesForFamily(nftables.TableFamilyIPv4, "127.0.0.1"); err != nil {
		return fmt.Errorf("failed to ensure CoreDNS IPv4 firewall rules: %v", err)
	}
	if err := ensureCoreDNSFirewallRulesForFamily(nftables.TableFamilyIPv6, "::1"); err != nil {
		return fmt.Errorf("failed to ensure CoreDNS IPv6 firewall rules: %v", err)
	}
	return nil
}

// cleanCoreDNSFirewallRulesForFamily removes the CoreDNS filter table for a
// single IP family. Removing the table removes all chains and rules within it.
func cleanCoreDNSFirewallRulesForFamily(family nftables.TableFamily) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to create nftables connection: %v", err)
	}
	defer conn.CloseLasting()

	table := findCoreDNSTable(conn, family)
	if table == nil {
		return nil // Already clean
	}

	conn.DelTable(table)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables changes: %v", err)
	}

	log.WithFields(logrus.Fields{
		"table":  coreDNSTableName,
		"family": family,
	}).Info("Removed CoreDNS external access blocking rules")

	return nil
}

// cleanCoreDNSFirewallRules removes all nftables rules that block external DNS
// access, for both IPv4 and IPv6.
func cleanCoreDNSFirewallRules() error {
	var firstErr error
	if err := cleanCoreDNSFirewallRulesForFamily(nftables.TableFamilyIPv4); err != nil {
		log.WithFields(logrus.Fields{"err": err}).Error("Failed to clean CoreDNS IPv4 firewall rules")
		firstErr = err
	}
	if err := cleanCoreDNSFirewallRulesForFamily(nftables.TableFamilyIPv6); err != nil {
		log.WithFields(logrus.Fields{"err": err}).Error("Failed to clean CoreDNS IPv6 firewall rules")
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// checkCoreDNSFirewallRules checks whether CoreDNS external access blocking
// rules are in place for both IPv4 and IPv6.
func checkCoreDNSFirewallRules() (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("failed to create nftables connection: %v", err)
	}
	defer conn.CloseLasting()

	v4 := coreDNSRulesExistForFamily(conn, nftables.TableFamilyIPv4)
	v6 := coreDNSRulesExistForFamily(conn, nftables.TableFamilyIPv6)
	return v4 && v6, nil
}
