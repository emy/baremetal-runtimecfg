package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/baremetal-runtimecfg/pkg/utils"
	"k8s.io/client-go/rest"
)

const infrastructureAPIPath = "/apis/config.openshift.io/v1/infrastructures/cluster"

// getExternalDNSAccessPolicy reads the Infrastructure CR "cluster" and returns
// the value of spec.platformSpec.baremetal.externalDNSAccessPolicy.
// Returns ExternalDNSAccessPolicyDeny if the field is unset, if the platform
// is not bare metal, or on any error (fail-secure).
func getExternalDNSAccessPolicy(kubeconfigPath string) (configv1.ExternalDNSAccessPolicyType, error) {
	restConfig, err := utils.GetClientConfig("", kubeconfigPath)
	if err != nil {
		return configv1.ExternalDNSAccessPolicyDeny, fmt.Errorf("failed to get client config: %v", err)
	}

	transport, err := rest.TransportFor(restConfig)
	if err != nil {
		return configv1.ExternalDNSAccessPolicyDeny, fmt.Errorf("failed to create transport: %v", err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	url := restConfig.Host + infrastructureAPIPath
	resp, err := client.Get(url)
	if err != nil {
		return configv1.ExternalDNSAccessPolicyDeny, fmt.Errorf("failed to get Infrastructure CR: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return configv1.ExternalDNSAccessPolicyDeny, fmt.Errorf("unexpected status code %d reading Infrastructure CR", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return configv1.ExternalDNSAccessPolicyDeny, fmt.Errorf("failed to read Infrastructure CR response: %v", err)
	}

	var infra configv1.Infrastructure
	if err := json.Unmarshal(body, &infra); err != nil {
		return configv1.ExternalDNSAccessPolicyDeny, fmt.Errorf("failed to unmarshal Infrastructure CR: %v", err)
	}

	return parseExternalDNSAccessPolicy(&infra), nil
}

// parseExternalDNSAccessPolicy extracts the externalDNSAccessPolicy from a
// typed Infrastructure object. Returns ExternalDNSAccessPolicyDeny if the
// field is unset or the platform is not bare metal.
func parseExternalDNSAccessPolicy(infra *configv1.Infrastructure) configv1.ExternalDNSAccessPolicyType {
	if infra.Spec.PlatformSpec.BareMetal == nil {
		return configv1.ExternalDNSAccessPolicyDeny
	}

	policy := infra.Spec.PlatformSpec.BareMetal.ExternalDNSAccessPolicy
	if policy == configv1.ExternalDNSAccessPolicyAllow {
		return configv1.ExternalDNSAccessPolicyAllow
	}
	return configv1.ExternalDNSAccessPolicyDeny
}
