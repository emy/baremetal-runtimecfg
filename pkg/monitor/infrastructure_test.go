package monitor

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestParseExternalDNSAccessPolicy(t *testing.T) {
	tests := []struct {
		name     string
		infra    *configv1.Infrastructure
		expected configv1.ExternalDNSAccessPolicyType
	}{
		{
			name: "returns Deny when baremetal spec is nil",
			infra: &configv1.Infrastructure{
				Spec: configv1.InfrastructureSpec{
					PlatformSpec: configv1.PlatformSpec{
						BareMetal: nil,
					},
				},
			},
			expected: configv1.ExternalDNSAccessPolicyDeny,
		},
		{
			name: "returns Deny when field is empty",
			infra: &configv1.Infrastructure{
				Spec: configv1.InfrastructureSpec{
					PlatformSpec: configv1.PlatformSpec{
						BareMetal: &configv1.BareMetalPlatformSpec{},
					},
				},
			},
			expected: configv1.ExternalDNSAccessPolicyDeny,
		},
		{
			name: "returns Deny when field is Deny",
			infra: &configv1.Infrastructure{
				Spec: configv1.InfrastructureSpec{
					PlatformSpec: configv1.PlatformSpec{
						BareMetal: &configv1.BareMetalPlatformSpec{
							ExternalDNSAccessPolicy: configv1.ExternalDNSAccessPolicyDeny,
						},
					},
				},
			},
			expected: configv1.ExternalDNSAccessPolicyDeny,
		},
		{
			name: "returns Allow when field is Allow",
			infra: &configv1.Infrastructure{
				Spec: configv1.InfrastructureSpec{
					PlatformSpec: configv1.PlatformSpec{
						BareMetal: &configv1.BareMetalPlatformSpec{
							ExternalDNSAccessPolicy: configv1.ExternalDNSAccessPolicyAllow,
						},
					},
				},
			},
			expected: configv1.ExternalDNSAccessPolicyAllow,
		},
		{
			name: "returns Deny for unknown policy value",
			infra: &configv1.Infrastructure{
				Spec: configv1.InfrastructureSpec{
					PlatformSpec: configv1.PlatformSpec{
						BareMetal: &configv1.BareMetalPlatformSpec{
							ExternalDNSAccessPolicy: configv1.ExternalDNSAccessPolicyType("Unknown"),
						},
					},
				},
			},
			expected: configv1.ExternalDNSAccessPolicyDeny,
		},
		{
			name:     "returns Deny for empty infrastructure object",
			infra:    &configv1.Infrastructure{},
			expected: configv1.ExternalDNSAccessPolicyDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseExternalDNSAccessPolicy(tt.infra)
			if result != tt.expected {
				t.Errorf("parseExternalDNSAccessPolicy() = %v, want %v", result, tt.expected)
			}
		})
	}
}
