package plugin

import (
	"time"

	"github.com/nox-hq/nox/registry"
)

// ProfileForTrack returns a pre-built safety Policy for the given track.
// The returned policy encodes the default safety characteristics for the track
// (e.g. passive tracks get stricter limits than active tracks).
// Returns DefaultPolicy() for unrecognized tracks.
func ProfileForTrack(track registry.Track) Policy {
	switch track {
	case registry.TrackCoreAnalysis:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			MaxArtifactBytes:      50 * 1024 * 1024, // 50 MB — large codebases
			MaxConcurrency:        4,
			ToolInvocationTimeout: 2 * time.Minute,
			RequestsPerMinute:     120,
			BandwidthBytesPerMin:  100 * 1024 * 1024,
		}

	case registry.TrackDynamicRuntime:
		return Policy{
			MaxRiskClass:          RiskClassActive,
			AllowConfirmationReqd: true,
			AllowedNetworkHosts:   []string{"localhost", "127.0.0.1", "::1"},
			MaxArtifactBytes:      10 * 1024 * 1024,
			MaxConcurrency:        2,
			ToolInvocationTimeout: 5 * time.Minute,
			RequestsPerMinute:     60,
			BandwidthBytesPerMin:  50 * 1024 * 1024,
		}

	case registry.TrackAISecurity:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			MaxArtifactBytes:      50 * 1024 * 1024,
			MaxConcurrency:        4,
			ToolInvocationTimeout: 2 * time.Minute,
			RequestsPerMinute:     120,
			BandwidthBytesPerMin:  100 * 1024 * 1024,
		}

	case registry.TrackThreatModeling:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			MaxArtifactBytes:      20 * 1024 * 1024,
			MaxConcurrency:        2,
			ToolInvocationTimeout: 2 * time.Minute,
			RequestsPerMinute:     60,
			BandwidthBytesPerMin:  50 * 1024 * 1024,
		}

	case registry.TrackSupplyChain:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			AllowedNetworkHosts:   []string{"*.osv.dev", "*.github.com", "*.npmjs.org", "*.pypi.org"},
			MaxArtifactBytes:      20 * 1024 * 1024,
			MaxConcurrency:        4,
			ToolInvocationTimeout: 3 * time.Minute,
			RequestsPerMinute:     120,
			BandwidthBytesPerMin:  100 * 1024 * 1024,
		}

	case registry.TrackIntelligence:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			AllowedNetworkHosts:   []string{"*.osv.dev", "*.github.com", "*.nvd.nist.gov"},
			MaxArtifactBytes:      10 * 1024 * 1024,
			MaxConcurrency:        2,
			ToolInvocationTimeout: 3 * time.Minute,
			RequestsPerMinute:     60,
			BandwidthBytesPerMin:  50 * 1024 * 1024,
		}

	case registry.TrackPolicyGovernance:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			MaxArtifactBytes:      10 * 1024 * 1024,
			MaxConcurrency:        2,
			ToolInvocationTimeout: 1 * time.Minute,
			RequestsPerMinute:     60,
			BandwidthBytesPerMin:  50 * 1024 * 1024,
		}

	case registry.TrackIncidentReadiness:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			MaxArtifactBytes:      10 * 1024 * 1024,
			MaxConcurrency:        2,
			ToolInvocationTimeout: 1 * time.Minute,
			RequestsPerMinute:     60,
			BandwidthBytesPerMin:  50 * 1024 * 1024,
		}

	case registry.TrackDeveloperExperience:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			MaxArtifactBytes:      20 * 1024 * 1024,
			MaxConcurrency:        4,
			ToolInvocationTimeout: 1 * time.Minute,
			RequestsPerMinute:     120,
			BandwidthBytesPerMin:  100 * 1024 * 1024,
		}

	case registry.TrackAgentAssistance:
		return Policy{
			MaxRiskClass:          RiskClassPassive,
			AllowedNetworkHosts:   []string{"*.openai.com", "*.anthropic.com", "*.googleapis.com"},
			AllowedEnvVars:        []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"},
			MaxArtifactBytes:      10 * 1024 * 1024,
			MaxConcurrency:        2,
			ToolInvocationTimeout: 2 * time.Minute,
			RequestsPerMinute:     30,
			BandwidthBytesPerMin:  50 * 1024 * 1024,
		}

	default:
		return DefaultPolicy()
	}
}

// MergeWithUserPolicy merges a track-specific profile with user-provided policy
// overrides. User values take precedence where set (non-zero). This allows users
// to tighten or relax track defaults via .nox.yaml.
func MergeWithUserPolicy(profile, user Policy) Policy {
	merged := profile

	if len(user.AllowedNetworkHosts) > 0 {
		merged.AllowedNetworkHosts = user.AllowedNetworkHosts
	}
	if len(user.AllowedNetworkCIDRs) > 0 {
		merged.AllowedNetworkCIDRs = user.AllowedNetworkCIDRs
	}
	if len(user.AllowedFilePaths) > 0 {
		merged.AllowedFilePaths = user.AllowedFilePaths
	}
	if len(user.AllowedEnvVars) > 0 {
		merged.AllowedEnvVars = user.AllowedEnvVars
	}
	if user.MaxRiskClass != "" {
		merged.MaxRiskClass = user.MaxRiskClass
	}
	if user.AllowConfirmationReqd {
		merged.AllowConfirmationReqd = true
	}
	if user.MaxArtifactBytes > 0 {
		merged.MaxArtifactBytes = user.MaxArtifactBytes
	}
	if user.MaxConcurrency > 0 {
		merged.MaxConcurrency = user.MaxConcurrency
	}
	if user.ToolInvocationTimeout > 0 {
		merged.ToolInvocationTimeout = user.ToolInvocationTimeout
	}
	if user.RequestsPerMinute > 0 {
		merged.RequestsPerMinute = user.RequestsPerMinute
	}
	if user.BandwidthBytesPerMin > 0 {
		merged.BandwidthBytesPerMin = user.BandwidthBytesPerMin
	}

	return merged
}
