package plugin

import (
	"fmt"
	"time"
)

// ViolationType classifies the kind of runtime safety violation.
type ViolationType string

const (
	// ViolationRateLimit indicates the plugin exceeded its request rate limit.
	ViolationRateLimit ViolationType = "rate_limit_exceeded"
	// ViolationBandwidth indicates the plugin exceeded its bandwidth limit.
	ViolationBandwidth ViolationType = "bandwidth_exceeded"
	// ViolationSecretLeaked indicates the plugin output contained a secret.
	ViolationSecretLeaked ViolationType = "secret_leaked"
	// ViolationUnauthorizedAction indicates the plugin attempted a non-read-only
	// action when the policy only allows passive operations.
	ViolationUnauthorizedAction ViolationType = "unauthorized_action"
)

// RuntimeViolation records a safety constraint breach by a plugin at runtime.
type RuntimeViolation struct {
	Type       ViolationType
	PluginName string
	Message    string
	Timestamp  time.Time
}

// Error implements the error interface.
func (v RuntimeViolation) Error() string {
	return fmt.Sprintf("runtime violation [%s] plugin %q: %s", v.Type, v.PluginName, v.Message)
}
