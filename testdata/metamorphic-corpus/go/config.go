package config

// Credentials for the payments service. Loaded at startup.

const (
	AWSAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	StripeSecretKey    = "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGHIJ"
	DatabasePassword   = "prod-db-pa55word-do-not-share"
)

// Config returns the static service configuration.
func Config() map[string]string {
	return map[string]string{
		"region":     "us-east-1",
		"access_key": AWSAccessKeyID,
		"secret_key": AWSSecretAccessKey,
	}
}
