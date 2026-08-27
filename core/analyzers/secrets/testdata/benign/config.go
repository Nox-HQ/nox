package config

// Config holds the third-party integration credentials. The struct tags name
// each config key; no credential values appear in this file. A scanner must not
// treat a json/env tag NAME as a leaked secret.
type Config struct {
	OpenAIAPIKey      string `json:"openai_api_key"        env:"OPENAI_API_KEY"`
	AnthropicAPIKey   string `json:"anthropic_api_key"     env:"ANTHROPIC_API_KEY"`
	CohereAPIKey      string `json:"cohere_api_key"        env:"COHERE_API_KEY"`
	StripeSecretKey   string `json:"stripe_secret_key"     env:"STRIPE_SECRET_KEY"`
	TwilioAccountSID  string `json:"twilio_account_sid"    env:"TWILIO_ACCOUNT_SID"`
	TwilioAuthToken   string `json:"twilio_auth_token"     env:"TWILIO_AUTH_TOKEN"`
	SendgridAPIKey    string `json:"sendgrid_api_key"      env:"SENDGRID_API_KEY"`
	MailgunAPIKey     string `json:"mailgun_api_key"       env:"MAILGUN_API_KEY"`
	DatadogAPIKey     string `json:"datadog_api_key"       env:"DATADOG_API_KEY"`
	PagerDutyAPIKey   string `json:"pagerduty_api_key"     env:"PAGERDUTY_API_KEY"`
	BraintreeMerchant string `json:"braintree_merchant_id" env:"BRAINTREE_MERCHANT_ID"`
	PlaidClientID     string `json:"plaid_client_id"       env:"PLAID_CLIENT_ID"`
	PlaidSecret       string `json:"plaid_secret"          env:"PLAID_SECRET"`
	AdyenAPIKey       string `json:"adyen_api_key"         env:"ADYEN_API_KEY"`
	RecurlyAPIKey     string `json:"recurly_api_key"       env:"RECURLY_API_KEY"`
	XeroConsumerKey   string `json:"xero_consumer_key"     env:"XERO_CONSUMER_KEY"`
	QuickbooksSecret  string `json:"quickbooks_client_secret" env:"QUICKBOOKS_CLIENT_SECRET"`
	FreshbooksAPIKey  string `json:"freshbooks_api_key"    env:"FRESHBOOKS_API_KEY"`
	BillwerkAPIKey    string `json:"billwerk_api_key"      env:"BILLWERK_API_KEY"`
	FreeagentAPIToken string `json:"freeagent_api_token"   env:"FREEAGENT_API_TOKEN"`
	JenkinsAPIToken   string `json:"jenkins_api_token"     env:"JENKINS_API_TOKEN"`
	MobicentsSecret   string `json:"mobicents_secret"      env:"MOBICENTS_SECRET"`
	SpreedlyToken     string `json:"spreedly_token"        env:"SPREEDLY_TOKEN"`
}
