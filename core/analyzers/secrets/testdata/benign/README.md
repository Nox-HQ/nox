# Configuration Reference

This service reads all credentials from the environment. The following keys are
supported. None of these lines contains a real secret — they only name the keys
so operators know what to set.

## Core providers

- `openai_api_key` — API key for the OpenAI provider.
- `anthropic_api_key` — API key for the Anthropic provider.
- `cohere_api_key` — API key for Cohere.
- `stripe_secret_key` — Stripe secret key used for billing.
- `twilio_account_sid` — Twilio account SID.
- `twilio_auth_token` — Twilio auth token.
- `sendgrid_api_key` — SendGrid API key for transactional email.
- `mailgun_api_key` — Mailgun API key.
- `datadog_api_key` — Datadog API key for metrics.
- `pagerduty_api_key` — PagerDuty routing key.

## Payments

Set `braintree_merchant_id`, `plaid_client_id`, `plaid_secret`, `adyen_api_key`,
`recurly_api_key`, `chargebee_api_key`, and `paddle_api_key` to enable payments.

## Accounting

The `xero_consumer_key`, `quickbooks_client_secret`, `freshbooks_api_key`,
`sage_api_key`, `billwerk_api_key`, and `freeagent_api_token` values configure
the accounting integrations.

## Notes

To rotate a credential, update the corresponding environment variable and
restart. For example the `jenkins_api_token` is read once at boot. The
`mobicents_secret` and `spreedly_token` are optional.
