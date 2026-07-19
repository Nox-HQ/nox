# Django-style settings that read every credential from the environment.
# The dictionary keys NAME the vendor credentials; the values are os.environ
# lookups, never literals. A scanner must not flag a key name as a secret.
import os

INTEGRATIONS = {
    "openai_api_key": os.environ.get("OPENAI_API_KEY"),
    "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY"),
    "cohere_api_key": os.environ.get("COHERE_API_KEY"),
    "stripe_secret_key": os.environ.get("STRIPE_SECRET_KEY"),
    "twilio_account_sid": os.environ.get("TWILIO_ACCOUNT_SID"),
    "sendgrid_api_key": os.environ.get("SENDGRID_API_KEY"),
    "mailgun_api_key": os.environ.get("MAILGUN_API_KEY"),
    "datadog_api_key": os.environ.get("DATADOG_API_KEY"),
    "pagerduty_api_key": os.environ.get("PAGERDUTY_API_KEY"),
    "braintree_merchant_id": os.environ.get("BRAINTREE_MERCHANT_ID"),
    "plaid_client_id": os.environ.get("PLAID_CLIENT_ID"),
    "plaid_secret": os.environ.get("PLAID_SECRET"),
    "adyen_api_key": os.environ.get("ADYEN_API_KEY"),
    "recurly_api_key": os.environ.get("RECURLY_API_KEY"),
    "xero_consumer_key": os.environ.get("XERO_CONSUMER_KEY"),
    "quickbooks_client_secret": os.environ.get("QUICKBOOKS_CLIENT_SECRET"),
    "jenkins_api_token": os.environ.get("JENKINS_API_TOKEN"),
    "mobicents_secret": os.environ.get("MOBICENTS_SECRET"),
    "spreedly_token": os.environ.get("SPREEDLY_TOKEN"),
}
