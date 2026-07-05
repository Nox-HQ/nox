// Stripe and GCP keys hardcoded in Go — the cloud-provider secret pair mirrors
// tp_secrets_cloud.py. Both resolve to their canonical provider rule.
package billing

// stripeSecretKey is a live-mode Stripe key (canonical example shape).
const stripeSecretKey = "sk_live_0123456789abcdefghijklmnop" // nox-expect: SEC-030

// gcpAPIKey is a Google Cloud API key (canonical AIza… shape).
const gcpAPIKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv" // nox-expect: SEC-007
