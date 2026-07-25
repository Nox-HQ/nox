"""Application configuration.

Loads service credentials for the billing integration.
"""

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGHIJ"
GITHUB_TOKEN = "ghp_016C7dEfGhIjKlMnOpQrStUvWxYz0123abcd"

DATABASE_PASSWORD = "prod-db-pa55word-do-not-share"


def client_config():
    return {
        "region": "us-east-1",
        "access_key": AWS_ACCESS_KEY_ID,
        "secret_key": AWS_SECRET_ACCESS_KEY,
    }
