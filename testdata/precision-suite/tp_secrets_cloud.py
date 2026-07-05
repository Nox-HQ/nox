# Live cloud-provider secrets a correct scanner must flag exactly once each.
# nox fires the right provider rule on each line (SEC-030 Stripe, SEC-007 GCP)
# but ALSO trips 5-6 overlapping entropy/keyword rules per key — the over-firing
# the density view is built to quantify (see the README headline).
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH1234"  # nox-expect: SEC-030
GOOGLE_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"  # nox-expect: SEC-007
