(ns app.datablob
  "Clean: data blobs and identifiers whose long alphanumeric runs look like
   secrets but are inert data — an embedded base64 data-URI, a git SHA, UUIDs, a
   hex color. lexctx classifies the string bodies as data, so the entropy/secret
   rules must not fire. Any finding here is a false positive.")

;; A base64 data-URI SVG icon — a long blob, not a credential.
(def icon
  "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PHBhdGggZD0iTTggMEwxNiA4TDggMTZMMCA4WiIvPjwvc3ZnPg==")

;; Public identifiers, not secrets.
(def build-sha "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
(def request-id "550e8400-e29b-41d4-a716-446655440000")
(def brand-color "#1a2b3c")
(def sri-hash "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC")
