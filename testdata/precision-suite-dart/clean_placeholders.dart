// Clean: configuration constants and `.env`-style placeholder credentials that a
// broad rule might trip on, but which carry no taint flow. There is no untrusted
// input and no sink reached with a tainted value here. A correct scanner emits
// nothing; any finding on this file is a false positive.
class Config {
  // Placeholder values — documentation defaults, never real secrets, never
  // attacker-controlled, and never reaching a sink.
  static const apiBaseUrl = 'https://api.example.com/v1';
  static const defaultToken = 'YOUR_API_TOKEN_HERE';
  static const sampleUuid = '123e4567-e89b-12d3-a456-426614174000';
  static const brandColor = '#4A90E2';
}

String banner() {
  return 'service starting against ${Config.apiBaseUrl}';
}
