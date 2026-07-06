// Clean: configuration constants and `.env`-style placeholder credentials that a
// broad rule might trip on, but which carry no taint flow. There is no untrusted
// input and no sink reached with a tainted value here. A correct scanner emits
// nothing; any finding on this file is a false positive.
import Foundation

enum Config {
    // Placeholder values — documentation defaults, never real secrets, never
    // attacker-controlled, and never reaching a sink.
    static let apiBaseURL = "https://api.example.com/v1"
    static let defaultToken = "YOUR_API_TOKEN_HERE"
    static let sampleUUID = "123e4567-e89b-12d3-a456-426614174000"
    static let brandColor = "#4A90E2"
}

func banner() -> String {
    return "service starting against \(Config.apiBaseURL)"
}
