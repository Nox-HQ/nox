package agentflow

import "testing"

// Returning a model's reply from a Flask route is output handling, not an
// action the model takes, so AGENTFLOW-002 stays silent on it even though a
// route's return is an XSS sink for request data.
func TestFlaskReturnOfModelReplyIsNotExcessiveAgency(t *testing.T) {
	src := "from flask import Flask, request\nfrom openai import OpenAI\napp = Flask(__name__)\nclient = OpenAI()\n\n" +
		"@app.post('/chat')\ndef chat():\n    q = request.json.get('q', '')\n" +
		"    response = client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': q}])\n" +
		"    return response.choices[0].message.content\n"
	for _, f := range scan(t, "app.py", src) {
		if f.RuleID == ruleOutputToSink {
			t.Fatalf("AGENTFLOW-002 on a route returning the model's reply: %+v", f)
		}
	}
}
