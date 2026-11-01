package agentflow

import "testing"

// AGENTFLOW-001 covered Python, JS/TS, Go and C#. An AI application written on
// the JVM, in Ruby, PHP or Rust produced no finding at all, because the prompt
// sink vocabulary had no spelling for those SDKs. Every case below pairs a
// vulnerable fixture with a safe twin that differs in exactly ONE token: the
// twin still READS a real untrusted source into q, so it guards something. A
// twin with no source would pass for the wrong reason.
//
// Spellings are the SDKs' documented call shapes: Spring AI ChatClient,
// langchain4j ChatLanguageModel/ChatModel, openai-java, ruby-openai,
// openai-php and async-openai.
type langCase struct {
	name string
	file string
	// src holds %s where the prompt value goes. vuln substitutes the tainted
	// variable, safe a string literal.
	src string
}

var moreLanguageCases = []langCase{
	{"java spring-ai ChatClient one line", "App.java", `
class App {
  String chat(HttpServletRequest request) {
    String q = request.getParameter("q");
    return chatClient.prompt().user(%s).call().content();
  }
}
`},
	{"java spring-ai ChatClient builder chain across lines", "App.java", `
class App {
  String chat(HttpServletRequest request) {
    String q = request.getParameter("q");
    return chatClient.prompt()
        .system("You are terse.")
        .user(%s)
        .call()
        .content();
  }
}
`},
	{"java langchain4j generate", "App.java", `
class App {
  String chat(HttpServletRequest request) {
    String q = request.getParameter("q");
    return chatLanguageModel.generate(%s);
  }
}
`},
	{"java langchain4j chat", "App.java", `
class App {
  String chat(HttpServletRequest request) {
    String q = request.getParameter("q");
    return chatModel.chat(%s);
  }
}
`},
	{"java openai-java", "App.java", `
class App {
  String chat(HttpServletRequest request) {
    String q = request.getParameter("q");
    ChatCompletionCreateParams params = ChatCompletionCreateParams.builder()
        .model(ChatModel.GPT_4O)
        .addUserMessage(%s)
        .build();
    return client.chat().completions().create(params).toString();
  }
}
`},
	{"kotlin spring-ai ChatClient chain across lines", "App.kt", `
class App {
    fun chat(request: HttpServletRequest): String? {
        val q = request.getParameter("q")
        return chatClient.prompt()
            .user(%s)
            .call()
            .content()
    }
}
`},
	{"kotlin langchain4j", "App.kt", `
class App {
    fun chat(request: HttpServletRequest): String {
        val q = request.getParameter("q")
        return chatLanguageModel.generate(%s)
    }
}
`},
	{"ruby ruby-openai", "app.rb", `
get '/chat' do
  q = params[:q]
  r = client.chat(parameters: { model: "gpt-4o", messages: [{ role: "user", content: %s }] })
  r.dig("choices", 0, "message", "content")
end
`},
	{"php openai-php", "app.php", `<?php
$client = OpenAI::client('key');
$q = $_GET['q'];
$result = $client->chat()->create([
    'model' => 'gpt-4o',
    'messages' => [['role' => 'user', 'content' => %s]],
]);
echo $result->choices[0]->message->content;
`},
	{"rust async-openai builder across lines", "main.rs", `
use actix_web::web;
async fn chat(qs: web::Query<String>) {
    let q = qs.into_inner();
    let client = Client::new();
    let req = CreateChatCompletionRequestArgs::default()
        .model("gpt-4o")
        .messages([ChatCompletionRequestUserMessageArgs::default().content(%s).build().unwrap().into()])
        .build().unwrap();
    client.chat().create(req).await;
}
`},
}

func fill(src, v string) string {
	out := ""
	for i := 0; i < len(src); i++ {
		if src[i] == '%' && i+1 < len(src) && src[i+1] == 's' {
			out += v
			i++
			continue
		}
		out += string(src[i])
	}
	return out
}

func TestAIPromptSinksInMoreLanguages(t *testing.T) {
	for _, tc := range moreLanguageCases {
		t.Run(tc.name+"/vulnerable fires", func(t *testing.T) {
			if got := fired(scanSource(t, tc.file, fill(tc.src, "q")), "AGENTFLOW-001"); got == 0 {
				t.Errorf("AGENTFLOW-001 did not fire: an untrusted request value reaches the model prompt")
			}
		})
		t.Run(tc.name+"/safe twin silent", func(t *testing.T) {
			if got := fired(scanSource(t, tc.file, fill(tc.src, `"Say hello"`)), "AGENTFLOW-001"); got != 0 {
				t.Errorf("AGENTFLOW-001 fired %d time(s) on a constant prompt; the rule reports a flow, not a call", got)
			}
		})
	}
}

// Receiver-agnostic names must not turn unrelated methods into model calls.
func TestAIPromptSinksIgnoreUnrelatedMethods(t *testing.T) {
	cases := []struct{ file, src string }{
		{"A.java", "class A { void f(HttpServletRequest request) {\n String q = request.getParameter(\"q\");\n room.chat(q);\n logger.generate(q);\n } }\n"},
		{"a.rb", "get '/x' do\n  q = params[:q]\n  room.chat(q)\n  room.chat(message: q)\nend\n"},
		{"a.php", "<?php\n$q = $_GET['q'];\n$room->chat($q);\n$logger->create($q);\n"},
	}
	for _, c := range cases {
		if got := fired(scanSource(t, c.file, c.src), "AGENTFLOW-001"); got != 0 {
			t.Errorf("%s: AGENTFLOW-001 fired on a non-LLM method; spellings are too loose", c.file)
		}
	}
}
