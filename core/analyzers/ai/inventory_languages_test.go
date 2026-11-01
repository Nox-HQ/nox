package ai

import (
	"strings"
	"testing"
)

// The AI inventory recognised SDK usage in Python, JS/TS, Go and (by accident of
// a config-style `model:`) Ruby. An application on the JVM, .NET, PHP or Rust
// that built a client and called a model produced an empty inventory: no
// component, no model. One table now covers them all (frameworkPatterns for
// "this file uses SDK X", providerInvocations for "this call names model Y").
//
// Each case also carries a NEGATIVE twin: the same language, same file shape,
// with no AI SDK in it, which must add nothing.
type inventoryCase struct {
	name      string
	path      string
	src       string
	component string // expected component name, "" when none expected
	model     string // expected model name, "" when the SDK names none in code
	registry  string
}

var inventoryCases = []inventoryCase{
	{"java spring-ai", "src/App.java", `import org.springframework.ai.chat.client.ChatClient;
class App {
  String chat(String q) { return chatClient.prompt().user(q).call().content(); }
}
`, "spring-ai", "", ""},
	{"java spring-ai options model", "src/App.java", `import org.springframework.ai.openai.OpenAiChatOptions;
class App {
  Object o = OpenAiChatOptions.builder()
      .model("gpt-4o")
      .build();
}
`, "spring-ai", "gpt-4o", "openai"},
	{"java langchain4j", "src/App.java", `import dev.langchain4j.model.openai.OpenAiChatModel;
class App {
  Object m = OpenAiChatModel.builder()
      .apiKey(System.getenv("OPENAI_API_KEY"))
      .modelName("gpt-4o-mini")
      .build();
}
`, "langchain4j", "gpt-4o-mini", "openai"},
	{"java openai-java", "src/App.java", `import com.openai.client.OpenAIClient;
import com.openai.models.ChatCompletionCreateParams;
class App {
  Object p = ChatCompletionCreateParams.builder()
      .model("gpt-4o")
      .addUserMessage("hi")
      .build();
}
`, "openai-java", "gpt-4o", "openai"},
	{"java anthropic-java", "src/App.java", `import com.anthropic.client.AnthropicClient;
import com.anthropic.models.messages.MessageCreateParams;
class App {
  Object p = MessageCreateParams.builder()
      .model("claude-sonnet-4-5")
      .maxTokens(1024)
      .build();
}
`, "anthropic-java", "claude-sonnet-4-5", "anthropic"},
	{"kotlin spring-ai", "src/App.kt", `import org.springframework.ai.chat.client.ChatClient
class App(private val chatClient: ChatClient) {
    fun chat(q: String) = chatClient.prompt().user(q).call().content()
}
`, "spring-ai", "", ""},
	{"kotlin langchain4j", "src/App.kt", `import dev.langchain4j.model.anthropic.AnthropicChatModel
val m = AnthropicChatModel.builder()
    .modelName("claude-3-5-haiku-latest")
    .build()
`, "langchain4j", "claude-3-5-haiku-latest", "anthropic"},
	{"ruby ruby-openai", "app.rb", `require 'openai'
client = OpenAI::Client.new(access_token: ENV["K"])
client.chat(parameters: { model: "gpt-4o", messages: [] })
`, "openai-ruby", "gpt-4o", "openai"},
	{"php openai-php", "app.php", `<?php
use OpenAI;
$client = OpenAI::client($key);
$result = $client->chat()->create([
    'model' => 'gpt-4o',
    'messages' => [],
]);
`, "openai-php", "gpt-4o", "openai"},
	{"rust async-openai", "src/main.rs", `use async_openai::{types::CreateChatCompletionRequestArgs, Client};
fn f() {
    let req = CreateChatCompletionRequestArgs::default()
        .model("gpt-4o")
        .build().unwrap();
}
`, "async-openai", "gpt-4o", "openai"},
	{"csharp openai dotnet", "src/App.cs", `using OpenAI.Chat;
class C {
  ChatClient client = new ChatClient("gpt-4o", "key");
}
`, "openai-dotnet", "gpt-4o", "openai"},
	{"csharp azure.ai.openai", "src/App.cs", `using Azure.AI.OpenAI;
class C {
  void F(AzureOpenAIClient az) { var c = az.GetChatClient("my-gpt4o-deployment"); }
}
`, "azure-ai-openai", "my-gpt4o-deployment", "azure"},
}

var inventoryNegatives = map[string]string{
	"src/App.java": "class App {\n  Object o = Thing.builder()\n      .model(\"Invoice\")\n      .modelName(\"x\")\n      .build();\n  String chat(String q) { return room.chat(q); }\n}\n",
	"src/App.kt":   "class App { val m = Thing.builder().modelName(\"x\").build() }\n",
	"app.rb":       "client = Chat::Client.new\nclient.chat(parameters: { model: \"Invoice\" })\n",
	"app.php":      "<?php\n$client = Mailer::client($key);\n$client->chat()->create(['model' => 'Invoice']);\n",
	"src/main.rs":  "fn f() { let r = Thing::default().model(\"Invoice\"); }\n",
	"src/App.cs":   "class C { ChatClient client = new ChatClient(\"room\"); }\n",
}

func TestInventoryRecognisesSDKsInMoreLanguages(t *testing.T) {
	for _, tc := range inventoryCases {
		t.Run(tc.name, func(t *testing.T) {
			inv := scanSources(t, map[string]string{tc.path: tc.src})
			var haveComp bool
			for _, c := range inv.Components {
				if c.Name == tc.component {
					haveComp = true
				}
			}
			if !haveComp {
				t.Errorf("component %q not in inventory: %+v", tc.component, inv.Components)
			}
			if tc.model == "" {
				return
			}
			for _, m := range inv.ModelProvenance {
				if m.Name == tc.model {
					if m.Registry != tc.registry {
						t.Errorf("model %q registry = %q, want %q", tc.model, m.Registry, tc.registry)
					}
					return
				}
			}
			t.Errorf("model %q not in model_provenance: %+v", tc.model, inv.ModelProvenance)
		})
	}
}

func TestInventoryIgnoresLookalikesInMoreLanguages(t *testing.T) {
	for path, src := range inventoryNegatives {
		t.Run(path, func(t *testing.T) {
			// A comment naming openai passes the cheap marker gate, so the
			// extractors really run over the lookalike.
			lead := "// see the openai docs\n"
			if strings.HasSuffix(path, ".rb") {
				lead = "# see the openai docs\n"
			}
			if strings.HasSuffix(path, ".php") {
				src = strings.Replace(src, "<?php\n", "<?php\n"+lead, 1)
			} else {
				src = lead + src
			}
			inv := scanSources(t, map[string]string{path: src})
			if len(inv.Components) != 0 || len(inv.ModelProvenance) != 0 {
				t.Errorf("no AI SDK here, but inventory has components=%+v models=%+v", inv.Components, inv.ModelProvenance)
			}
		})
	}
}

func TestIsSourceFileCoversPHP(t *testing.T) {
	if !isSourceFile("app/Http/Chat.php") {
		t.Error(".php must be scanned for AI SDK usage")
	}
}
