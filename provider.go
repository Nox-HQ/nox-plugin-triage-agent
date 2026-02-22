package main

import (
	"fmt"
	"os"
	"strings"

	plannerllm "github.com/felixgeelhaar/agent-go/contrib/planner-llm"
	"github.com/felixgeelhaar/agent-go/contrib/planner-llm/providers"
)

// resolveProvider creates an LLM provider from NOX_AI_* environment variables.
// Returns an error if the required API key is not set.
func resolveProvider() (plannerllm.Provider, string, error) {
	providerName := strings.ToLower(os.Getenv("NOX_AI_PROVIDER"))
	if providerName == "" {
		providerName = "openai"
	}

	apiKey := os.Getenv("NOX_AI_API_KEY")
	model := os.Getenv("NOX_AI_MODEL")
	baseURL := os.Getenv("NOX_AI_BASE_URL")

	switch providerName {
	case "openai":
		if apiKey == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY is required for openai provider")
		}
		if model == "" {
			model = "gpt-4o"
		}
		p := providers.NewOpenAIProvider(providers.OpenAIConfig{
			APIKey:  apiKey,
			BaseURL: baseURL,
			Model:   model,
		})
		return p, model, nil

	case "anthropic":
		if apiKey == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY is required for anthropic provider")
		}
		if model == "" {
			model = "claude-sonnet-4-5-20250514"
		}
		p := providers.NewAnthropicProvider(providers.AnthropicConfig{
			APIKey:  apiKey,
			BaseURL: baseURL,
			Model:   model,
		})
		return p, model, nil

	case "gemini":
		if apiKey == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY is required for gemini provider")
		}
		if model == "" {
			model = "gemini-pro"
		}
		p := providers.NewGeminiProvider(providers.GeminiConfig{
			APIKey: apiKey,
			Model:  model,
		})
		return p, model, nil

	case "ollama":
		if model == "" {
			model = "llama3"
		}
		url := baseURL
		if url == "" {
			url = "http://localhost:11434"
		}
		p := providers.NewOllamaProvider(providers.OllamaConfig{
			BaseURL: url,
			Model:   model,
		})
		return p, model, nil

	case "cohere":
		if apiKey == "" {
			return nil, "", fmt.Errorf("NOX_AI_API_KEY is required for cohere provider")
		}
		if model == "" {
			model = "command-r"
		}
		p := providers.NewCohereProvider(providers.CohereConfig{
			APIKey:  apiKey,
			BaseURL: baseURL,
			Model:   model,
		})
		return p, model, nil

	default:
		return nil, "", fmt.Errorf("unsupported provider: %s", providerName)
	}
}
