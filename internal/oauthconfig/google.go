package oauthconfig

import "os"

const (
	geminiClientIDPlaceholder         = "SET_GEMINI_OAUTH_CLIENT_ID"
	geminiClientSecretPlaceholder     = "SET_GEMINI_OAUTH_CLIENT_SECRET"
	antigravityClientIDPlaceholder    = "SET_ANTIGRAVITY_OAUTH_CLIENT_ID"
	antigravityClientSecretPlaceholder = "SET_ANTIGRAVITY_OAUTH_CLIENT_SECRET"
	iflowClientIDPlaceholder          = "SET_IFLOW_OAUTH_CLIENT_ID"
	iflowClientSecretPlaceholder      = "SET_IFLOW_OAUTH_CLIENT_SECRET"
)

func envOrPlaceholder(key, placeholder string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return placeholder
}

func GeminiClientID() string {
	return envOrPlaceholder("GEMINI_OAUTH_CLIENT_ID", geminiClientIDPlaceholder)
}

func GeminiClientSecret() string {
	return envOrPlaceholder("GEMINI_OAUTH_CLIENT_SECRET", geminiClientSecretPlaceholder)
}

func AntigravityClientID() string {
	return envOrPlaceholder("ANTIGRAVITY_OAUTH_CLIENT_ID", antigravityClientIDPlaceholder)
}

func AntigravityClientSecret() string {
	return envOrPlaceholder("ANTIGRAVITY_OAUTH_CLIENT_SECRET", antigravityClientSecretPlaceholder)
}

func IFlowClientID() string {
	return envOrPlaceholder("IFLOW_OAUTH_CLIENT_ID", iflowClientIDPlaceholder)
}

func IFlowClientSecret() string {
	return envOrPlaceholder("IFLOW_OAUTH_CLIENT_SECRET", iflowClientSecretPlaceholder)
}
