package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

type apiKeyPolicy struct {
	CustomerName  string
	Enabled       bool
	AllowedModels []string
	ExpiresAt     time.Time
}

func loadAPIKeyPolicy(c *gin.Context) apiKeyPolicy {
	var policy apiKeyPolicy
	if c == nil {
		return policy
	}
	rawValue, exists := c.Get("accessMetadata")
	if !exists {
		return policy
	}
	metadata, ok := rawValue.(map[string]string)
	if !ok {
		return policy
	}
	policy.CustomerName = strings.TrimSpace(metadata["customer_name"])
	policy.Enabled = !strings.EqualFold(strings.TrimSpace(metadata["enabled"]), "false")
	if expiresAt := strings.TrimSpace(metadata["expires_at"]); expiresAt != "" {
		if ts, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			policy.ExpiresAt = ts.UTC()
		}
	}
	if rawAllowed := strings.TrimSpace(metadata["allowed_models"]); rawAllowed != "" {
		_ = json.Unmarshal([]byte(rawAllowed), &policy.AllowedModels)
	}
	return policy
}

func apiKeyModelPolicyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		policy := loadAPIKeyPolicy(c)
		if len(policy.AllowedModels) == 0 {
			c.Next()
			return
		}

		modelName, ok := extractRequestedModel(c)
		if !ok {
			c.Next()
			return
		}

		for _, allowed := range policy.AllowedModels {
			if strings.EqualFold(strings.TrimSpace(allowed), modelName) {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "model not allowed for this api key"})
	}
}

func extractRequestedModel(c *gin.Context) (string, bool) {
	if c == nil || c.Request == nil {
		return "", false
	}
	path := c.FullPath()
	switch {
	case strings.HasPrefix(path, "/v1beta/models/"):
		modelPart := strings.TrimPrefix(path, "/v1beta/models/")
		if idx := strings.Index(modelPart, ":"); idx >= 0 {
			modelPart = modelPart[:idx]
		}
		modelPart = strings.Trim(modelPart, "/")
		return strings.TrimSpace(modelPart), modelPart != ""
	case c.Request.Method == http.MethodGet:
		return "", false
	}

	body, ok := readRequestBody(c)
	if !ok {
		return "", false
	}
	modelName := strings.TrimSpace(gjson.GetBytes(body, "model").String())
	if modelName == "" {
		modelName = strings.TrimSpace(gjson.GetBytes(body, "request.model").String())
	}
	return modelName, modelName != ""
}

func readRequestBody(c *gin.Context) ([]byte, bool) {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return nil, false
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, false
	}
	_ = c.Request.Body.Close()
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	return body, len(body) > 0
}
