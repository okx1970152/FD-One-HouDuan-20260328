package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

type apiKeyUsageSummary struct {
	TodayRequests int64            `json:"today_requests"`
	TodayTokens   int64            `json:"today_tokens"`
	TotalRequests int64            `json:"total_requests"`
	TotalTokens   int64            `json:"total_tokens"`
	Models        map[string]apiKeyModelUsageSummary `json:"models"`
}

type apiKeyModelUsageSummary struct {
	TodayTokens int64 `json:"today_tokens"`
	TotalTokens int64 `json:"total_tokens"`
}

type apiKeyView struct {
	config.APIKeyEntry
	Usage apiKeyUsageSummary `json:"usage"`
}

type apiKeyCreateRequest struct {
	CustomerName  string   `json:"customer-name"`
	ModelPrefix   string   `json:"model-prefix"`
	ExpiresInDays int      `json:"expires-in-days"`
	Note          string   `json:"note"`
	AllowedModels []string `json:"allowed-models"`
	Enabled       *bool    `json:"enabled"`
}

type apiKeyUpdateRequest struct {
	APIKey        string   `json:"api-key"`
	CustomerName  *string  `json:"customer-name"`
	ModelPrefix   *string  `json:"model-prefix"`
	ExpiresAt     *string  `json:"expires-at"`
	Note          *string  `json:"note"`
	AllowedModels []string `json:"allowed-models"`
	Enabled       *bool    `json:"enabled"`
}

type apiKeyExtendRequest struct {
	APIKey string `json:"api-key"`
	Days   int    `json:"days"`
}

func (h *Handler) GetAPIKeys(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusOK, gin.H{"api-keys": []apiKeyView{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api-keys": h.apiKeyViews()})
}

func (h *Handler) CreateAPIKey(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}
	var body apiKeyCreateRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	key, err := h.generateUniqueAPIKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate api key"})
		return
	}

	entry := config.APIKeyEntry{
		APIKey:        key,
		CustomerName:  strings.TrimSpace(body.CustomerName),
		ModelPrefix:   strings.Trim(strings.TrimSpace(body.ModelPrefix), "/"),
		CreatedAt:     time.Now().UTC(),
		Enabled:       true,
		Note:          strings.TrimSpace(body.Note),
		AllowedModels: config.NormalizeAllowedModels(body.AllowedModels),
	}
	if body.Enabled != nil {
		entry.Enabled = *body.Enabled
	}
	if body.ExpiresInDays > 0 {
		entry.ExpiresAt = time.Now().UTC().Add(time.Duration(body.ExpiresInDays) * 24 * time.Hour)
	}

	h.cfg.APIKeys = append(h.cfg.APIKeys, entry)
	h.cfg.APIKeys = config.NormalizeAPIKeyEntries(h.cfg.APIKeys)
	h.persist(c)
}

func (h *Handler) PutAPIKeys(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	var body []config.APIKeyEntry
	if err := json.Unmarshal(data, &body); err != nil {
		var wrapper struct {
			Items []config.APIKeyEntry `json:"items"`
		}
		if errWrap := json.Unmarshal(data, &wrapper); errWrap != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		body = wrapper.Items
	}
	h.cfg.APIKeys = config.NormalizeAPIKeyEntries(body)
	h.persist(c)
}

func (h *Handler) PatchAPIKeys(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}
	var body apiKeyUpdateRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	key := strings.TrimSpace(body.APIKey)
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing api-key"})
		return
	}

	for i := range h.cfg.APIKeys {
		entry := &h.cfg.APIKeys[i]
		if entry.APIKey != key {
			continue
		}
		if body.CustomerName != nil {
			entry.CustomerName = strings.TrimSpace(*body.CustomerName)
		}
		if body.ModelPrefix != nil {
			entry.ModelPrefix = strings.Trim(strings.TrimSpace(*body.ModelPrefix), "/")
		}
		if body.Note != nil {
			entry.Note = strings.TrimSpace(*body.Note)
		}
		if body.Enabled != nil {
			entry.Enabled = *body.Enabled
		}
		if body.ExpiresAt != nil {
			expiresAtRaw := strings.TrimSpace(*body.ExpiresAt)
			if expiresAtRaw == "" {
				entry.ExpiresAt = time.Time{}
			} else {
				expiresAt, err := time.Parse(time.RFC3339, expiresAtRaw)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid expires-at"})
					return
				}
				entry.ExpiresAt = expiresAt.UTC()
			}
		}
		if body.AllowedModels != nil {
			entry.AllowedModels = config.NormalizeAllowedModels(body.AllowedModels)
		}
		h.cfg.APIKeys = config.NormalizeAPIKeyEntries(h.cfg.APIKeys)
		h.persist(c)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
}

func (h *Handler) DeleteAPIKeys(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}
	key := strings.TrimSpace(c.Query("api-key"))
	if key == "" {
		key = strings.TrimSpace(c.Query("value"))
	}
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing api-key"})
		return
	}
	next := make([]config.APIKeyEntry, 0, len(h.cfg.APIKeys))
	removed := false
	for _, entry := range h.cfg.APIKeys {
		if entry.APIKey == key {
			removed = true
			continue
		}
		next = append(next, entry)
	}
	if !removed {
		c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
		return
	}
	h.cfg.APIKeys = next
	h.persist(c)
}

func (h *Handler) ExtendAPIKey(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}
	var body apiKeyExtendRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if body.Days <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid days"})
		return
	}
	key := strings.TrimSpace(body.APIKey)
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing api-key"})
		return
	}
	now := time.Now().UTC()
	for i := range h.cfg.APIKeys {
		entry := &h.cfg.APIKeys[i]
		if entry.APIKey != key {
			continue
		}
		base := now
		if entry.ExpiresAt.After(now) {
			base = entry.ExpiresAt.UTC()
		}
		entry.ExpiresAt = base.Add(time.Duration(body.Days) * 24 * time.Hour)
		h.persist(c)
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
}

func (h *Handler) GetAPIKeyUsageStatistics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"api-keys": h.apiKeyViews()})
}

func (h *Handler) apiKeyViews() []apiKeyView {
	if h == nil || h.cfg == nil {
		return nil
	}
	views := make([]apiKeyView, 0, len(h.cfg.APIKeys))
	for _, entry := range h.cfg.APIKeys {
		views = append(views, apiKeyView{
			APIKeyEntry: entry,
			Usage:       h.apiKeyUsage(entry.APIKey),
		})
	}
	sort.SliceStable(views, func(i, j int) bool {
		return strings.ToLower(views[i].CustomerName) < strings.ToLower(views[j].CustomerName)
	})
	return views
}

func (h *Handler) apiKeyUsage(apiKey string) apiKeyUsageSummary {
	if h == nil || h.usageStats == nil || strings.TrimSpace(apiKey) == "" {
		return apiKeyUsageSummary{Models: map[string]apiKeyModelUsageSummary{}}
	}
	snapshot := h.usageStats.Snapshot()
	apiSnapshot, ok := snapshot.APIs[apiKey]
	if !ok {
		return apiKeyUsageSummary{Models: map[string]apiKeyModelUsageSummary{}}
	}
	summary := apiKeyUsageSummary{
		TotalRequests: apiSnapshot.TotalRequests,
		TotalTokens:   apiSnapshot.TotalTokens,
		Models:        make(map[string]apiKeyModelUsageSummary, len(apiSnapshot.Models)),
	}
	today := time.Now().UTC().Format("2006-01-02")
	for modelName, modelSnapshot := range apiSnapshot.Models {
		modelSummary := apiKeyModelUsageSummary{
			TotalTokens: modelSnapshot.TotalTokens,
		}
		for _, detail := range modelSnapshot.Details {
			if detail.Timestamp.UTC().Format("2006-01-02") != today {
				continue
			}
			summary.TodayRequests++
			summary.TodayTokens += detail.Tokens.TotalTokens
			modelSummary.TodayTokens += detail.Tokens.TotalTokens
		}
		summary.Models[modelName] = modelSummary
	}
	return summary
}

func (h *Handler) generateUniqueAPIKey() (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		key, err := config.GenerateAPIKey()
		if err != nil {
			return "", err
		}
		if !h.apiKeyExists(key) {
			return key, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique api key")
}

func (h *Handler) apiKeyExists(key string) bool {
	for _, entry := range h.cfg.APIKeys {
		if entry.APIKey == key {
			return true
		}
	}
	return false
}
