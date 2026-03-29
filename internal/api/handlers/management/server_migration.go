package management

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

const (
	serverMigrationCertStatusNone    = "none"
	serverMigrationCertStatusIssued  = "issued"
	serverMigrationCertStatusFailed  = "failed"
	serverMigrationDNSStatusUnknown  = "unknown"
	serverMigrationDNSStatusValid    = "valid"
	serverMigrationDNSStatusInvalid  = "invalid"
	serverMigrationDNSStatusEmpty    = "empty"
	serverMigrationExportNamePrefix  = "migration-package-"
	serverMigrationProjectSubdir     = "migration-package"
	serverMigrationCertificateSubdir = "certs"
)

type serverMigrationDNSResponse struct {
	Status         string   `json:"status"`
	Domain         string   `json:"domain,omitempty"`
	PublicIP       string   `json:"public_ip,omitempty"`
	ResolvedIPs    []string `json:"resolved_ips,omitempty"`
	Message        string   `json:"message,omitempty"`
	CheckedAt      string   `json:"checked_at,omitempty"`
	MatchesCurrent bool     `json:"matches_current"`
}

type serverMigrationStatusResponse struct {
	Domain           string                   `json:"domain,omitempty"`
	DNSStatus        string                   `json:"dns_status"`
	DNSResult        string                   `json:"dns_result,omitempty"`
	DNSCheckedAt     string                   `json:"dns_checked_at,omitempty"`
	Certificate      serverMigrationCertState `json:"certificate"`
	ScannedCertificates []serverMigrationExistingCertificate `json:"scanned_certificates,omitempty"`
	TLS              serverMigrationTLSState  `json:"tls"`
	AvailableIssuers []string                 `json:"available_issuers"`
	Installers       map[string]serverMigrationInstallerState `json:"installers,omitempty"`
	Renewal          serverMigrationRenewalState              `json:"renewal"`
	Environment      string                                   `json:"environment,omitempty"`
}

type serverMigrationTLSState struct {
	Enabled  bool   `json:"enabled"`
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
}

type serverMigrationCertState struct {
	Provider   string `json:"provider,omitempty"`
	Status     string `json:"status"`
	IssuedAt   string `json:"issued_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	CertPath   string `json:"cert_path,omitempty"`
	KeyPath    string `json:"key_path,omitempty"`
	Message    string `json:"message,omitempty"`
	Importable bool   `json:"importable"`
}

type serverMigrationExistingCertificate struct {
	ID            string   `json:"id"`
	Provider      string   `json:"provider,omitempty"`
	Status        string   `json:"status"`
	Domain        string   `json:"domain,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	IssuedAt      string   `json:"issued_at,omitempty"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
	CertPath      string   `json:"cert_path,omitempty"`
	KeyPath       string   `json:"key_path,omitempty"`
	SourceDir     string   `json:"source_dir,omitempty"`
	Message       string   `json:"message,omitempty"`
	MatchedDomain bool     `json:"matched_domain"`
	Selected      bool     `json:"selected"`
	Importable    bool     `json:"importable"`
}

type serverMigrationDomainRequest struct {
	Domain string `json:"domain"`
}

type serverMigrationIssueRequest struct {
	Provider string `json:"provider"`
}

type serverMigrationSelectCertificateRequest struct {
	ID      string `json:"id"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

type serverMigrationImportResponse struct {
	Imported   []string `json:"imported"`
	Skipped    []string `json:"skipped,omitempty"`
	Message    string   `json:"message,omitempty"`
	BackupPath string   `json:"backup_path,omitempty"`
}

type serverMigrationInstallerState struct {
	Installed bool   `json:"installed"`
	Message   string `json:"message,omitempty"`
}

type serverMigrationRenewalState struct {
	Provider string `json:"provider,omitempty"`
	Ready    bool   `json:"ready"`
	Message  string `json:"message,omitempty"`
}

type serverMigrationInstallRequest struct {
	Provider string `json:"provider"`
}

type serverMigrationImportPreviewResponse struct {
	Files          []string `json:"files"`
	OverwritePaths []string `json:"overwrite_paths,omitempty"`
	MissingFiles   []string `json:"missing_files,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

type serverMigrationPackageManifest struct {
	ConfigPath string `json:"config_path"`
	AuthDir    string `json:"auth_dir"`
}

type serverMigrationPackageContext struct {
	PathMap           map[string]map[string]string
	ExportProjectRoot string
	ExportAuthDir     string
}

func (h *Handler) GetServerMigrationStatus(c *gin.Context) {
	installerState := detectCertificateInstallerState()
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusOK, serverMigrationStatusResponse{
			DNSStatus: serverMigrationDNSStatusUnknown,
			Certificate: serverMigrationCertState{
				Status: serverMigrationCertStatusNone,
			},
			AvailableIssuers: detectAvailableCertificateIssuers(),
			Installers:       installerState,
			Renewal:          serverMigrationRenewalState{},
			Environment:      detectServerEnvironment(""),
		})
		return
	}

	certState := h.detectCertificateState()
	scannedCertificates := h.scanExistingCertificates()
	state := h.cfg.ServerMigration
	if state.CertStatus == "" {
		state.CertStatus = certState.Status
	}

	c.JSON(http.StatusOK, serverMigrationStatusResponse{
		Domain:              strings.TrimSpace(state.Domain),
		DNSStatus:           defaultIfEmpty(strings.TrimSpace(state.DNSLastStatus), serverMigrationDNSStatusUnknown),
		DNSResult:           strings.TrimSpace(state.DNSLastResult),
		DNSCheckedAt:        strings.TrimSpace(state.DNSLastCheckedAt),
		Certificate:         certState,
		ScannedCertificates: scannedCertificates,
		TLS: serverMigrationTLSState{
			Enabled:  h.cfg.TLS.Enable,
			CertPath: strings.TrimSpace(h.cfg.TLS.Cert),
			KeyPath:  strings.TrimSpace(h.cfg.TLS.Key),
		},
		AvailableIssuers: detectAvailableCertificateIssuers(),
		Installers:       installerState,
		Renewal:          detectCertificateRenewalState(certState, installerState),
		Environment:      detectServerEnvironment(h.projectRoot()),
	})
}

func (h *Handler) PutServerMigrationDomain(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	var body serverMigrationDomainRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	domain := sanitizeMigrationDomain(body.Domain)
	h.cfg.ServerMigration.Domain = domain
	if domain == "" {
		h.cfg.ServerMigration.DNSLastStatus = serverMigrationDNSStatusEmpty
		h.cfg.ServerMigration.DNSLastResult = "no domain"
		h.cfg.ServerMigration.DNSLastCheckedAt = ""
	} else {
		h.cfg.ServerMigration.DNSLastStatus = serverMigrationDNSStatusUnknown
		h.cfg.ServerMigration.DNSLastResult = ""
		h.cfg.ServerMigration.DNSLastCheckedAt = ""
	}

	h.persist(c)
}

func (h *Handler) CheckServerMigrationDNS(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	result := h.runDNSCheck(c.Request.Context())
	h.cfg.ServerMigration.DNSLastStatus = result.Status
	h.cfg.ServerMigration.DNSLastResult = result.Message
	h.cfg.ServerMigration.DNSLastCheckedAt = result.CheckedAt
	if result.Status == serverMigrationDNSStatusValid {
		h.cfg.ServerMigration.Domain = result.Domain
	}
	if !h.persistSilent() {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist dns status"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *Handler) InstallServerCertificateIssuer(c *gin.Context) {
	var body serverMigrationInstallRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	provider := strings.TrimSpace(body.Provider)
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing provider"})
		return
	}

	output, err := installCertificateIssuer(c.Request.Context(), provider)
	if err != nil {
		message := strings.TrimSpace(output)
		if message == "" {
			message = err.Error()
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": "install failed", "message": message})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    defaultIfEmpty(strings.TrimSpace(output), provider+" installed"),
		"installers": detectCertificateInstallerState(),
	})
}

func (h *Handler) ScanServerCertificates(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	certificates := h.scanExistingCertificates()
	c.JSON(http.StatusOK, gin.H{
		"certificates": certificates,
		"message":      fmt.Sprintf("scanned %d certificate candidate(s)", len(certificates)),
	})
}

func (h *Handler) SelectServerCertificate(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	var body serverMigrationSelectCertificateRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	certificates := h.scanExistingCertificates()
	var selected *serverMigrationExistingCertificate
	for i := range certificates {
		item := certificates[i]
		if strings.TrimSpace(body.ID) != "" && item.ID == strings.TrimSpace(body.ID) {
			selected = &item
			break
		}
		if strings.TrimSpace(body.CertPath) != "" &&
			filepath.Clean(item.CertPath) == filepath.Clean(strings.TrimSpace(body.CertPath)) &&
			filepath.Clean(item.KeyPath) == filepath.Clean(strings.TrimSpace(body.KeyPath)) {
			selected = &item
			break
		}
	}
	if selected == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate candidate not found"})
		return
	}

	h.cfg.ServerMigration.CertProvider = defaultIfEmpty(strings.TrimSpace(selected.Provider), "existing")
	h.cfg.ServerMigration.CertStatus = selected.Status
	h.cfg.ServerMigration.CertIssuedAt = selected.IssuedAt
	h.cfg.ServerMigration.CertExpiresAt = selected.ExpiresAt
	h.cfg.ServerMigration.CertPath = selected.CertPath
	h.cfg.ServerMigration.KeyPath = selected.KeyPath
	if strings.TrimSpace(selected.Domain) != "" {
		h.cfg.ServerMigration.Domain = strings.TrimSpace(selected.Domain)
	}
	h.cfg.TLS.Enable = selected.Importable
	if selected.CertPath != "" {
		h.cfg.TLS.Cert = selected.CertPath
	}
	if selected.KeyPath != "" {
		h.cfg.TLS.Key = selected.KeyPath
	}
	if !h.persistSilent() {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save selected certificate"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "existing certificate selected",
		"certificate": h.detectCertificateState(),
	})
}

func (h *Handler) IssueServerCertificate(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	var body serverMigrationIssueRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	domain := sanitizeMigrationDomain(h.cfg.ServerMigration.Domain)
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing domain"})
		return
	}
	if strings.TrimSpace(h.cfg.ServerMigration.DNSLastStatus) != serverMigrationDNSStatusValid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "dns not effective"})
		return
	}

	provider := strings.TrimSpace(body.Provider)
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing provider"})
		return
	}

	output, err := h.issueCertificate(c.Request.Context(), provider, domain)
	if err != nil {
		message := strings.TrimSpace(output)
		if message == "" {
			message = err.Error()
		}
		h.cfg.ServerMigration.DNSLastResult = message
		_ = h.persistSilent()
		c.JSON(http.StatusBadGateway, gin.H{"error": "certificate issue failed", "message": message})
		return
	}

	certState := h.detectCertificateState()
	certState.Provider = provider
	h.cfg.ServerMigration.CertProvider = provider
	h.cfg.ServerMigration.CertStatus = certState.Status
	h.cfg.ServerMigration.CertIssuedAt = certState.IssuedAt
	h.cfg.ServerMigration.CertExpiresAt = certState.ExpiresAt
	h.cfg.ServerMigration.CertPath = certState.CertPath
	h.cfg.ServerMigration.KeyPath = certState.KeyPath
	h.cfg.TLS.Enable = certState.Importable
	if certState.CertPath != "" {
		h.cfg.TLS.Cert = certState.CertPath
	}
	if certState.KeyPath != "" {
		h.cfg.TLS.Key = certState.KeyPath
	}
	if !h.persistSilent() {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save certificate state"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     strings.TrimSpace(output),
		"certificate": certState,
	})
}

func (h *Handler) ImportServerCertificate(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	domain := strings.TrimSpace(h.cfg.ServerMigration.Domain)
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing domain"})
		return
	}

	certHeader, err := c.FormFile("cert")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing cert file"})
		return
	}
	keyHeader, err := c.FormFile("key")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing key file"})
		return
	}

	projectRoot := h.projectRoot()
	targetDir := filepath.Join(projectRoot, serverMigrationCertificateSubdir, domain)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare certificate directory"})
		return
	}

	certPath := filepath.Join(targetDir, "fullchain.pem")
	keyPath := filepath.Join(targetDir, "privkey.pem")
	if err := saveUploadedFile(certHeader, certPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save cert file"})
		return
	}
	if err := saveUploadedFile(keyHeader, keyPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save key file"})
		return
	}

	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid certificate pair", "message": err.Error()})
		return
	}

	certState := detectCertificateStateFromFiles(certPath, keyPath)
	h.cfg.ServerMigration.CertProvider = strings.TrimSpace(c.PostForm("provider"))
	if h.cfg.ServerMigration.CertProvider == "" {
		h.cfg.ServerMigration.CertProvider = "imported"
	}
	h.cfg.ServerMigration.CertStatus = certState.Status
	h.cfg.ServerMigration.CertIssuedAt = certState.IssuedAt
	h.cfg.ServerMigration.CertExpiresAt = certState.ExpiresAt
	h.cfg.ServerMigration.CertPath = certPath
	h.cfg.ServerMigration.KeyPath = keyPath
	h.cfg.TLS.Enable = true
	h.cfg.TLS.Cert = certPath
	h.cfg.TLS.Key = keyPath
	if !h.persistSilent() {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save certificate state"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"certificate": certState})
}

func (h *Handler) ExportServerMigrationPackage(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	data, filename, err := h.buildMigrationPackage()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build migration package", "message": err.Error()})
		return
	}

	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Cache-Control", "no-store")
	_, _ = c.Writer.Write(data)
}

func (h *Handler) PreviewServerMigrationPackage(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing package file"})
		return
	}
	f, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to open package"})
		return
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read package"})
		return
	}

	preview, err := h.previewMigrationPackage(data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to preview package", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, preview)
}

func (h *Handler) ImportServerMigrationPackage(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config unavailable"})
		return
	}

	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing package file"})
		return
	}
	f, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to open package"})
		return
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read package"})
		return
	}

	backupPath, backupErr := h.createMigrationBackupFile()
	if backupErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create backup", "message": backupErr.Error()})
		return
	}

	imported, skipped, err := h.restoreMigrationPackage(data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to import package", "message": err.Error()})
		return
	}

	certState := h.detectCertificateState()
	h.cfg.ServerMigration.CertStatus = certState.Status
	h.cfg.ServerMigration.CertIssuedAt = certState.IssuedAt
	h.cfg.ServerMigration.CertExpiresAt = certState.ExpiresAt
	h.cfg.ServerMigration.CertPath = certState.CertPath
	h.cfg.ServerMigration.KeyPath = certState.KeyPath
	_ = h.persistSilent()

	c.JSON(http.StatusOK, serverMigrationImportResponse{
		Imported:   imported,
		Skipped:    skipped,
		Message:    "migration package imported",
		BackupPath: backupPath,
	})
}

func (h *Handler) RestartManagedService(c *gin.Context) {
	projectRoot := h.projectRoot()

	restartCommands := [][]string{}
	if runtime.GOOS == "windows" {
		restartCommands = append(restartCommands,
			[]string{"powershell", "-NoProfile", "-Command", "docker compose up -d --remove-orphans --no-build"},
			[]string{"powershell", "-NoProfile", "-Command", "docker-compose up -d --remove-orphans --no-build"},
		)
	} else {
		restartCommands = append(restartCommands,
			[]string{"sh", "-lc", "docker compose up -d --remove-orphans --no-build"},
			[]string{"sh", "-lc", "docker-compose up -d --remove-orphans --no-build"},
		)
	}

	for _, argv := range restartCommands {
		cmd := exec.CommandContext(c.Request.Context(), argv[0], argv[1:]...)
		cmd.Dir = projectRoot
		output, err := cmd.CombinedOutput()
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"message":      "service restarted",
				"mode":         "compose",
				"output":       strings.TrimSpace(string(output)),
				"restarted_at": time.Now().UTC().Format(time.RFC3339),
			})
			return
		}
	}

	if runtime.GOOS != "windows" {
		go func() {
			time.Sleep(800 * time.Millisecond)
			os.Exit(0)
		}()
		c.JSON(http.StatusOK, gin.H{
			"message":      "service restart scheduled by process exit",
			"mode":         "process-exit",
			"restarted_at": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "restart mechanism unavailable",
		"mode":         "none",
		"restarted_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *Handler) persistSilent() bool {
	if h == nil || h.cfg == nil || strings.TrimSpace(h.configFilePath) == "" {
		return false
	}
	return config.SaveConfigPreserveComments(h.configFilePath, h.cfg) == nil
}

func (h *Handler) runDNSCheck(ctx context.Context) serverMigrationDNSResponse {
	result := serverMigrationDNSResponse{
		Status:    serverMigrationDNSStatusUnknown,
		Domain:    strings.TrimSpace(h.cfg.ServerMigration.Domain),
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if result.Domain == "" {
		result.Status = serverMigrationDNSStatusEmpty
		result.Message = "no domain"
		return result
	}

	publicIP, _ := h.fetchPublicIP(ctx)
	result.PublicIP = publicIP

	resolvedIPs, err := lookupPublicIPs(ctx, result.Domain)
	if err != nil || len(resolvedIPs) == 0 {
		result.Status = serverMigrationDNSStatusInvalid
		result.Message = "public DNS not effective; no valid IP resolved"
		return result
	}
	result.ResolvedIPs = resolvedIPs

	if publicIP == "" {
		result.Status = serverMigrationDNSStatusUnknown
		result.Message = fmt.Sprintf("resolved public IPs %s but failed to detect current host public IP", strings.Join(resolvedIPs, ", "))
		return result
	}

	for _, ip := range resolvedIPs {
		if ip == publicIP {
			result.Status = serverMigrationDNSStatusValid
			result.Message = fmt.Sprintf("public DNS effective; resolved to current host public IP %s", publicIP)
			result.MatchesCurrent = true
			return result
		}
	}

	result.Status = serverMigrationDNSStatusInvalid
	result.Message = fmt.Sprintf("public DNS not effective; resolved IPs %s do not match current host public IP %s", strings.Join(resolvedIPs, ", "), publicIP)
	return result
}

func (h *Handler) fetchPublicIP(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	if h != nil && h.cfg != nil && strings.TrimSpace(h.cfg.ProxyURL) != "" {
		sdkCfg := &sdkconfig.SDKConfig{ProxyURL: strings.TrimSpace(h.cfg.ProxyURL)}
		util.SetProxy(sdkCfg, client)
	}

	publicIPURLs := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
	}
	for _, rawURL := range publicIPURLs {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode >= 400 {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if parsed := net.ParseIP(ip); parsed != nil {
			return parsed.String(), nil
		}
	}

	return "", errors.New("public ip lookup failed")
}

func lookupPublicIPs(ctx context.Context, domain string) ([]string, error) {
	resolvers := []*net.Resolver{
		{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(ctx, "udp", "1.1.1.1:53")
			},
		},
		{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(ctx, "udp", "8.8.8.8:53")
			},
		},
		net.DefaultResolver,
	}

	seen := map[string]struct{}{}
	ips := make([]string, 0, 4)
	for _, resolver := range resolvers {
		addrs, err := resolver.LookupIPAddr(ctx, domain)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := strings.TrimSpace(addr.IP.String())
			if ip == "" {
				continue
			}
			if _, exists := seen[ip]; exists {
				continue
			}
			seen[ip] = struct{}{}
			ips = append(ips, ip)
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}

	if len(ips) == 0 {
		return nil, errors.New("no public dns records found")
	}
	return ips, nil
}

func (h *Handler) detectCertificateState() serverMigrationCertState {
	if h == nil || h.cfg == nil {
		return serverMigrationCertState{Status: serverMigrationCertStatusNone}
	}

	candidates := [][2]string{}
	if h.cfg.ServerMigration.CertPath != "" && h.cfg.ServerMigration.KeyPath != "" {
		candidates = append(candidates, [2]string{h.cfg.ServerMigration.CertPath, h.cfg.ServerMigration.KeyPath})
	}
	if h.cfg.TLS.Cert != "" && h.cfg.TLS.Key != "" {
		candidates = append(candidates, [2]string{h.cfg.TLS.Cert, h.cfg.TLS.Key})
	}

	domain := strings.TrimSpace(h.cfg.ServerMigration.Domain)
	projectRoot := h.projectRoot()
	if domain != "" {
		candidates = append(candidates,
			[2]string{
				filepath.Join(projectRoot, serverMigrationCertificateSubdir, domain, "fullchain.pem"),
				filepath.Join(projectRoot, serverMigrationCertificateSubdir, domain, "privkey.pem"),
			},
			[2]string{
				filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem"),
				filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem"),
			},
		)
	}

	for _, pair := range candidates {
		if strings.TrimSpace(pair[0]) == "" || strings.TrimSpace(pair[1]) == "" {
			continue
		}
		if _, err := os.Stat(pair[0]); err != nil {
			continue
		}
		if _, err := os.Stat(pair[1]); err != nil {
			continue
		}
		state := detectCertificateStateFromFiles(pair[0], pair[1])
		if h.cfg.ServerMigration.CertProvider != "" {
			state.Provider = h.cfg.ServerMigration.CertProvider
		}
		return state
	}

	for _, item := range h.scanExistingCertificates() {
		if item.Selected || item.MatchedDomain {
			return serverMigrationCertState{
				Provider:   item.Provider,
				Status:     item.Status,
				IssuedAt:   item.IssuedAt,
				ExpiresAt:  item.ExpiresAt,
				CertPath:   item.CertPath,
				KeyPath:    item.KeyPath,
				Message:    item.Message,
				Importable: item.Importable,
			}
		}
	}

	return serverMigrationCertState{
		Status:  serverMigrationCertStatusNone,
		Message: "no imported certificate detected",
	}
}

func detectCertificateStateFromFiles(certPath string, keyPath string) serverMigrationCertState {
	state := serverMigrationCertState{
		Status:   serverMigrationCertStatusNone,
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	if certPath == "" || keyPath == "" {
		state.Message = "certificate path or private key path is empty"
		return state
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		state.Status = serverMigrationCertStatusFailed
		state.Message = fmt.Sprintf("certificate pair invalid: %v", err)
		return state
	}

	content, err := os.ReadFile(certPath)
	if err != nil {
		state.Status = serverMigrationCertStatusFailed
		state.Message = "failed to read certificate file"
		return state
	}

	block, _ := pem.Decode(content)
	if block == nil {
		state.Status = serverMigrationCertStatusFailed
		state.Message = "failed to parse certificate payload"
		return state
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		state.Status = serverMigrationCertStatusFailed
		state.Message = "failed to parse certificate metadata"
		return state
	}

	state.Status = serverMigrationCertStatusIssued
	state.Importable = true
	state.IssuedAt = cert.NotBefore.UTC().Format(time.RFC3339)
	state.ExpiresAt = cert.NotAfter.UTC().Format(time.RFC3339)
	state.Message = fmt.Sprintf("certificate issued; expires at %s", cert.NotAfter.UTC().Format("20060102"))
	return state
}

func (h *Handler) scanExistingCertificates() []serverMigrationExistingCertificate {
	if h == nil || h.cfg == nil {
		return nil
	}

	targetDomain := sanitizeMigrationDomain(h.cfg.ServerMigration.Domain)
	searchRoots := []string{
		filepath.Join(h.projectRoot(), serverMigrationCertificateSubdir),
		filepath.Join("/etc/letsencrypt/live"),
		filepath.Join("/etc/letsencrypt/archive"),
		filepath.Join("/home/web/certs"),
		filepath.Join("/etc/nginx/certs"),
		filepath.Join("/host-certs"),
		filepath.Join("/host-letsencrypt/live"),
	}

	seenPairs := map[string]struct{}{}
	certificates := make([]serverMigrationExistingCertificate, 0, 8)
	for _, root := range searchRoots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}

		_ = filepath.Walk(root, func(path string, walkInfo os.FileInfo, walkErr error) error {
			if walkErr != nil || walkInfo == nil || !walkInfo.IsDir() {
				return nil
			}

			for _, pair := range findCertificatePairsInDir(path) {
				certPath, keyPath := pair[0], pair[1]
				pairKey := filepath.Clean(certPath) + "|" + filepath.Clean(keyPath)
				if _, exists := seenPairs[pairKey]; exists {
					continue
				}
				seenPairs[pairKey] = struct{}{}

				item := detectExistingCertificate(certPath, keyPath)
				item.SourceDir = path
				item.Selected = samePath(item.CertPath, h.cfg.ServerMigration.CertPath) && samePath(item.KeyPath, h.cfg.ServerMigration.KeyPath)
				if targetDomain != "" {
					item.MatchedDomain = certificateMatchesDomain(item, targetDomain)
				}
				certificates = append(certificates, item)
			}
			return nil
		})
	}

	sort.SliceStable(certificates, func(i, j int) bool {
		if certificates[i].Selected != certificates[j].Selected {
			return certificates[i].Selected
		}
		if certificates[i].MatchedDomain != certificates[j].MatchedDomain {
			return certificates[i].MatchedDomain
		}
		if certificates[i].ExpiresAt != certificates[j].ExpiresAt {
			return certificates[i].ExpiresAt > certificates[j].ExpiresAt
		}
		return certificates[i].CertPath < certificates[j].CertPath
	})
	return certificates
}

func detectExistingCertificate(certPath string, keyPath string) serverMigrationExistingCertificate {
	idInput := filepath.Clean(certPath) + "|" + filepath.Clean(keyPath)
	sum := sha1.Sum([]byte(idInput))
	item := serverMigrationExistingCertificate{
		ID:       hex.EncodeToString(sum[:]),
		Status:   serverMigrationCertStatusNone,
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	state := detectCertificateStateFromFiles(certPath, keyPath)
	item.Status = state.Status
	item.IssuedAt = state.IssuedAt
	item.ExpiresAt = state.ExpiresAt
	item.Message = state.Message
	item.Importable = state.Importable
	item.Provider = inferCertificateProvider(certPath)

	content, err := os.ReadFile(certPath)
	if err != nil {
		if item.Message == "" {
			item.Message = "failed to read certificate file"
		}
		return item
	}
	block, _ := pem.Decode(content)
	if block == nil {
		if item.Message == "" {
			item.Message = "failed to parse certificate payload"
		}
		return item
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		if item.Message == "" {
			item.Message = "failed to parse certificate metadata"
		}
		return item
	}
	item.Domain = strings.TrimSpace(cert.Subject.CommonName)
	item.Domains = uniqueStrings(append([]string{item.Domain}, cert.DNSNames...))
	return item
}

func findCertificatePairsInDir(dir string) [][2]string {
	candidates := make([][2]string, 0, 6)
	seen := map[string]struct{}{}
	appendPair := func(certPath string, keyPath string) {
		if !fileExists(certPath) || !fileExists(keyPath) {
			return
		}
		pairKey := filepath.Clean(certPath) + "|" + filepath.Clean(keyPath)
		if _, exists := seen[pairKey]; exists {
			return
		}
		seen[pairKey] = struct{}{}
		candidates = append(candidates, [2]string{certPath, keyPath})
	}

	appendPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
	appendPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "privkey.pem"))
	appendPair(filepath.Join(dir, "fullchain.cer"), filepath.Join(dir, filepath.Base(dir)+".key"))
	appendPair(filepath.Join(dir, "cert.cer"), filepath.Join(dir, filepath.Base(dir)+".key"))

	entries, err := os.ReadDir(dir)
	if err != nil {
		return candidates
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)
		fullPath := filepath.Join(dir, name)
		switch {
		case strings.HasSuffix(lowerName, "_cert.pem"):
			base := strings.TrimSuffix(name, "_cert.pem")
			appendPair(fullPath, filepath.Join(dir, base+"_key.pem"))
		case strings.HasSuffix(lowerName, ".crt"):
			base := strings.TrimSuffix(name, filepath.Ext(name))
			appendPair(fullPath, filepath.Join(dir, base+".key"))
		}
	}
	return candidates
}

func certificateMatchesDomain(item serverMigrationExistingCertificate, domain string) bool {
	domain = sanitizeMigrationDomain(domain)
	for _, candidate := range append([]string{item.Domain}, item.Domains...) {
		candidate = strings.TrimSpace(strings.ToLower(candidate))
		if candidate == "" {
			continue
		}
		if candidate == domain {
			return true
		}
		if strings.HasPrefix(candidate, "*.") && strings.HasSuffix(domain, strings.TrimPrefix(candidate, "*")) {
			return true
		}
	}
	return false
}

func inferCertificateProvider(certPath string) string {
	lowerPath := strings.ToLower(filepath.ToSlash(certPath))
	switch {
	case strings.Contains(lowerPath, "/etc/letsencrypt/"):
		return "letsencrypt-existing"
	case strings.Contains(lowerPath, ".acme.sh"):
		return "acme.sh-existing"
	case strings.Contains(lowerPath, "/home/web/certs/"), strings.Contains(lowerPath, "/etc/nginx/certs/"), strings.Contains(lowerPath, "/host-certs/"):
		return "custom-existing"
	default:
		return "existing"
	}
}

func sanitizeMigrationDomain(raw string) string {
	domain := strings.TrimSpace(raw)
	domain = strings.TrimSuffix(domain, "/")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "//")
	if idx := strings.Index(domain, "/"); idx >= 0 {
		domain = domain[:idx]
	}
	return strings.TrimSpace(strings.ToLower(domain))
}

func samePath(left string, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	items := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		items = append(items, trimmed)
	}
	return items
}

func detectAvailableCertificateIssuers() []string {
	return []string{"certbot", "acme.sh"}
}

func detectCertificateInstallerState() map[string]serverMigrationInstallerState {
	states := map[string]serverMigrationInstallerState{
		"certbot": {Installed: false, Message: "not installed"},
		"acme.sh": {Installed: false, Message: "not installed"},
	}

	if _, err := exec.LookPath("certbot"); err == nil {
		states["certbot"] = serverMigrationInstallerState{Installed: true, Message: "available in PATH"}
	}

	if _, err := exec.LookPath("acme.sh"); err == nil {
		states["acme.sh"] = serverMigrationInstallerState{Installed: true, Message: "available in PATH"}
	} else {
		home, _ := os.UserHomeDir()
		if home != "" {
			acmePath := filepath.Join(home, ".acme.sh", "acme.sh")
			if _, statErr := os.Stat(acmePath); statErr == nil {
				states["acme.sh"] = serverMigrationInstallerState{Installed: true, Message: acmePath}
			}
		}
	}

	return states
}

func detectCertificateRenewalState(certState serverMigrationCertState, installers map[string]serverMigrationInstallerState) serverMigrationRenewalState {
	provider := strings.TrimSpace(certState.Provider)
	if provider == "" || provider == "imported" {
		return serverMigrationRenewalState{
			Provider: provider,
			Ready:    false,
			Message:  "renewal not managed automatically",
		}
	}
	inst, ok := installers[provider]
	if ok && inst.Installed {
		return serverMigrationRenewalState{
			Provider: provider,
			Ready:    true,
			Message:  "renewal tooling installed",
		}
	}
	return serverMigrationRenewalState{
		Provider: provider,
		Ready:    false,
		Message:  "renewal tool not installed",
	}
}

func detectServerEnvironment(projectRoot string) string {
	lower := strings.ToLower(projectRoot)
	if strings.Contains(lower, "test") {
		return "test"
	}
	if strings.TrimSpace(os.Getenv("DEPLOY")) != "" {
		return strings.TrimSpace(os.Getenv("DEPLOY"))
	}
	return "production"
}

func installCertificateIssuer(ctx context.Context, provider string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", errors.New("installer is only supported on Linux hosts")
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "certbot":
		cmd := exec.CommandContext(ctx, "sh", "-lc", "if command -v apk >/dev/null 2>&1; then apk add --no-cache certbot; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y certbot; elif command -v yum >/dev/null 2>&1; then yum install -y certbot; else exit 127; fi")
		out, err := cmd.CombinedOutput()
		return string(out), err
	case "acme.sh":
		cmd := exec.CommandContext(ctx, "sh", "-lc", "if command -v apk >/dev/null 2>&1; then apk add --no-cache curl bash openssl; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl bash openssl; elif command -v yum >/dev/null 2>&1; then yum install -y curl bash openssl; fi && curl -fsSL https://get.acme.sh | sh")
		out, err := cmd.CombinedOutput()
		return string(out), err
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (h *Handler) issueCertificate(ctx context.Context, provider, domain string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", errors.New("certificate issue is only supported on Linux hosts")
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "certbot":
		if _, err := exec.LookPath("certbot"); err != nil {
			return "", errors.New("certbot is not installed on this runtime")
		}
		cmd := exec.CommandContext(ctx, "sh", "-lc", fmt.Sprintf("certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d %q", domain))
		out, err := cmd.CombinedOutput()
		if err == nil {
			h.cfg.ServerMigration.CertPath = filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
			h.cfg.ServerMigration.KeyPath = filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")
		}
		return string(out), err
	case "acme.sh":
		acmePath := "acme.sh"
		if _, err := exec.LookPath(acmePath); err != nil {
			home, _ := os.UserHomeDir()
			acmePath = filepath.Join(home, ".acme.sh", "acme.sh")
			if _, statErr := os.Stat(acmePath); statErr != nil {
				return "", errors.New("acme.sh is not installed on this runtime")
			}
		}
		cmd := exec.CommandContext(ctx, "sh", "-lc", fmt.Sprintf("%q --issue -d %q --standalone", acmePath, domain))
		out, err := cmd.CombinedOutput()
		if err == nil {
			home, _ := os.UserHomeDir()
			h.cfg.ServerMigration.CertPath = filepath.Join(home, ".acme.sh", domain, "fullchain.cer")
			h.cfg.ServerMigration.KeyPath = filepath.Join(home, ".acme.sh", domain, domain+".key")
		}
		return string(out), err
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func saveUploadedFile(header *multipart.FileHeader, target string) error {
	src, err := header.Open()
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	dst, err := os.Create(target)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()

	if _, err = io.Copy(dst, src); err != nil {
		return err
	}

	mode := os.FileMode(0o644)
	lowerTarget := strings.ToLower(target)
	if strings.Contains(lowerTarget, "privkey") || strings.HasSuffix(lowerTarget, ".key") {
		mode = 0o600
	}
	return os.Chmod(target, mode)
}

func (h *Handler) buildMigrationPackage() ([]byte, string, error) {
	var buffer bytes.Buffer
	zipWriter := zip.NewWriter(&buffer)

	root := h.projectRoot()
	filesAdded := make([]string, 0, 12)
	pathMap := make(map[string]map[string]string)
	selectedCertPath := strings.TrimSpace(h.cfg.ServerMigration.CertPath)
	selectedKeyPath := strings.TrimSpace(h.cfg.ServerMigration.KeyPath)
	if selectedCertPath == "" || selectedKeyPath == "" {
		for _, item := range h.scanExistingCertificates() {
			if item.Selected || item.MatchedDomain {
				selectedCertPath = item.CertPath
				selectedKeyPath = item.KeyPath
				if h.cfg.ServerMigration.CertProvider == "" {
					h.cfg.ServerMigration.CertProvider = item.Provider
				}
				if h.cfg.ServerMigration.CertIssuedAt == "" {
					h.cfg.ServerMigration.CertIssuedAt = item.IssuedAt
				}
				if h.cfg.ServerMigration.CertExpiresAt == "" {
					h.cfg.ServerMigration.CertExpiresAt = item.ExpiresAt
				}
				h.cfg.ServerMigration.CertStatus = item.Status
				break
			}
		}
	}

	addBytes := func(name string, data []byte) error {
		writer, err := zipWriter.Create(name)
		if err != nil {
			return err
		}
		_, err = writer.Write(data)
		return err
	}

	var addFile func(sourcePath string) error
	addFile = func(sourcePath string) error {
		sourcePath = strings.TrimSpace(sourcePath)
		if sourcePath == "" {
			return nil
		}

		info, err := os.Stat(sourcePath)
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return filepath.Walk(sourcePath, func(path string, walkInfo os.FileInfo, walkErr error) error {
				if walkErr != nil || walkInfo == nil || walkInfo.IsDir() {
					return walkErr
				}
				return addFile(path)
			})
		}

		data, err := os.ReadFile(sourcePath)
		if err != nil {
			return err
		}

		archivePath, restoreTo := h.archivePathForSource(sourcePath)
		filesAdded = append(filesAdded, archivePath)
		pathMap[archivePath] = map[string]string{
			"source_path": sourcePath,
			"restore_to":  restoreTo,
		}
		return addBytes(archivePath, data)
	}

	_ = addFile(h.configFilePath)
	envPath := filepath.Join(root, ".env")
	if fileExists(envPath) {
		_ = addFile(envPath)
	} else if envData := buildMigrationEnvData(); len(envData) > 0 {
		filesAdded = append(filesAdded, "files/project/.env")
		pathMap["files/project/.env"] = map[string]string{
			"source_path": "process-environment",
			"restore_to":  filepath.ToSlash(filepath.Join(root, ".env")),
		}
		_ = addBytes("files/project/.env", envData)
	}
	_ = addFile(h.cfg.AuthDir)
	_ = addFile(selectedCertPath)
	_ = addFile(selectedKeyPath)
	if selectedCertPath != "" {
		certDir := filepath.Dir(selectedCertPath)
		_ = addFile(filepath.Join(certDir, "cert.pem"))
		_ = addFile(filepath.Join(certDir, "chain.pem"))
		_ = addFile(filepath.Join(certDir, "fullchain.pem"))
	}
	if selectedKeyPath != "" {
		keyDir := filepath.Dir(selectedKeyPath)
		_ = addFile(filepath.Join(keyDir, "privkey.pem"))
	}
	_ = addFile("/etc/letsencrypt")
	_ = addFile("/home/web/certs")

	manifest := map[string]interface{}{
		"version":     1,
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"domain":      h.cfg.ServerMigration.Domain,
		"config_path": h.configFilePath,
		"auth_dir":    h.cfg.AuthDir,
		"cert_path":   normalizeMigrationExportPath(selectedCertPath),
		"key_path":    normalizeMigrationExportPath(selectedKeyPath),
		"files":       filesAdded,
		"asset_name":  "ip9988001.html",
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	_ = addBytes(serverMigrationProjectSubdir+"/manifest.json", manifestData)

	pathMapData, _ := json.MarshalIndent(pathMap, "", "  ")
	_ = addBytes(serverMigrationProjectSubdir+"/path-map.json", pathMapData)

	certificateManifest := map[string]interface{}{
		"domain":      h.cfg.ServerMigration.Domain,
		"provider":    h.cfg.ServerMigration.CertProvider,
		"status":      h.cfg.ServerMigration.CertStatus,
		"issued_at":   h.cfg.ServerMigration.CertIssuedAt,
		"expires_at":  h.cfg.ServerMigration.CertExpiresAt,
		"cert_path":   normalizeMigrationExportPath(selectedCertPath),
		"key_path":    normalizeMigrationExportPath(selectedKeyPath),
		"required": []map[string][]string{
			{"pair": []string{"fullchain.pem", "privkey.pem"}},
			{"pair": []string{".crt", ".key"}},
			{"pair": []string{"_cert.pem", "_key.pem"}},
		},
		"recommended": []string{"cert.pem", "chain.pem"},
	}
	certificateManifestData, _ := json.MarshalIndent(certificateManifest, "", "  ")
	_ = addBytes(serverMigrationProjectSubdir+"/meta/certificate-manifest.json", certificateManifestData)

	summary := map[string]interface{}{
		"domain":                     h.cfg.ServerMigration.Domain,
		"dns_status":                 h.cfg.ServerMigration.DNSLastStatus,
		"dns_result":                 h.cfg.ServerMigration.DNSLastResult,
		"certificate_status":         h.cfg.ServerMigration.CertStatus,
		"certificate_expires_at":     h.cfg.ServerMigration.CertExpiresAt,
		"project_root":               root,
		"config_path":                h.configFilePath,
		"auth_dir":                   h.cfg.AuthDir,
		"exported_files":             filesAdded,
		"required_certificate_files": []map[string][]string{
			{"pair": []string{"fullchain.pem", "privkey.pem"}},
			{"pair": []string{".crt", ".key"}},
			{"pair": []string{"_cert.pem", "_key.pem"}},
		},
		"exported_at":                time.Now().UTC().Format(time.RFC3339),
	}
	summaryData, _ := json.MarshalIndent(summary, "", "  ")
	_ = addBytes(serverMigrationProjectSubdir+"/meta/migration-summary.json", summaryData)

	restoreText := []byte("Restore order:\n1. Restore config.yaml\n2. Restore .env\n3. Restore auths\n4. Restore certificate and private key files\n5. Restart the service\n")
	_ = addBytes(serverMigrationProjectSubdir+"/meta/RESTORE.md", restoreText)

	if err := zipWriter.Close(); err != nil {
		return nil, "", err
	}

	filename := serverMigrationExportNamePrefix + time.Now().UTC().Format("20060102-150405") + ".zip"
	return buffer.Bytes(), filename, nil
}

func (h *Handler) createMigrationBackupFile() (string, error) {
	data, filename, err := h.buildMigrationPackage()
	if err != nil {
		return "", err
	}

	backupDir := filepath.Join(h.projectRoot(), "backups", "server-migration")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", err
	}

	target := filepath.Join(backupDir, "backup-"+filename)
	if err := os.WriteFile(target, data, 0o600); err != nil {
		return "", err
	}

	return target, nil
}

func (h *Handler) previewMigrationPackage(data []byte) (*serverMigrationImportPreviewResponse, error) {
	readerAt := bytes.NewReader(data)
	zipReader, err := zip.NewReader(readerAt, int64(len(data)))
	if err != nil {
		return nil, err
	}
	packageContext := loadServerMigrationPackageContext(zipReader)

	preview := &serverMigrationImportPreviewResponse{
		Files:          make([]string, 0, len(zipReader.File)),
		OverwritePaths: []string{},
		MissingFiles:   []string{},
		Warnings:       []string{},
	}

	foundCertFile := false
	foundKeyFile := false
	for _, file := range zipReader.File {
		preview.Files = append(preview.Files, file.Name)
		base := strings.ToLower(filepath.Base(file.Name))
		if isMigrationCertificateArchiveEntry(base) {
			foundCertFile = true
		}
		if isMigrationPrivateKeyArchiveEntry(base) {
			foundKeyFile = true
		}
		if file.FileInfo().IsDir() || !strings.HasPrefix(file.Name, "files/") {
			continue
		}
		target := restoreTargetPath(file.Name, h.projectRoot(), h.cfg.AuthDir, packageContext)
		if target == "" {
			preview.Warnings = append(preview.Warnings, "unable to determine restore path for "+file.Name)
			continue
		}
		if _, statErr := os.Stat(target); statErr == nil {
			preview.OverwritePaths = append(preview.OverwritePaths, target)
		}
	}

	if !foundCertFile {
		preview.MissingFiles = append(preview.MissingFiles, "certificate file")
	}
	if !foundKeyFile {
		preview.MissingFiles = append(preview.MissingFiles, "private key file")
	}
	if len(preview.OverwritePaths) == 0 {
		preview.Warnings = append(preview.Warnings, "no existing files will be overwritten")
	}

	return preview, nil
}

func (h *Handler) restoreMigrationPackage(data []byte) ([]string, []string, error) {
	readerAt := bytes.NewReader(data)
	zipReader, err := zip.NewReader(readerAt, int64(len(data)))
	if err != nil {
		return nil, nil, err
	}
	packageContext := loadServerMigrationPackageContext(zipReader)

	imported := make([]string, 0, len(zipReader.File))
	skipped := make([]string, 0)
	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() || !strings.HasPrefix(file.Name, "files/") {
			skipped = append(skipped, file.Name)
			continue
		}

		target := restoreTargetPath(file.Name, h.projectRoot(), h.cfg.AuthDir, packageContext)
		if target == "" {
			skipped = append(skipped, file.Name)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return imported, skipped, err
		}

		rc, err := file.Open()
		if err != nil {
			return imported, skipped, err
		}
		payload, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return imported, skipped, err
		}

		mode := os.FileMode(0o644)
		lowerTarget := strings.ToLower(target)
		if strings.Contains(lowerTarget, "privkey") || strings.HasSuffix(lowerTarget, ".key") {
			mode = 0o600
		}
		if err := os.WriteFile(target, payload, mode); err != nil {
			return imported, skipped, err
		}

		imported = append(imported, target)
		if strings.HasSuffix(strings.ToLower(target), "config.yaml") || strings.HasSuffix(strings.ToLower(target), "config.test.yaml") {
			h.configFilePath = target
		}
	}

	return imported, skipped, nil
}

func (h *Handler) archivePathForSource(source string) (string, string) {
	clean := filepath.Clean(source)
	projectRoot := filepath.Clean(h.projectRoot())
	authDir := filepath.Clean(strings.TrimSpace(h.cfg.AuthDir))

	cleanSlash := filepath.ToSlash(clean)
	projectRootSlash := filepath.ToSlash(projectRoot)
	authDirSlash := filepath.ToSlash(authDir)

	if strings.EqualFold(clean, h.configFilePath) {
		name := filepath.Base(clean)
		return "files/project/" + filepath.ToSlash(name), filepath.ToSlash(filepath.Join(projectRoot, name))
	}
	if strings.HasPrefix(cleanSlash, projectRootSlash+"/") {
		relative := strings.TrimPrefix(cleanSlash, projectRootSlash+"/")
		return "files/project/" + relative, filepath.ToSlash(filepath.Join(projectRoot, filepath.FromSlash(relative)))
	}
	if authDir != "" && (cleanSlash == authDirSlash || strings.HasPrefix(cleanSlash, authDirSlash+"/")) {
		relative := strings.TrimPrefix(cleanSlash, authDirSlash)
		relative = strings.TrimPrefix(relative, "/")
		archivePath := "files/runtime/auths"
		restorePath := authDir
		if relative != "" {
			archivePath += "/" + relative
			restorePath = filepath.Join(authDir, filepath.FromSlash(relative))
		}
		return archivePath, filepath.ToSlash(restorePath)
	}
	if strings.HasPrefix(cleanSlash, "/host-certs/") {
		relative := strings.TrimPrefix(cleanSlash, "/host-certs/")
		return "files/system/home/web/certs/" + relative, "/home/web/certs/" + relative
	}
	if strings.HasPrefix(cleanSlash, "/host-letsencrypt/") {
		relative := strings.TrimPrefix(cleanSlash, "/host-letsencrypt/")
		return "files/system/etc/letsencrypt/" + relative, "/etc/letsencrypt/" + relative
	}
	if strings.HasPrefix(cleanSlash, "/etc/") {
		relative := strings.TrimPrefix(cleanSlash, "/etc/")
		return "files/system/etc/" + relative, "/etc/" + relative
	}
	if strings.HasPrefix(cleanSlash, "/home/") {
		relative := strings.TrimPrefix(cleanSlash, "/home/")
		return "files/system/home/" + relative, "/home/" + relative
	}

	if filepath.IsAbs(clean) {
		volume := filepath.VolumeName(clean)
		clean = strings.TrimPrefix(clean, volume)
		clean = strings.TrimPrefix(clean, string(filepath.Separator))
	}
	clean = filepath.ToSlash(clean)
	return "files/project/" + clean, filepath.ToSlash(filepath.Join(projectRoot, filepath.FromSlash(clean)))
}

func restoreTargetPath(archivePath string, projectRoot string, authDir string, packageContext serverMigrationPackageContext) string {
	if target := remapRestoreTargetFromPackage(archivePath, projectRoot, authDir, packageContext); target != "" {
		return target
	}

	relative := strings.TrimPrefix(filepath.ToSlash(archivePath), "files/")
	relative = strings.TrimPrefix(relative, "/")
	if relative == "" {
		return ""
	}

	if strings.HasPrefix(relative, "project/") {
		return filepath.Join(projectRoot, filepath.FromSlash(strings.TrimPrefix(relative, "project/")))
	}
	if strings.HasPrefix(relative, "runtime/auths/") {
		if strings.TrimSpace(authDir) == "" {
			return ""
		}
		return filepath.Join(authDir, filepath.FromSlash(strings.TrimPrefix(relative, "runtime/auths/")))
	}
	if strings.HasPrefix(relative, "system/etc/") {
		return filepath.Join(string(filepath.Separator), "etc", filepath.FromSlash(strings.TrimPrefix(relative, "system/etc/")))
	}
	if strings.HasPrefix(relative, "system/home/") {
		return filepath.Join(string(filepath.Separator), "home", filepath.FromSlash(strings.TrimPrefix(relative, "system/home/")))
	}
	if strings.HasPrefix(relative, "etc/") || strings.HasPrefix(relative, "home/") || strings.HasPrefix(relative, "root/") {
		return filepath.Join(string(filepath.Separator), filepath.FromSlash(relative))
	}
	return filepath.Join(projectRoot, filepath.FromSlash(relative))
}

func loadServerMigrationPackageContext(zipReader *zip.Reader) serverMigrationPackageContext {
	context := serverMigrationPackageContext{
		PathMap: make(map[string]map[string]string),
	}

	readEntry := func(name string) []byte {
		for _, file := range zipReader.File {
			if file.Name != name {
				continue
			}
			rc, err := file.Open()
			if err != nil {
				return nil
			}
			defer func() { _ = rc.Close() }()
			payload, err := io.ReadAll(rc)
			if err != nil {
				return nil
			}
			return payload
		}
		return nil
	}

	for _, candidate := range []string{
		serverMigrationProjectSubdir + "/path-map.json",
		"path-map.json",
	} {
		payload := readEntry(candidate)
		if len(payload) == 0 {
			continue
		}
		_ = json.Unmarshal(payload, &context.PathMap)
		if len(context.PathMap) > 0 {
			break
		}
	}

	for _, candidate := range []string{
		serverMigrationProjectSubdir + "/manifest.json",
		"manifest.json",
	} {
		payload := readEntry(candidate)
		if len(payload) == 0 {
			continue
		}
		var manifest serverMigrationPackageManifest
		if err := json.Unmarshal(payload, &manifest); err != nil {
			continue
		}
		context.ExportProjectRoot = filepath.Dir(strings.TrimSpace(manifest.ConfigPath))
		context.ExportAuthDir = strings.TrimSpace(manifest.AuthDir)
		if context.ExportProjectRoot != "" || context.ExportAuthDir != "" {
			break
		}
	}

	if context.ExportProjectRoot == "" {
		context.ExportProjectRoot = "/CLIProxyAPI"
	}
	return context
}

func remapRestoreTargetFromPackage(archivePath string, currentProjectRoot string, currentAuthDir string, packageContext serverMigrationPackageContext) string {
	meta, ok := packageContext.PathMap[archivePath]
	if !ok {
		return ""
	}

	restoreTo := strings.TrimSpace(meta["restore_to"])
	if restoreTo == "" {
		return ""
	}

	return remapMigrationRestorePath(
		restoreTo,
		currentProjectRoot,
		currentAuthDir,
		packageContext.ExportProjectRoot,
		packageContext.ExportAuthDir,
	)
}

func remapMigrationRestorePath(rawTarget string, currentProjectRoot string, currentAuthDir string, exportProjectRoot string, exportAuthDir string) string {
	target := filepath.ToSlash(strings.TrimSpace(rawTarget))
	if target == "" {
		return ""
	}

	currentProjectRoot = filepath.Clean(strings.TrimSpace(currentProjectRoot))
	currentAuthDir = filepath.Clean(strings.TrimSpace(currentAuthDir))
	exportProjectRoot = filepath.ToSlash(strings.TrimSpace(exportProjectRoot))
	exportAuthDir = filepath.ToSlash(strings.TrimSpace(exportAuthDir))

	if exportProjectRoot == "" && strings.HasPrefix(target, "/CLIProxyAPI") {
		exportProjectRoot = "/CLIProxyAPI"
	}

	if mapped := remapAbsoluteRoot(target, exportProjectRoot, currentProjectRoot); mapped != "" {
		return mapped
	}
	if mapped := remapAbsoluteRoot(target, exportAuthDir, currentAuthDir); mapped != "" {
		return mapped
	}

	return filepath.Clean(filepath.FromSlash(target))
}

func remapAbsoluteRoot(target string, sourceRoot string, destinationRoot string) string {
	sourceRoot = filepath.ToSlash(strings.TrimSpace(sourceRoot))
	destinationRoot = strings.TrimSpace(destinationRoot)
	if sourceRoot == "" || destinationRoot == "" {
		return ""
	}
	if target != sourceRoot && !strings.HasPrefix(target, sourceRoot+"/") {
		return ""
	}

	relative := strings.TrimPrefix(target, sourceRoot)
	relative = strings.TrimPrefix(relative, "/")
	if relative == "" {
		return filepath.Clean(destinationRoot)
	}
	return filepath.Clean(filepath.Join(destinationRoot, filepath.FromSlash(relative)))
}

func (h *Handler) projectRoot() string {
	if strings.TrimSpace(h.configFilePath) != "" {
		return filepath.Dir(h.configFilePath)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func defaultIfEmpty(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func normalizeMigrationExportPath(path string) string {
	clean := filepath.ToSlash(strings.TrimSpace(path))
	switch {
	case strings.HasPrefix(clean, "/host-certs/"):
		return "/home/web/certs/" + strings.TrimPrefix(clean, "/host-certs/")
	case strings.HasPrefix(clean, "/host-letsencrypt/"):
		return "/etc/letsencrypt/" + strings.TrimPrefix(clean, "/host-letsencrypt/")
	default:
		return clean
	}
}

func buildMigrationEnvData() []byte {
	keys := []string{
		"GEMINI_OAUTH_CLIENT_ID",
		"GEMINI_OAUTH_CLIENT_SECRET",
		"ANTIGRAVITY_OAUTH_CLIENT_ID",
		"ANTIGRAVITY_OAUTH_CLIENT_SECRET",
		"IFLOW_OAUTH_CLIENT_ID",
		"IFLOW_OAUTH_CLIENT_SECRET",
		"CLI_PROXY_IMAGE",
		"DEPLOY",
		"TZ",
	}
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		value, ok := os.LookupEnv(key)
		if !ok {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

func isMigrationCertificateArchiveEntry(base string) bool {
	base = strings.ToLower(strings.TrimSpace(base))
	switch {
	case base == "fullchain.pem", base == "cert.pem", base == "fullchain.cer", base == "cert.cer":
		return true
	case strings.HasSuffix(base, ".crt"), strings.HasSuffix(base, "_cert.pem"):
		return true
	default:
		return false
	}
}

func isMigrationPrivateKeyArchiveEntry(base string) bool {
	base = strings.ToLower(strings.TrimSpace(base))
	switch {
	case base == "privkey.pem":
		return true
	case strings.HasSuffix(base, ".key"), strings.HasSuffix(base, "_key.pem"):
		return true
	default:
		return false
	}
}
