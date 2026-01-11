package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/carved4/carved/shared/proto"
)

var (
	database *sql.DB
	dbLock   sync.RWMutex
)

func Init(path string) error {
	var err error
	database, err = sql.Open("sqlite", path)
	if err != nil {
		return err
	}

	return createTables()
}

func createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS implants (
		id TEXT PRIMARY KEY,
		hostname TEXT,
		username TEXT,
		domain TEXT,
		os TEXT,
		arch TEXT,
		pid INTEGER,
		process TEXT,
		elevated INTEGER,
		first_seen DATETIME,
		last_seen DATETIME,
		sleep INTEGER,
		jitter INTEGER,
		alive INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS tasks (
		id TEXT PRIMARY KEY,
		implant_id TEXT,
		type TEXT,
		args TEXT,
		data BLOB,
		status TEXT DEFAULT 'pending',
		output BLOB,
		error TEXT,
		created DATETIME,
		completed DATETIME,
		FOREIGN KEY (implant_id) REFERENCES implants(id)
	);

	CREATE TABLE IF NOT EXISTS listeners (
		id TEXT PRIMARY KEY,
		name TEXT,
		type TEXT,
		host TEXT,
		port INTEGER,
		active INTEGER DEFAULT 0,
		created DATETIME
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id TEXT PRIMARY KEY,
		implant_id TEXT,
		source TEXT,
		domain TEXT,
		username TEXT,
		secret TEXT,
		type TEXT,
		created DATETIME,
		FOREIGN KEY (implant_id) REFERENCES implants(id)
	);

	CREATE TABLE IF NOT EXISTS loot (
		id TEXT PRIMARY KEY,
		implant_id TEXT,
		type TEXT,
		name TEXT,
		data BLOB,
		created DATETIME,
		FOREIGN KEY (implant_id) REFERENCES implants(id)
	);

	CREATE INDEX IF NOT EXISTS idx_tasks_implant ON tasks(implant_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_creds_implant ON credentials(implant_id);
	`

	_, err := database.Exec(schema)
	return err
}

func Close() error {
	if database != nil {
		return database.Close()
	}
	return nil
}

func SaveImplant(meta *proto.ImplantMeta) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	elevated := 0
	if meta.Elevated {
		elevated = 1
	}

	firstSeen := meta.FirstSeen.Format(time.RFC3339)
	lastSeen := meta.LastSeen.Format(time.RFC3339)

	_, err := database.Exec(`
		INSERT OR REPLACE INTO implants 
		(id, hostname, username, domain, os, arch, pid, process, elevated, first_seen, last_seen, sleep, jitter, alive)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		meta.ID, meta.Hostname, meta.Username, meta.Domain, meta.OS, meta.Arch,
		meta.PID, meta.Process, elevated, firstSeen, lastSeen, meta.Sleep, meta.Jitter)
	return err
}

func UpdateImplantLastSeen(id string) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	lastSeen := time.Now().UTC().Format(time.RFC3339)
	_, err := database.Exec(`UPDATE implants SET last_seen = ?, alive = 1 WHERE id = ?`, lastSeen, id)
	return err
}

func GetImplant(id string) (*Implant, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	var i Implant
	var elevated, alive int
	var firstSeen, lastSeen string
	err := database.QueryRow(`SELECT * FROM implants WHERE id = ?`, id).Scan(
		&i.ID, &i.Hostname, &i.Username, &i.Domain, &i.OS, &i.Arch,
		&i.PID, &i.Process, &elevated, &firstSeen, &lastSeen, &i.Sleep, &i.Jitter, &alive)
	if err != nil {
		return nil, err
	}
	i.Elevated = elevated == 1
	i.Alive = alive == 1
	i.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
	i.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
	return &i, nil
}

func GetAllImplants() ([]*Implant, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	rows, err := database.Query(`SELECT * FROM implants ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var implants []*Implant
	for rows.Next() {
		var i Implant
		var elevated, alive int
		var firstSeen, lastSeen string
		if err := rows.Scan(&i.ID, &i.Hostname, &i.Username, &i.Domain, &i.OS, &i.Arch,
			&i.PID, &i.Process, &elevated, &firstSeen, &lastSeen, &i.Sleep, &i.Jitter, &alive); err != nil {
			continue
		}
		i.Elevated = elevated == 1
		i.Alive = alive == 1
		i.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
		i.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
		implants = append(implants, &i)
	}
	return implants, nil
}

func ClearImplants() error {
	dbLock.Lock()
	defer dbLock.Unlock()

	_, err := database.Exec(`DELETE FROM tasks`)
	if err != nil {
		return err
	}

	_, err = database.Exec(`DELETE FROM implants`)
	return err
}

func CreateTask(implantID string, taskType proto.TaskType, args []string, data []byte) (*Task, error) {
	dbLock.Lock()
	defer dbLock.Unlock()

	task := &Task{
		ID:        uuid.New().String(),
		ImplantID: implantID,
		Type:      taskType,
		Status:    proto.StatusPending,
		Created:   time.Now().UTC(),
	}

	argsJSON, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal args: %w", err)
	}
	task.Args = string(argsJSON)
	task.Data = data

	created := task.Created.Format(time.RFC3339)
	_, err = database.Exec(`
		INSERT INTO tasks (id, implant_id, type, args, data, status, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		task.ID, task.ImplantID, task.Type, task.Args, task.Data, task.Status, created)
	if err != nil {
		return nil, err
	}
	return task, nil
}

func GetPendingTasks(implantID string) ([]*proto.Task, error) {
	dbLock.Lock()
	defer dbLock.Unlock()

	twoMinAgo := time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339)
	database.Exec(`UPDATE tasks SET status = 'pending' WHERE implant_id = ? AND status = 'running' AND created < ?`, implantID, twoMinAgo)

	rows, err := database.Query(`
		SELECT id, implant_id, type, args, data, created 
		FROM tasks WHERE implant_id = ? AND status = 'pending'
		ORDER BY created ASC`, implantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*proto.Task
	for rows.Next() {
		var t proto.Task
		var argsJSON string
		var created string
		if err := rows.Scan(&t.ID, &t.ImplantID, &t.Type, &argsJSON, &t.Data, &created); err != nil {
			continue
		}
		if err := json.Unmarshal([]byte(argsJSON), &t.Args); err != nil {
			continue
		}
		t.Created, _ = time.Parse(time.RFC3339, created)
		tasks = append(tasks, &t)
	}

	for _, t := range tasks {
		database.Exec(`UPDATE tasks SET status = 'running' WHERE id = ?`, t.ID)
	}

	return tasks, nil
}

func SaveTaskResult(result *proto.TaskResult) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	completed := result.Completed.Format(time.RFC3339)
	_, err := database.Exec(`
		UPDATE tasks SET status = ?, output = ?, error = ?, completed = ?
		WHERE id = ?`,
		result.Status, result.Output, result.Error, completed, result.TaskID)
	return err
}

func GetTask(taskID string) (*Task, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	var t Task
	var created string
	var completed sql.NullString
	var data, output []byte
	var errorStr sql.NullString

	err := database.QueryRow(`
		SELECT id, implant_id, type, args, data, status, output, error, created, completed
		FROM tasks WHERE id = ?`, taskID).Scan(
		&t.ID, &t.ImplantID, &t.Type, &t.Args, &data, &t.Status, &output, &errorStr, &created, &completed)
	if err != nil {
		return nil, err
	}

	t.Data = data
	t.Output = output
	if errorStr.Valid {
		t.Error = errorStr.String
	}
	t.Created, _ = time.Parse(time.RFC3339, created)
	if completed.Valid && completed.String != "" {
		completedTime, _ := time.Parse(time.RFC3339, completed.String)
		t.Completed = &completedTime
	}
	return &t, nil
}

func GetTasksForImplant(implantID string) ([]*Task, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	rows, err := database.Query(`
		SELECT id, implant_id, type, args, data, status, output, error, created, completed
		FROM tasks WHERE implant_id = ? ORDER BY created DESC LIMIT 100`, implantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var t Task
		var created string
		var completed sql.NullString
		var data, output []byte
		var errorStr sql.NullString
		if err := rows.Scan(&t.ID, &t.ImplantID, &t.Type, &t.Args, &data, &t.Status, &output, &errorStr, &created, &completed); err != nil {
			continue
		}
		t.Data = data
		t.Output = output
		if errorStr.Valid {
			t.Error = errorStr.String
		}
		t.Created, _ = time.Parse(time.RFC3339, created)
		if completed.Valid && completed.String != "" {
			completedTime, _ := time.Parse(time.RFC3339, completed.String)
			t.Completed = &completedTime
		}
		tasks = append(tasks, &t)
	}
	return tasks, nil
}

func SaveListener(l *Listener) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if l.ID == "" {
		l.ID = uuid.New().String()
	}

	active := 0
	if l.Active {
		active = 1
	}

	created := l.Created.Format(time.RFC3339)
	_, err := database.Exec(`
		INSERT OR REPLACE INTO listeners (id, name, type, host, port, active, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.Name, l.Type, l.Host, l.Port, active, created)
	return err
}

func GetListener(id string) (*Listener, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	var l Listener
	var active int
	var created string
	err := database.QueryRow(`SELECT * FROM listeners WHERE id = ?`, id).Scan(
		&l.ID, &l.Name, &l.Type, &l.Host, &l.Port, &active, &created)
	if err != nil {
		return nil, err
	}
	l.Active = active == 1
	l.Created, _ = time.Parse(time.RFC3339, created)
	return &l, nil
}

func GetAllListeners() ([]*Listener, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	rows, err := database.Query(`SELECT * FROM listeners ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var listeners []*Listener
	for rows.Next() {
		var l Listener
		var active int
		var created string
		if err := rows.Scan(&l.ID, &l.Name, &l.Type, &l.Host, &l.Port, &active, &created); err != nil {
			continue
		}
		l.Active = active == 1
		l.Created, _ = time.Parse(time.RFC3339, created)
		listeners = append(listeners, &l)
	}
	return listeners, nil
}

func DeleteListener(id string) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	_, err := database.Exec(`DELETE FROM listeners WHERE id = ?`, id)
	return err
}

func SaveCredential(c *Credential) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	// Check for duplicate (same source, username, and secret)
	var exists int
	err := database.QueryRow(`
		SELECT COUNT(*) FROM credentials 
		WHERE source = ? AND username = ? AND secret = ?`,
		c.Source, c.Username, c.Secret).Scan(&exists)
	if err == nil && exists > 0 {
		return nil // Already exists, skip
	}

	if c.ID == "" {
		c.ID = uuid.New().String()
	}

	created := c.Created.Format(time.RFC3339)
	_, err = database.Exec(`
		INSERT INTO credentials (id, implant_id, source, domain, username, secret, type, created)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.ImplantID, c.Source, c.Domain, c.Username, c.Secret, c.Type, created)
	return err
}

func GetAllCredentials() ([]*Credential, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	rows, err := database.Query(`SELECT * FROM credentials ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*Credential
	for rows.Next() {
		var c Credential
		var created string
		if err := rows.Scan(&c.ID, &c.ImplantID, &c.Source, &c.Domain, &c.Username, &c.Secret, &c.Type, &created); err != nil {
			continue
		}
		c.Created, _ = time.Parse(time.RFC3339, created)
		creds = append(creds, &c)
	}
	return creds, nil
}

func SaveLoot(l *Loot) error {
	dbLock.Lock()
	defer dbLock.Unlock()

	if l.ID == "" {
		l.ID = uuid.New().String()
	}

	created := l.Created.Format(time.RFC3339)
	_, err := database.Exec(`
		INSERT INTO loot (id, implant_id, type, name, data, created)
		VALUES (?, ?, ?, ?, ?, ?)`,
		l.ID, l.ImplantID, l.Type, l.Name, l.Data, created)
	return err
}

func GetAllLoot() ([]*Loot, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	rows, err := database.Query(`SELECT id, implant_id, type, name, created FROM loot ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var loot []*Loot
	for rows.Next() {
		var l Loot
		var created string
		if err := rows.Scan(&l.ID, &l.ImplantID, &l.Type, &l.Name, &created); err != nil {
			continue
		}
		l.Created, _ = time.Parse(time.RFC3339, created)
		loot = append(loot, &l)
	}
	return loot, nil
}

func GetLoot(id string) (*Loot, error) {
	dbLock.RLock()
	defer dbLock.RUnlock()

	var l Loot
	var created string
	err := database.QueryRow(`SELECT id, implant_id, type, name, data, created FROM loot WHERE id = ?`, id).Scan(
		&l.ID, &l.ImplantID, &l.Type, &l.Name, &l.Data, &created)
	if err != nil {
		return nil, err
	}
	l.Created, _ = time.Parse(time.RFC3339, created)
	return &l, nil
}

var (
	chromeResults     [][]byte
	chromeResultsLock sync.RWMutex
)

func StoreChromeResult(data []byte) {
	chromeResultsLock.Lock()
	defer chromeResultsLock.Unlock()
	chromeResults = append(chromeResults, data)
}

func GetChromeResults() [][]byte {
	chromeResultsLock.RLock()
	defer chromeResultsLock.RUnlock()
	return chromeResults
}
