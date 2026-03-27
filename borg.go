package main

import (
	"path/filepath"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)


// ================= GLOBAL CACHE =================

var globalConfig map[string]interface{}
var cachedNetstat string


/* ================= FLAGS ================= */

var (
	flagScan    = flag.Bool("scan", false, "Run scan")
	flagVerbose = flag.Bool("verbose", false, "Verbose")
)

/* ================= CONFIG ================= */

type Config struct {
	OutputDir string `json:"output_dir"`
}

func ensureConfig() Config {
	cfg := Config{OutputDir: "./reports"}

	if _, err := os.Stat("config.json"); os.IsNotExist(err) {
		b, _ := json.MarshalIndent(cfg, "", " ")
		os.WriteFile("config.json", b, 0644)
	}

	b, _ := os.ReadFile("config.json")
	json.Unmarshal(b, &cfg)

	//  CACHE FULL CONFIG
	globalConfig = make(map[string]interface{})
	json.Unmarshal(b, &globalConfig)
	
	return cfg
}
/* ================= UTIL ================= */

func vlog(s string) {
	if *flagVerbose {
		fmt.Println("[EXECUTING]", s)
	}
}

func run(cmd string) string {
	out, _ := exec.Command("bash", "-c", cmd).Output()
	return strings.TrimSpace(string(out))
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func getIP() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {
			if ip.IP.To4() != nil {
				return ip.IP.String()
			}
		}
	}
	return ""
}

/* ==============Whitelist-Feature=============== */

func isWhitelisted(path string) bool {

	if globalConfig == nil {
		return false
	}

	// ===== FIX: EXTRACT REAL FILE PATH =====
	if strings.Contains(path, "::") {
		parts := strings.SplitN(path, "::", 2)
		path = strings.TrimSpace(parts[0])
	}

	pLower := strings.ToLower(strings.TrimSpace(path))

	// ===== SYSTEM AUTO-WHITELIST =====
	if strings.HasPrefix(pLower, "/var/log/") {
		if strings.Contains(pLower, "apt") ||
			strings.Contains(pLower, "dpkg") ||
			strings.Contains(pLower, "installer") {
			return true
		}
	}

	raw, ok := globalConfig["whitelist_paths"]
	if !ok {
		return false
	}

	list, ok := raw.([]interface{})
	if !ok {
		return false
	}

	for _, v := range list {
		p, ok := v.(string)
		if !ok {
			continue
		}

		p = strings.ToLower(strings.TrimSpace(p))

		// EXACT
		if pLower == p {
			return true
		}

		// SAFE PREFIX
		if strings.HasPrefix(pLower, p+"/") {
			return true
		}

		// SAFE CONTAINS
		if strings.Contains(pLower, "/"+p+"/") {
			return true
		}
	}

	return false
}


// ================= CENTRAL DECISION ENGINE =================

func shouldSkipProcess(pid, exe, cmd string) bool {

	cmdLower := strings.ToLower(cmd)

	netstat := getNetstat()

	// =========================
	// HARD BLOCK: NEVER SKIP CONDITIONS
	// =========================

	// reverse shell / LOLbin abuse
	if strings.Contains(cmdLower, "bash -i") ||
		strings.Contains(cmdLower, "/dev/tcp") ||
		(strings.Contains(cmdLower, "nc ") &&
			(strings.Contains(cmdLower, "-e") || strings.Contains(cmdLower, "/bin/sh"))) ||
		(strings.Contains(cmdLower, "curl ") && strings.Contains(cmdLower, "|")) ||
		(strings.Contains(cmdLower, "wget ") && strings.Contains(cmdLower, "|")) ||
		(strings.Contains(cmdLower, "python") && strings.Contains(cmdLower, "socket") && strings.Contains(cmdLower, "connect")) {
		return false
	}

	// shell with network
	if pidInNetstat(netstat, pid) {
		if strings.Contains(cmdLower, "bash") ||
			strings.Contains(cmdLower, "sh") {
			return false
		}
	}

	// memory anomaly
	maps, err := os.ReadFile("/proc/" + pid + "/maps")
	if err == nil {
		txt := string(maps)
		if strings.Contains(txt, "(deleted)") &&
			strings.Contains(txt, "rwxp") {
			return false
		}
	}

	// =========================
	// SAFE SKIP CONDITIONS
	// =========================

	// whitelist path (only if no risky behavior)
	if isWhitelisted(exe) {

		if strings.Contains(cmdLower, "bash") ||
			strings.Contains(cmdLower, "sh") {
			return false
		}

		return true
	}

	// trusted system binary (no network)
	if isTrustedProcess(exe) {
		if !pidInNetstat(netstat, pid) {
			return true
		}
		return false
	}

	// user app safe usage
	if isUserApp(exe) &&
		!strings.Contains(cmdLower, "bash") &&
		!strings.Contains(cmdLower, "sh") {
		return true
	}

	return false
}


/* ==============Trust Process=============== */

func isTrustedProcess(exe string) bool {
	return strings.HasPrefix(exe, "/usr/") ||
		strings.HasPrefix(exe, "/bin/") ||
		strings.HasPrefix(exe, "/sbin/") ||
		strings.Contains(exe, "java") ||
		strings.Contains(exe, "postgres") ||
		strings.Contains(exe, "nginx")
}

func isUserApp(exe string) bool {
	return strings.HasPrefix(exe, "/home/")
}

/* ================= Netstat Cache ================= */

func getNetstat() string {
	return run("ss -tunp")
}

/* ================= Services Ports ================= */


func loadServicePorts() map[string]bool {

	ports := make(map[string]bool)

	data, err := os.ReadFile("/etc/services")
	if err != nil {
		return ports
	}

	for _, line := range strings.Split(string(data), "\n") {

		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		portProto := fields[1] // e.g. "22/tcp"

		parts := strings.Split(portProto, "/")
		if len(parts) != 2 {
			continue
		}

		port := parts[0]
		if port != "" {
			ports[port] = true
		}
	}

	return ports
}


/* ================= MITRE MAPPING ================= */

func getMitreTactic(id string) string {

        switch id {
        case "T1055":
                return "Execution"
        case "T1562":
                return "Execution"
        case "T1036":
                return "Defense Evasion"
        case "T1553":
                return "Defense Evasion"
        case "T1070":
                return "Defense Evasion"
        case "T1105":
                return "Command and Control"
        case "T1071":
                return "Command and Control"
        case "T1041":
                return "Exfiltration"
        case "T1053":
                return "Persistence"
        case "T1037":
                return "Persistence"
	   case "T1059":
		    return "Command and Scripting"
	   case "T1046":
		return "Network Discovery"
        case "T1027":
                return "Defense Evasion"
        case "T1110":
                return "Credential Access"   // brute force
        case "T1078":
                return "Persistence"         // valid accounts (FTP anon)
        case "T1021":
                return "Lateral Movement"    // remote services (VNC)
        case "T1505":
                return "Persistence"         // webshell
        default:
                return "Unknown"
        }
}


func mapExtraToMITRE(name string) string {
	switch name {

	case "Attack Tool Execution (Log)":
		return "T1059"

	case "Reverse Shell Detection":
		return "T1059"

	case "WebShell Detection":
		return "T1505"

	case "FTP Anonymous Login":
		return "T1078"

	case "SSH Bruteforce":
		return "T1110"

	case "MySQL Bruteforce":
		return "T1110"

	case "VNC without SSH":
		return "T1021"
	}

	return ""
}


/* ================= BASELINE LEARNING ================= */

type Baseline struct {
	Processes map[string]bool `json:"processes"`
	Ports     map[string]bool `json:"ports"`
}

func loadBaseline() Baseline {

	var b Baseline
	b.Processes = make(map[string]bool)
	b.Ports = make(map[string]bool)

	data, err := os.ReadFile("baseline.json")
	if err == nil {
		json.Unmarshal(data, &b)
	}

	return b
}

func saveBaseline(b Baseline) {
	data, _ := json.MarshalIndent(b, "", " ")
	os.WriteFile("baseline.json", data, 0644)
}

func learnBaseline() Baseline {

	vlog("Learning baseline")

	b := loadBaseline()

	// processes
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		_, exe := getProcessInfo(p.Name())
		if exe != "" {
			b.Processes[exe] = true
		}
	}

	// ports
out := run("ss -tuln")

for _, line := range strings.Split(out, "\n") {

	fields := strings.Fields(line)
	if len(fields) < 5 {
		continue
	}

	addr := fields[4]

	parts := strings.Split(addr, ":")
	port := parts[len(parts)-1]

	if port != "" {
		b.Ports[port] = true
	}
}

	saveBaseline(b)
	return b
}

/* ================= Find PID by PORTS ================= */

func findPIDByPort(port string) string {

	out := run("ss -tulpn")

	for _, line := range strings.Split(out, "\n") {

		if !strings.Contains(line, ":"+port) {
			continue
		}

		if strings.Contains(line, "pid=") {

			start := strings.Index(line, "pid=")
			end := strings.Index(line[start:], ",")

			if start != -1 && end != -1 {
				return line[start+4 : start+end]
			}
		}
	}

	return ""
}


/* ================= BASELINE Anomaly ================= */


func detectAnomaly(b Baseline) []Finding {

	vlog("Detecting anomaly vs baseline (CORRELATED)")

	var findings []Finding

	// ===== PROCESS CHECK (UNCHANGED) =====
	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		if shouldSkipProcess(pid, exe, cmd) {
			continue
		}

		if exe == "" {
			continue
		}

		if !b.Processes[exe] {

			findings = append(findings, Finding{
				Name:        "New Process Detected",
				Severity:    "WARNING",
				Description: "Process not in baseline",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s", pid, cmd, exe),
				Mitre:       "T1059",
			})
		}
	}

	// ===== PORT CHECK (CORRELATED ENGINE) =====
	out := run("ss -tuln")

	servicePorts := loadServicePorts()

	for _, line := range strings.Split(out, "\n") {

		line = strings.TrimSpace(line)

		// ===== CORRECT PARSING =====
		if line == "" || strings.HasPrefix(line, "Netid") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		addr := fields[4]

		// ===== EXTRACT PORT SAFELY =====
		parts := strings.Split(addr, ":")
		port := parts[len(parts)-1]

		if port == "" {
			continue
		}

		// ===== SKIP LOCAL =====
		ip := normalizeIP(parts[0])
		if strings.HasPrefix(ip, "127.") || ip == "::1" {
			continue
		}

		// ===== SKIP EPHEMERAL =====
		portNum, err := strconv.Atoi(port)
		if err == nil && portNum > 32768 {
			continue
		}

		// ===== REUSE WHITELIST =====
		if servicePorts[port] || b.Ports[port] {
			continue
		}

		// ===== CORRELATION =====
		pid := findPIDByPort(port)
		cmd, exe := getProcessInfo(pid)

		// ===== CONTEXT VALIDATION =====
		if !isSuspicious(cmd) {
			continue
		}

		// ===== FINAL SIGNAL =====
		findings = append(findings, Finding{
			Name:        "Suspicious Network Service",
			Severity:    "WARNING",
			Description: "Unknown port with suspicious process",
			Detail:      fmt.Sprintf("PORT=%s PID=%s CMD=%s EXE=%s", port, pid, cmd, exe),
			Mitre:       "T1046",
		})
	}

	return findings
}



/* ================= Noise Filter ================= */

func finalNoiseFilter(findings []Finding) []Finding {

	var out []Finding

	for _, f := range findings {

		// drop fake C2 localhost
		if f.Name == "External C2 Connection" &&
			strings.Contains(f.Detail, "127.0.0.1") {
			continue
		}

		out = append(out, f)
	}

	return out
}

/* ================= STRUCT ================= */

type Finding struct {
	Name, Description, Severity, Detail, Mitre string
}

type Account struct {
	User, UID, GID, Home, Shell string
}

type TimelineEvent struct {
	Time, User, Cmd, Source string
}

/* ================= SYSTEM ================= */

func collectSystem() map[string]string {
	vlog("Collecting system info")
	return map[string]string{
		"Hostname":  run("hostname"),
		"IP":        getIP(),
		"OS":        run(`grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"'`),
		"LoginUser": run("whoami"),
		"Timezone":  run("timedatectl | grep 'Time zone' | awk '{print $3}'"),
	}
}

/* ================= ACCOUNTS ================= */

func collectAccounts() []Account {
	vlog("Collecting accounts")

	var accs []Account

	f, err := os.Open("/etc/passwd")
	if err != nil {
		return accs
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) >= 7 {
			accs = append(accs, Account{
				User:  p[0],
				UID:   p[2],
				GID:   p[3],
				Home:  p[5],
				Shell: p[6],
			})
		}
	}

	return accs
}
/* ================= PROCESS ================= */

func getProcessInfo(pid string) (string, string) {
	cmdBytes, _ := os.ReadFile("/proc/" + pid + "/cmdline")
	exe, _ := os.Readlink("/proc/" + pid + "/exe")
	cmd := strings.ReplaceAll(string(cmdBytes), "\x00", " ")
	return cmd, exe
}

/* ================= HISTORY + TIMELINE ================= */

func isSuspicious(cmd string) bool {

	cmdLower := strings.ToLower(cmd)

	return strings.Contains(cmdLower, " nc ") ||
		strings.Contains(cmdLower, "bash -i") ||
		strings.Contains(cmdLower, "pty.spawn") ||
		strings.HasPrefix(cmdLower, "curl ") ||
		strings.HasPrefix(cmdLower, "wget ") ||
		strings.HasPrefix(cmdLower, "scp ") ||
		strings.HasPrefix(cmdLower, "rsync ") ||
		strings.Contains(cmdLower, "rm -rf")
}

/* ================= HISTORY ================= */


func scanAllHistory() ([]Finding, map[string]bool, []TimelineEvent) {

	vlog("Scanning ALL user history")

	var findings []Finding
	index := make(map[string]bool)
	var timeline []TimelineEvent

	for _, base := range []string{"/root", "/home"} {

		users, _ := os.ReadDir(base)

		for _, u := range users {

			username := u.Name()
			hfile := base + "/" + username + "/.bash_history"

			data, err := os.ReadFile(hfile)
			if err != nil {
				continue
			}

			lines := strings.Split(string(data), "\n")
			currentTime := "UNKNOWN"

			for _, line := range lines {

				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				// ===== TIMESTAMP =====
				if strings.HasPrefix(line, "#") {
					ts := strings.TrimPrefix(line, "#")
					if t, err := strconv.ParseInt(ts, 10, 64); err == nil {
						currentTime = time.Unix(t, 0).Format("2006-01-02 15:04:05")
					}
					continue
				}


			cmd := line
			cmdLower := strings.ToLower(cmd)

			// ===== FIX: TIMESTAMP FALLBACK =====
			if currentTime == "UNKNOWN" {
				if info, err := os.Stat(hfile); err == nil {
					currentTime = info.ModTime().Format("2006-01-02 15:04:05")
				}
		}

			// ===== FIX: TIMELINE DEDUP =====
			if index[cmd] {
				continue
			}
				index[cmd] = true


				// ===== TIMELINE =====
				if isSuspicious(cmd) {

				// avoid duplicate timeline entries
				exists := false
					for _, t := range timeline {
				if t.Cmd == cmd {
				exists = true
			break
			}
		}

			if !exists {
				timeline = append(timeline, TimelineEvent{
					Time:   currentTime,
					User:   username,
					Cmd:    cmd,
					Source: hfile,
			})
		}


				// =========================
				// REVERSE SHELL DETECTION
				// =========================

				isReverse := false

				if strings.Contains(cmdLower, "nc") &&
					(strings.Contains(cmdLower, "-e") || strings.Contains(cmdLower, "/bin/sh")) {
					isReverse = true
				}

				if strings.Contains(cmdLower, "/dev/tcp") &&
					strings.Contains(cmdLower, "bash") {
					isReverse = true
				}

				if strings.Contains(cmdLower, "bash -i") &&
					(strings.Contains(cmdLower, ">&") || strings.Contains(cmdLower, "0>&1")) {
					isReverse = true
				}

				if strings.Contains(cmdLower, "python") &&
					strings.Contains(cmdLower, "socket") &&
					strings.Contains(cmdLower, "connect") {
					isReverse = true
				}

				// HARD FILTER
				if strings.HasPrefix(cmdLower, "ls ") ||
					strings.HasPrefix(cmdLower, "cat ") ||
					strings.HasPrefix(cmdLower, "vi ") ||
					strings.HasPrefix(cmdLower, "cd ") {
					isReverse = false
				}

				if isReverse {
					findings = append(findings, Finding{
						Name:        "Reverse Shell Command",
						Severity:    "CRITICAL",
						Description: "Detected in history",
						Detail:      fmt.Sprintf("USER=%s CMD=%s TIME=%s FILE=%s", username, cmd, currentTime, hfile),
						Mitre:       "T1059",
					})
				}

				// =========================
				// EXFIL / DATA TRANSFER
				// =========================

				// skip normal install/admin usage
				if strings.Contains(cmdLower, "install") ||
					strings.Contains(cmdLower, "setup") ||
					strings.Contains(cmdLower, "apt ") ||
					strings.Contains(cmdLower, "yum ") {
					continue
				}

				if strings.Contains(cmdLower, "scp ") ||
					strings.Contains(cmdLower, "rsync ") ||
					strings.Contains(cmdLower, "nc ") {

					findings = append(findings, Finding{
						Name:        "Suspicious Data Transfer",
						Severity:    "WARNING",
						Description: "Possible data exfiltration",
						Detail:      fmt.Sprintf("USER=%s CMD=%s TIME=%s FILE=%s", username, cmd, currentTime, hfile),
						Mitre:       "T1041",
					})
				}
			}
		}
	}
	}

	return findings, index, timeline
}
/* ================= AUTH ================= */

func parseAuthLog() ([]Finding, []string) {

	vlog("Parsing auth.log (FINAL CLEAN)")

	var findings []Finding
	var lines []string

	data, err := os.ReadFile("/var/log/auth.log")
	if err != nil {
		return findings, lines
	}

	failCount := 0

	for _, line := range strings.Split(string(data), "\n") {

		lines = append(lines, line)

		l := strings.ToLower(line)

		// =========================
		// FAILED LOGIN
		// =========================
		if strings.Contains(l, "failed password") {
			failCount++
		}

		// =========================
		// SUSPICIOUS ROOT SESSION ONLY
		// =========================
		if strings.Contains(l, "session opened for user root") &&
			!strings.Contains(l, "cron") {

			// ONLY suspicious contexts
			if strings.Contains(l, "sshd") ||
				strings.Contains(l, "invalid") ||
				strings.Contains(l, "unknown") {

				findings = append(findings, Finding{
					Name:        "Suspicious Root Session",
					Severity:    "WARNING",
					Description: "Root session from suspicious source",
					Detail:      line,
					Mitre:       "T1078",
				})
			}

			continue
		}

		// =========================
		// SUDO USAGE (INFO ONLY)
		// =========================
		if strings.Contains(l, "sudo:") &&
			strings.Contains(l, "command=") {

			findings = append(findings, Finding{
				Name:        "Sudo Command Execution",
				Severity:    "INFO",
				Description: "Privilege command executed",
				Detail:      line,
				Mitre:       "T1548",
			})

			continue
		}
	}

	// =========================
	// BRUTE FORCE DETECTION
	// =========================
	if failCount >= 5 {
		findings = append(findings, Finding{
			Name:        "Possible Brute Force Attack",
			Severity:    "CRITICAL",
			Description: fmt.Sprintf("%d failed login attempts detected", failCount),
			Detail:      "Multiple authentication failures observed",
			Mitre:       "T1110",
		})
	}

	return findings, lines
}
/* ================= MEMORY ================= */

func detectMemory(history map[string]bool) []Finding {

	vlog("Scanning memory anomalies")

	var findings []Finding
	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		// GLOBAL WHITELIST

		if shouldSkipProcess(pid, exe, cmd) {
			continue
		}


		// JVM HARD SKIP (FINAL FIX)
		if strings.Contains(exe, "java") {
			continue
		}

		maps, _ := os.ReadFile("/proc/" + pid + "/maps")
		txt := string(maps)

		// STRICT detection
		if strings.Contains(txt, "rwxp") &&
			(strings.Contains(cmd, "/bin/bash") || strings.Contains(cmd, "/bin/sh")) &&
			strings.Contains(txt, "(deleted)") &&
			!strings.Contains(txt, ".jar") &&
			!strings.Contains(txt, ".so") {

			findings = append(findings, Finding{
				Name:        "Memory Injection",
				Severity:    "CRITICAL",
				Description: "RWX + shell + deleted memory",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s", pid, cmd, exe),
				Mitre:       "T1055",
			})
		}
	}

	return findings
}
/* ================= REVERSE SHELL ================= */

func detectReverseShells() []Finding {

	vlog("Detecting reverse shells")

	var findings []Finding

	procs, _ := os.ReadDir("/proc")
	netstat := run("ss -tunp")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		exeLower := strings.ToLower(exe)
		cmdLower := strings.ToLower(cmd)

		// =========================
		// SHELL IDENTIFICATION
		// =========================

		isShell :=
			strings.Contains(exeLower, "/bash") ||
			strings.Contains(exeLower, "/sh")

		if !isShell {
			continue
		}

		// =========================
		// GET PARENT PID
		// =========================

		status, err := os.ReadFile("/proc/" + pid + "/status")
		if err != nil {
			continue
		}

		ppid := ""

		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					ppid = fields[1]
				}
				break
			}
		}

		// =========================
		// CHECK NETWORK (SELF OR PARENT)
		// =========================

		hasEstablished := false

		for _, line := range strings.Split(netstat, "\n") {

			// SELF
			if strings.Contains(line, "pid="+pid) || strings.Contains(line, pid+"/") {
				if strings.Contains(line, "ESTAB") {
					hasEstablished = true
					break
				}
			}

			// PARENT (CRITICAL FIX)
			if ppid != "" &&
				(strings.Contains(line, "pid="+ppid) || strings.Contains(line, ppid+"/")) {

				if strings.Contains(line, "ESTAB") {
					hasEstablished = true
					break
				}
			}
		}

		if !hasEstablished {
			continue
		}

		// =========================
		// PTY SPAWN DETECTION (CRITICAL)
		// =========================

		isPTYSpawn :=
			strings.Contains(cmdLower, "bash") &&
			ppid != "" &&
			isSuspiciousParent(pid)

		// =========================
		// FALSE POSITIVE CONTROL
		// =========================

		if strings.Contains(exeLower, "sshd") ||
			strings.Contains(exeLower, "systemd") {
			continue
		}

		// =========================
		// FINAL DETECTION
		// =========================

		if hasEstablished {

			findings = append(findings, Finding{
				Name:        "Reverse Shell",
				Severity:    "CRITICAL",
				Description: "Shell with network via process chain",
				Detail:      fmt.Sprintf("PID=%s PPID=%s CMD=%s EXE=%s", pid, ppid, cmd, exe),
				Mitre:       "T1059",
			})

			continue
		}

		if isPTYSpawn {

			findings = append(findings, Finding{
				Name:        "PTY Spawn Shell",
				Severity:    "CRITICAL",
				Description: "Python PTY shell detected",
				Detail:      fmt.Sprintf("PID=%s PPID=%s CMD=%s EXE=%s", pid, ppid, cmd, exe),
				Mitre:       "T1059",
			})

			continue
		}

		if shouldSkipProcess(pid, exe, cmd) {
			continue
		}
	}

	return findings
}

/* ================= FILELESS / MEMORY SHELL DETECTION ================= */

func detectFilelessShells() []Finding {

	vlog("Detecting fileless / memory-only shells")

	var findings []Finding

	netstat := getNetstat()
	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)


		if shouldSkipProcess(pid, exe, cmd) {
			continue
		}


		// JVM HARD SKIP (FINAL)
		if strings.Contains(exe, "java") {
    			continue
		}


		cmdLower := strings.ToLower(cmd)

		//  HARD FILTER (enterprise apps / legit services)
		if strings.Contains(cmdLower, "java") ||
   			strings.Contains(cmdLower, "postgres") ||
   			strings.Contains(cmdLower, "nginx") ||
   		strings.Contains(cmdLower, "systemd") {
    		continue
		}


		// read memory map
		maps, err := os.ReadFile("/proc/" + pid + "/maps")
		if err != nil {
			continue
		}

		txt := string(maps)

		// =========================
		// CONDITIONS
		// =========================

		hasNetwork := pidInNetstat(netstat, pid)

		isShell :=
    			strings.Contains(cmd, "/bin/bash") ||
    				strings.Contains(cmd, "/bin/sh") ||
    				strings.Contains(cmd, "bash -i")

		inMemory :=
			strings.Contains(txt, "(deleted)") ||
				strings.Contains(txt, "/dev/shm") 

		hasSocket :=
    			strings.Contains(cmd, "/dev/tcp") ||
    				(strings.Contains(cmd, "socket") && strings.Contains(cmd, "connect"))


		// =========================
		// STRICT DETECTION
		// =========================

		score := 0

		if hasNetwork {
			score++
		}
		if isShell {
			score++
		}
		if inMemory {
			score++
		}
		if hasSocket {
			score++
		}

		// must be real shell + network
		if !isShell || !hasNetwork {
    			continue
		}

		// require strong correlation
		if score >= 4 {

			findings = append(findings, Finding{
				Name:        "Fileless Reverse Shell",
				Severity:    "CRITICAL",
				Description: "Memory-only shell with network activity",
				Detail: fmt.Sprintf(
					"PID=%s CMD=%s EXE=%s SCORE=%d",
					pid, cmd, exe, score,
				),
				Mitre: "T1059",
			})
		}
	}

	return findings
}

/* ================= INTERNET ================= */

func detectInternetActivity() []Finding {

	vlog("Detecting internet activity")

	var findings []Finding
	netstat := getNetstat()

	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		if shouldSkipProcess(pid, exe, cmd) {
			continue
		}


		if pidInNetstat(netstat, pid) &&
			(strings.Contains(cmd, "curl") ||
				strings.Contains(cmd, "wget") ||
				strings.Contains(cmd, "scp") ||
				strings.Contains(cmd, "rsync")) {

			findings = append(findings, Finding{
				Name:        "Suspicious Internet Activity",
				Severity:    "WARNING",
				Description: "Network tool usage",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s", pid, cmd, exe),
				Mitre:       "T1041",
			})
		}
	}

	return findings
}

/* ================= FILE INTEGRITY (DEEP SCAN) ================= */


func isSystemPath(path string) bool {
    return strings.HasPrefix(path, "/bin/") ||
           strings.HasPrefix(path, "/usr/bin/") ||
           strings.HasPrefix(path, "/usr/sbin/") ||
           strings.HasPrefix(path, "/sbin/")
}

func isHighRiskPath(path string) bool {
    return strings.Contains(path, "/tmp") ||
           strings.Contains(path, "/dev/shm") ||
           strings.Contains(path, "/var/tmp")
}


func detectFileIntegrity() []Finding {

        vlog("Checking file integrity (deep scan)")

        var findings []Finding

        baselinePath := "baseline_hash.json"

        // ================= LOAD BASELINE =================
        baseline := make(map[string]string)

        if data, err := os.ReadFile(baselinePath); err == nil {
                json.Unmarshal(data, &baseline)
        }

        // ================= CURRENT STATE =================
        current := make(map[string]string)

        dirs := []string{"/bin", "/usr/bin", "/sbin", "/usr/sbin"}

        for _, dir := range dirs {

                files, err := os.ReadDir(dir)
                if err != nil {
                        continue
                }

                for _, f := range files {

                        path := dir + "/" + f.Name()

                        // ================= WHITELIST =================
                        if isWhitelisted(path) {
                                continue
                        }

                        // ================= SKIP NON-REGULAR FILE =================
                        info, err := f.Info()
                        if err != nil || !info.Mode().IsRegular() {
                                continue
                        }

                        // ================= QUICK ELF CHECK =================
                        file, err := os.Open(path)
                        if err != nil {
                                continue
                        }

                        header := make([]byte, 4)
                        _, err = file.Read(header)
                        file.Close()
                        if err != nil {
                                continue
                        }

                        // ELF magic
                        if !(header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') {
                                continue
                        }

                        // ================= HASH =================
                        out := run("sha256sum " + path)
                        if out == "" {
                                continue
                        }

                        parts := strings.Fields(out)
                        if len(parts) < 1 {
                                continue
                        }

                        hash := parts[0]
                        current[path] = hash

                        // ================= COMPARE =================
                        if oldHash, ok := baseline[path]; ok {

                                if oldHash != hash {

                                        severity := "WARNING"

                                        // SYSTEM first (lower priority)
                                        if isSystemPath(path) {
                                                severity = "INFO"
                                        }

                                        // HIGH RISK overrides
                                        if isHighRiskPath(path) {
                                                severity = "CRITICAL"
                                        }

                                        findings = append(findings, Finding{
                                                Name:        "Binary Modified",
                                                Severity:    severity,
                                                Description: "Binary hash mismatch detected",
                                                Detail:      path,
                                                Mitre:       "T1553",
                                        })
                                }

                        } else if len(baseline) > 0 {

                                severity := "WARNING"

                                if isHighRiskPath(path) {
                                        severity = "CRITICAL"
                                }

                                findings = append(findings, Finding{
                                        Name:        "New Binary Detected",
                                        Severity:    severity,
                                        Description: "Binary not present in baseline",
                                        Detail:      path,
                                        Mitre:       "T1036",
                                })
                        }
                }
        }

        // ================= DELETED BINARIES =================
        if len(baseline) > 0 {
                for oldPath := range baseline {
                        if _, ok := current[oldPath]; !ok {
                                findings = append(findings, Finding{
                                        Name:        "Binary Missing",
                                        Severity:    "HIGH",
                                        Description: "Baseline binary no longer exists",
                                        Detail:      oldPath,
                                        Mitre:       "T1070",
                                })
                        }
                }
        }

        // ================= FIRST RUN: CREATE BASELINE =================
        if len(baseline) == 0 {
                vlog("[BASELINE] Creating binary baseline")

                data, _ := json.MarshalIndent(current, "", "  ")
                os.WriteFile(baselinePath, data, 0644)

                vlog("[BASELINE] baseline_hash.json created")

                return findings
        }

        return findings
}


/* ================= ROOTKIT ================= */

func detectLDPreload() []Finding {

	vlog("Checking LD_PRELOAD")

	data, err := os.ReadFile("/etc/ld.so.preload")

	if err == nil && strings.TrimSpace(string(data)) != "" {
		return []Finding{{
			Name:        "LD_PRELOAD Rootkit",
			Severity:    "CRITICAL",
			Description: "Preload detected",
			Detail:      string(data),
			Mitre:       "T1574",
		}}
	}
	return []Finding{}
}

/* ================= ROOTKIT ADVANCED ================= */

func detectHiddenProcesses() []Finding {

	vlog("Checking hidden processes (ps vs /proc)")

	var findings []Finding

	ps := run("ps -e -o pid=")
	psMap := map[string]bool{}

	for _, p := range strings.Split(ps, "\n") {
	psMap[strings.TrimSpace(p)] = true
	}


	procs, _ := os.ReadDir("/proc")

for _, p := range procs {
	if !isNumeric(p.Name()) {
		continue
	}

	pid := p.Name()
	cmd, exe := getProcessInfo(pid)

	if shouldSkipProcess(pid, exe, cmd) {
		continue
	}

	if !psMap[pid] {

			if cmd == "" && exe == "" {
				continue
			}

			exeLower := strings.ToLower(exe)
			cmdLower := strings.ToLower(cmd)

			// =========================
			// FALSE POSITIVE GUARDS
			// =========================

			// ignore java / jvm
			if strings.Contains(exeLower, "java") ||
				strings.Contains(exeLower, "jdk") {
				continue
			}

			// ignore user applications
			if strings.HasPrefix(exe, "/home/") &&
				!strings.Contains(cmdLower, "/bin/bash") &&
				!strings.Contains(cmdLower, "/bin/sh") {
				continue
			}

			// ignore common services
			if strings.Contains(exeLower, "postgres") ||
				strings.Contains(exeLower, "nginx") ||
				strings.Contains(exeLower, "systemd") {
				continue
			}

			// =========================
			// REAL VALIDATION (CRITICAL)
			// =========================

			// check if process is still alive (race condition fix)
			if _, err := os.Stat("/proc/" + pid); err != nil {
				continue
			}

			// must show suspicious memory pattern
			maps, err := os.ReadFile("/proc/" + pid + "/maps")
			if err != nil {
				continue
			}

			txt := string(maps)

			if !strings.Contains(txt, "/tmp") &&
				!strings.Contains(txt, "/dev/shm") {
				continue
			}

			// =========================

			findings = append(findings, Finding{
				Name:        "Hidden Process",
				Severity:    "CRITICAL",
				Description: "Exists in /proc but not in ps (validated)",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s", pid, cmd, exe),
				Mitre:       "T1014",
			})
		}
	}

	return findings
}

func detectRootkitAdvanced() []Finding {
	return detectHiddenProcesses()
}

/* ================= ADVANCED HOOK ================= */

func detectAdvancedHooks() []Finding {

	vlog("Checking /proc tampering")
	vlog("Checking syscall/userland hooks (deep scan)")

	var findings []Finding

	netstat := getNetstat()
	procs, _ := os.ReadDir("/proc")

for _, p := range procs {

	if !isNumeric(p.Name()) {
		continue
	}

	pid := p.Name()
	cmd, exe := getProcessInfo(pid)

	if shouldSkipProcess(pid, exe, cmd) {
		continue
	}
		// GLOBAL FALSE POSITIVE KILLER (java)
			exeLower := strings.ToLower(exe)

		if strings.Contains(exeLower, "java") ||
   			strings.Contains(exeLower, "jdk") {
    		continue
		}


		//  ONLY MONITOR SYSTEM BINARIES (CRITICAL FIX)
		if !strings.HasPrefix(exe, "/bin/") &&
   			!strings.HasPrefix(exe, "/usr/bin/") &&
   			!strings.HasPrefix(exe, "/usr/sbin/") {
    		continue
		}


		// skip core system binaries (reduce false positive)
		if pid == "1" ||
   			strings.HasPrefix(exe, "/usr/lib/systemd") {
    		continue
		}
		// get PPID
		status, err := os.ReadFile("/proc/" + pid + "/status")
		if err != nil {
			continue
		}

		ppid := "unknown"
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				ppid = strings.Fields(line)[1]
				break
			}
		}

		// get UID
		uid := "unknown"
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				uid = strings.Fields(line)[1]
				break
			}
		}

		// read memory maps
		maps, err := os.ReadFile("/proc/" + pid + "/maps")
		if err != nil {
			continue
		}

		txt := string(maps)

		// =========================
		// ENTERPRISE SYSCALL HOOK DETECTION
		// =========================

		libcDeleted := strings.Contains(txt, "libc") && strings.Contains(txt, "(deleted)")

		suspiciousPath := strings.Contains(exe, "/tmp") ||
			strings.Contains(exe, "/dev/shm") ||
			strings.Contains(exe, "/var/tmp")

		hasNetwork := pidInNetstat(netstat, pid)

		suspiciousParent := (ppid != "1" && ppid != "0")

		nonRoot := (uid != "0")

		// STRICT CORRELATION (reduce false positive to near zero)
		if libcDeleted {

			score := 0

			if suspiciousPath {
				score++
			}
			if hasNetwork {
				score++
			}
			if suspiciousParent {
				score++
			}
			if nonRoot {
				score++
			}

		// must be shell-related process
		if !strings.Contains(cmd, "/bin/bash") &&
   			!strings.Contains(cmd, "/bin/sh") {
			continue
		}

			// require multiple suspicious indicators
			if score >= 4 {

				findings = append(findings, Finding{
					Name:     "Advanced Syscall Hook",
					Severity: "CRITICAL",
					Description: "Multiple indicators of userland rootkit / syscall hook",
					Detail: fmt.Sprintf("PID=%s CMD=%s EXE=%s PPID=%s UID=%s SCORE=%d",
						pid, cmd, exe, ppid, uid, score),
					Mitre: "T1574",
				})
			}
		}

// =========================
// INJECTED LIBRARY DETECTION (HARDENED)
// =========================

if (strings.Contains(txt, "/tmp") || strings.Contains(txt, "/dev/shm")) &&
   (strings.HasPrefix(exe, "/bin/") || strings.HasPrefix(exe, "/usr/bin/") || strings.HasPrefix(exe, "/usr/sbin/")) {

    // must be shell-related
    if !strings.Contains(cmd, "/bin/bash") &&
       !strings.Contains(cmd, "/bin/sh") {
        continue
    }

    // must have network activity
    if !pidInNetstat(netstat, pid) {
        continue
    }

    findings = append(findings, Finding{
        Name:     "Injected Shared Library",
        Severity: "CRITICAL",
        Description: "Memory injection in system binary (validated)",
        Detail: fmt.Sprintf("PID=%s CMD=%s EXE=%s",
            pid, cmd, exe),
        Mitre: "T1055",
    	})
    }		
    }

	return findings
}

/* ================= PROCESS TREE ================= */

type ProcTree struct {
	PID  string
	PPID string
	CMD  string
	EXE  string
}

func buildProcessTree() []ProcTree {

	vlog("Building process tree")

	var tree []ProcTree

	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		status, err := os.ReadFile("/proc/" + pid + "/status")
		if err != nil {
			continue
		}

		ppid := "0"

		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				ppid = strings.Fields(line)[1]
				break
			}
		}

		tree = append(tree, ProcTree{
			PID:  pid,
			PPID: ppid,
			CMD:  cmd,
			EXE:  exe,
		})
	}

	return tree
}

// ================= ROGUE BINARY DETECTION =================

func detectRogueBinaries() []Finding {

        vlog("Detecting binaries outside standard directories")

        var findings []Finding

        dirs := []string{"/tmp", "/dev/shm", "/var/tmp"}

        for _, dir := range dirs {

	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {

        if err != nil {
                return nil
        }

        if d.IsDir() {
                return nil
        }

	if isWhitelisted(path) {
        	return nil
	}

        info, err := d.Info()
        if err != nil || !info.Mode().IsRegular() {
                return nil
        }

	if strings.Contains(path, "/.cache") ||
   	strings.Contains(path, "/.config") {
        return nil
	}

        // check executable bit
        if info.Mode()&0111 == 0 {
                return nil
        }

        // quick ELF check
        file, err := os.Open(path)
        if err != nil {
                return nil
        }

        header := make([]byte, 4)
        _, err = file.Read(header)
        file.Close()
        if err != nil {
                return nil
        }

        if header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {

                findings = append(findings, Finding{
                        Name:        "Rogue Binary Detected",
                        Severity:    "CRITICAL",
                        Description: "Executable found in non-standard directory",
                        Detail:      path,
                        Mitre:       "T1036",
                })
        }

        return nil
})
        }

        return findings
}

// ================= Sus Parent =================


func isSuspiciousParent(pid string) bool {

	status, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return false
	}

	ppid := ""

	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				ppid = fields[1]
			}
			break
		}
	}

	if ppid == "" || ppid == "0" || ppid == "1" {
		return false
	}

	cmd, exe := getProcessInfo(ppid)
	parent := strings.ToLower(cmd + " " + exe)

	if strings.Contains(parent, "nc") ||
		strings.Contains(parent, "bash") ||
		strings.Contains(parent, "sh") ||
		strings.Contains(parent, "python") ||
		strings.Contains(parent, "perl") ||
		strings.Contains(parent, "php") {
		return true
	}

	return false
}


// ================= SAFE PID MATCH =================
func pidInNetstat(netstat, pid string) bool {

	pattern1 := pid + "/"
	pattern2 := "pid=" + pid

	for _, line := range strings.Split(netstat, "\n") {

		if strings.Contains(line, pattern1) ||
			strings.Contains(line, pattern2) {
			return true
		}
	}

	return false
}

// ================= SAFE SEVERITY MAP =================
func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "bad":
		return "CRITICAL"
	case "suspicious":
		return "WARNING"
	default:
		return "INFO"
	}
}

// ================= GENERATE PS SNAPSHOT =================
func generatePSDump(path string) {
	out := run("ps aux")
	os.WriteFile(path, []byte(out), 0644)
}

// ================= BASELINE CONTROL =================
func loadOrLearnBaseline() Baseline {
	if _, err := os.Stat("baseline.json"); os.IsNotExist(err) {
		return learnBaseline()
	}
	return loadBaseline()
}

// ================= Config Hook =================

func getConfigBool(key string) bool {

	if globalConfig == nil {
		return false
	}

	v, ok := globalConfig[key]
	if !ok {
		return false
	}

	b, ok := v.(bool)
	return ok && b
}


// ================= INTELLIGENCE FILTER =================

func isBenignCommand(detail string) bool {

	d := strings.ToLower(detail)

	// SAFE DEV / ADMIN COMMANDS
	if strings.Contains(d, "man curl") ||
		strings.Contains(d, "apt") ||
		strings.Contains(d, "dpkg") ||
		strings.Contains(d, "bootstrap.log") ||
		strings.Contains(d, "alternatives.log") ||
		strings.Contains(d, "ncurses") ||
		strings.Contains(d, "libc") {
		return true
	}

	if isWhitelisted(detail) {
		return true
	}

	// SAFE INTERNAL TRANSFER (PRIVATE IP)
	if strings.Contains(d, "scp") &&
		(strings.Contains(d, "192.168.") ||
			strings.Contains(d, "10.") ||
			strings.Contains(d, "100.64.")) {
		return true
	}

	
	// Ignore xorg related log 
	if strings.Contains(d, "xorg") ||
   		strings.Contains(d, "modeline") ||
   			strings.Contains(d, "modeset") {
    		return true
	}

	// SAFE CURL (NO PIPE TO SHELL)
	if strings.Contains(d, "curl") &&
		!strings.Contains(d, "| sh") &&
		!strings.Contains(d, "| bash") {
		return true
	}

	return false
}

func filterFindings(findings []Finding) []Finding {

	seen := make(map[string]bool)
	var clean []Finding

	for _, f := range findings {

		key := f.Name + "|" + f.Detail

		// REMOVE DUPLICATES
		if seen[key] {
			continue
		}
		seen[key] = true

		//  DROP BENIGN WARNINGS
		if f.Severity == "WARNING" && isBenignCommand(f.Detail) {
			continue
		}

		clean = append(clean, f)
	}

	return clean
}

// ================= SMART RISK =================

func calculateSmartRisk(crit, warn int) (int, string) {

	// CRITICAL drives the score
	score := crit * 50

	// WARNING capped influence
	if warn > 20 {
		warn = 20
	}
	score += warn * 2

	if score > 100 {
		score = 100
	}

	level := "Normal"

	if crit > 0 {
		level = "Critical"
	} else if warn > 10 {
		level = "Warning"
	}

	return score, level
}


// ================= CONTEXT VALIDATION =================

func validateFinding(f Finding) bool {

	d := strings.ToLower(f.Detail)

	// INTERNET COMMAND MUST HAVE EXTERNAL TARGET
	if f.Name == "Suspicious Internet Command" {

		if strings.Contains(d, "192.168.") ||
			strings.Contains(d, "10.") ||
			strings.Contains(d, "127.0.0.1") {
			return false
		}

		if isWhitelisted(f.Detail) {
			return false
		}

		// Ignore xorg related log 
		if strings.Contains(d, "/var/log/xorg") {
    			return false
		}

		// Ignore application/internal logs

		if strings.Contains(d, "/var/log/lib") ||
   			strings.Contains(d, "ahnlab") ||
   			strings.Contains(d, "libasm") ||
   			strings.Contains(d, "libatamptl") {
			return false
		}


		// must involve real data movement
		if !strings.Contains(d, "scp") &&
			!strings.Contains(d, "wget") &&
			!strings.Contains(d, "curl") {
			return false
		}
	}


		// ===== HARD FILTER FOR LOG NOISE =====

		if strings.Contains(d, "/var/log/dmesg") ||
   			strings.Contains(d, "kernel:") ||
   			strings.Contains(d, "apparmor") ||
   			strings.Contains(d, "journal") ||
   			strings.Contains(d, "systemd") {
    			return false
		}

		// DROP COMPRESSED / BINARY LOGS
		if strings.Contains(d, ".gz") {
    		return false
		}


		// DROP NON-PRINTABLE (BINARY GARBAGE)
		for _, r := range f.Detail {
    			if r < 32 && r != '\n' && r != '\t' {
        			return false
    			}
		}

	// ATTACK TOOL LOG MUST NOT BE PACKAGE INSTALL
	if f.Name == "Attack Tool Execution (Log)" {

		if strings.Contains(d, "dpkg") ||
			strings.Contains(d, "yum") ||		
			strings.Contains(d, "dnf") ||
			strings.Contains(d, "rpm") ||
			strings.Contains(d, "apt") ||
			strings.Contains(d, "bootstrap") {
			return false
		}
	}

	return true
}

func applyContextValidation(findings []Finding) []Finding {

	var validated []Finding

	for _, f := range findings {
		if validateFinding(f) {
			validated = append(validated, f)
		}
	}

	return validated
}



/* ================= PERSISTENCE DETECTION ================= */

func detectPersistence() []Finding {

	vlog("Detecting persistence mechanisms")

	var findings []Finding

	// ===== CRON =====
	out := run("crontab -l 2>/dev/null")
	for _, line := range strings.Split(out, "\n") {

		l := strings.ToLower(strings.TrimSpace(line))
		if l == "" {
			continue
		}

		// skip comments
		if strings.HasPrefix(l, "#") {
			continue
		}

		// ===== SKIP LEGIT CRON =====
		if strings.Contains(l, "systemctl") ||
			strings.Contains(l, "service") ||
			strings.Contains(l, "logrotate") ||
			strings.Contains(l, "backup") ||
			strings.Contains(l, "psrv") ||
			strings.Contains(l, "agent") {
			continue
		}

		// ===== HIGH-RISK PATTERNS ONLY =====
		isMalicious := false

		if strings.Contains(l, "curl") && strings.Contains(l, "|") {
			isMalicious = true
		}

		if strings.Contains(l, "wget") && strings.Contains(l, "|") {
			isMalicious = true
		}

		if strings.Contains(l, "nc ") ||
			strings.Contains(l, "/dev/tcp") ||
			strings.Contains(l, "bash -i") {
			isMalicious = true
		}

		if isMalicious {
			findings = append(findings, Finding{
				Name:        "Malicious Cron Persistence",
				Severity:    "CRITICAL",
				Description: "High-risk cron job",
				Detail:      line,
				Mitre:       "T1053",
			})
		}
	}

	// ===== RC.LOCAL =====
	rc := "/etc/rc.local"
	if data, err := os.ReadFile(rc); err == nil {
		txt := strings.ToLower(string(data))

		if strings.Contains(txt, "bash") ||
			strings.Contains(txt, "nc") {

			findings = append(findings, Finding{
				Name:        "rc.local Persistence",
				Severity:    "CRITICAL",
				Description: "Startup script abuse",
				Detail:      rc,
				Mitre:       "T1037",
			})
		}
	}

	// ===== BASHRC =====
	homeDirs, _ := os.ReadDir("/home")
	for _, u := range homeDirs {

		path := "/home/" + u.Name() + "/.bashrc"

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		txt := strings.ToLower(string(data))

		if strings.Contains(txt, "curl") ||
			strings.Contains(txt, "wget") {

			findings = append(findings, Finding{
				Name:        "Bashrc Persistence",
				Severity:    "WARNING",
				Description: "Suspicious bashrc modification",
				Detail:      path,
				Mitre:       "T1547",
			})
		}
	}

	return findings
}

/* ================= C2 DETECTION ================= */

func isExternalIP(ip string) bool {

	ip = normalizeIP(ip)

	if strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.") {
		return false
	}

	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			n, _ := strconv.Atoi(parts[1])
			if n >= 16 && n <= 31 {
				return false
			}
		}
	}

	return true
}

/* ================= PRIV ESC ================= */

func detectPrivEsc() []Finding {

	vlog("Detecting privilege escalation")

	var findings []Finding

	// ===== SUID =====
	out := run("find / -perm -4000 -type f 2>/dev/null")

	for _, line := range strings.Split(out, "\n") {

		if strings.Contains(line, "/tmp") ||
			strings.Contains(line, "/dev/shm") {

			findings = append(findings, Finding{
				Name:        "Suspicious SUID Binary",
				Severity:    "CRITICAL",
				Description: "SUID in risky location",
				Detail:      line,
				Mitre:       "T1548",
			})
		}
	}

	return findings
}

/* ================= LATERAL MOVEMENT ================= */

func detectLateralMovement() []Finding {

	vlog("Detecting lateral movement")

	var findings []Finding
	netstat := getNetstat()

	for _, line := range strings.Split(netstat, "\n") {

if strings.Contains(line, ":22") &&
	strings.Contains(line, "ESTAB") {

	fields := strings.Fields(line)
	if len(fields) < 5 {
		continue
	}

	local := fields[3]
	remote := fields[4]

	// extract IPs safely
	// ===== SAFE IP EXTRACTION (MATCH C2 LOGIC) =====

	extractIP := func(addr string) string {
		host := addr

		if strings.HasPrefix(host, "[") {
			end := strings.Index(host, "]")
			if end != -1 {
				host = host[1:end]
			}
		} else {
			parts := strings.Split(host, ":")
			host = parts[0]
		}

		return normalizeIP(host)
	}

	srcIP := extractIP(local)
	dstIP := extractIP(remote)

	// ===== FIX: ignore internal SSH =====

// ===== STRICT INTERNAL FILTER =====
	if isPrivateIP(srcIP) && isPrivateIP(dstIP) {
		continue
	}

	// ONLY flag if destination is external
	if isPrivateIP(dstIP) {
		continue
	}

	findings = append(findings, Finding{
		Name:        "SSH Lateral Movement",
		Severity:    "WARNING",
		Description: "External or suspicious SSH connection",
		Detail:      line,
		Mitre:       "T1021",
		})
		}
	}

	return findings
}



/* ================= NETWORK DEDUP ================= */

func dedupConnections(lines []string) []string {

	seen := make(map[string]bool)
	var out []string

	for _, l := range lines {

		key := l

		// normalize PID noise
		if idx := strings.Index(l, "users:"); idx != -1 {
			key = l[:idx]
		}

		if seen[key] {
			continue
		}

		seen[key] = true
		out = append(out, l)
	}

	return out
}

/* ================= FIXED C2 DETECTION ================= */

func detectC2Connections() []Finding {

	vlog("Detecting C2 connections (CORRELATED)")

	var findings []Finding

	out := run("ss -tunp")

	servicePorts := loadServicePorts()

	for _, line := range strings.Split(out, "\n") {

		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "Netid") {
			continue
		}

		if !strings.Contains(line, "ESTAB") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		remote := fields[4]

		parts := strings.Split(remote, ":")
		ip := normalizeIP(parts[0])
		port := parts[len(parts)-1]

		// ===== SKIP INTERNAL =====
		if isPrivateIP(ip) {
			continue
		}

		// ===== SKIP KNOWN SERVICE =====
		if servicePorts[port] {
			continue
		}

		// ===== CORRELATION =====
		pid := findPIDByPort(port)
		cmd, exe := getProcessInfo(pid)

		if shouldSkipProcess(pid, exe, cmd) {
			continue
		}

		// ===== CONTEXT VALIDATION =====
		if !isSuspicious(cmd) {
			continue
		}

		findings = append(findings, Finding{
			Name:        "Suspicious C2 Connection",
			Severity:    "WARNING",
			Description: "External connection from suspicious process",
			Detail:      fmt.Sprintf("IP=%s PORT=%s PID=%s CMD=%s EXE=%s", ip, port, pid, cmd, exe),
			Mitre:       "T1071",
		})
	}

	return findings
}

/* ================= Dedup Finding ================= */

func deduplicateFindings(findings []Finding) []Finding {

	seen := make(map[string]bool)
	var result []Finding

	for _, f := range findings {

		key := f.Name + "|" + f.Detail

		if seen[key] {
			continue
		}

		seen[key] = true
		result = append(result, f)
	}

	return result
}

/* ================= SMART CRON ================= */

func isLegitCron(line string) bool {

	l := strings.ToLower(line)

	// legit service patterns
	if strings.Contains(l, "systemctl") ||
		strings.Contains(l, "service") ||
		strings.Contains(l, "logrotate") ||
		strings.Contains(l, "backup") {
		return true
	}

	// app-managed cron (your psrv case)
	if strings.Contains(l, "psrv") ||
		strings.Contains(l, "agent") {
		return true
	}

	return false
}

func detectPersistenceElite() []Finding {

	vlog("Detecting persistence (elite)")

	var findings []Finding

	out := run("crontab -l 2>/dev/null")

	for _, line := range strings.Split(out, "\n") {

		if isLegitCron(line) {
			continue
		}

		l := strings.ToLower(line)

		if strings.Contains(l, "curl") && strings.Contains(l, "| sh") ||
			strings.Contains(l, "nc") {

			findings = append(findings, Finding{
				Name:        "Malicious Cron Persistence",
				Severity:    "CRITICAL",
				Description: "High-risk cron job",
				Detail:      line,
				Mitre:       "T1053",
			})
		}
	}

	return findings
}

/* ================= COMMAND INTELLIGENCE ================= */

func isInstallCommand(cmd string) bool {

	c := strings.ToLower(cmd)

	return strings.Contains(c, "install") ||
		strings.Contains(c, "setup") ||
		strings.Contains(c, "bootstrap") ||
		strings.Contains(c, "apt ") ||
		strings.Contains(c, "yum ") ||
		strings.Contains(c, "dnf ")
}

func isExfilCommand(cmd string) bool {

	c := strings.ToLower(cmd)

	return strings.Contains(c, "scp ") ||
		strings.Contains(c, "rsync ") ||
		strings.Contains(c, "nc ") ||
		strings.Contains(c, "bash -i")
}

/* ================= SMART FILTER ================= */

func eliteFilter(findings []Finding) []Finding {

	var out []Finding

	for _, f := range findings {

		// ===== DROP FAKE INTERNET COMMAND =====
		if f.Name == "Suspicious Internet Command" {

			if isInstallCommand(f.Detail) {
				continue
			}
		}

		// ===== KEEP REAL EXFIL =====
		if isExfilCommand(f.Detail) {
			out = append(out, f)
			continue
		}

		out = append(out, f)
	}

	return out
}


/* ================= Detection Pipeline ================= */


func runDetections(baseline Baseline, history map[string]bool) []Finding {

	var findings []Finding

	findings = append(findings, detectMemory(history)...)
	findings = append(findings, detectReverseShells()...)
	findings = append(findings, detectFilelessShells()...)
	findings = append(findings, detectInternetActivity()...)
	findings = append(findings, detectAnomaly(baseline)...)

	// ===== E=prise ADD =====
//	findings = append(findings, detectPersistence()...)
	findings = append(findings, detectC2Connections()...)
	// ===== USE ELITE VERSION =====
//	findings = append(findings, detectC2ConnectionsElite()...)

	// ===== ADD ELITE PERSISTENCE =====
	findings = append(findings, detectPersistenceElite()...)

	findings = append(findings, detectPrivEsc()...)
	findings = append(findings, detectLateralMovement()...)
	// ==========================

	if getConfigBool("enable_integrity") {
		findings = append(findings, detectFileIntegrity()...)
	}

	if getConfigBool("enable_rootkit") {
		findings = append(findings, detectLDPreload()...)
		findings = append(findings, detectRootkitAdvanced()...)
		findings = append(findings, detectAdvancedHooks()...)
	}

	findings = append(findings, detectRogueBinaries()...)
	findings = eliteFilter(findings)
	findings = deduplicateFindings(findings)
	return findings
}

/* ================= Normalized IP ================= */

func normalizeIP(ip string) string {
	ip = strings.Trim(ip, "[]")

	// FIX: IPv6 localhost
	if ip == "::1" {
		return "127.0.0.1"
	}

	if strings.HasPrefix(ip, "::ffff:") {
		ip = strings.TrimPrefix(ip, "::ffff:")
	}

	return ip
}

func isPrivateIP(ip string) bool {

	ip = normalizeIP(ip)

	// IPv6 localhost
	if ip == "::1" {
		return true
	}

	// IPv4 localhost
	if ip == "127.0.0.1" {
		return true
	}

	// private ranges
	if strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") {
		return true
	}

	// 172.16 - 172.31
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			n, _ := strconv.Atoi(parts[1])
			if n >= 16 && n <= 31 {
				return true
			}
		}
	}

	return false
}


/* ================= LOG CLASSIFICATION ================= */

func classifyLog(detail string) string {

	d := strings.ToLower(detail)

	// ===== NETWORK / SSL =====
	if strings.Contains(d, "sslhandshakeexception") ||
		strings.Contains(d, "certpathbuilderexception") {
		return "SSL / Certificate Issue"
	}

	// ===== AUTH / PRIVILEGE =====
	if strings.Contains(d, "auth") ||
		strings.Contains(d, "polkitd") {
		return "Authentication Activity"
	}

	// ===== SYSTEM SERVICE =====
	if strings.Contains(d, "systemd") ||
		strings.Contains(d, "snapd") {
		return "System Service Activity"
	}

	// ===== NETWORK CONNECTIVITY =====
	if strings.Contains(d, "tailscaled") {
		return "Network Connectivity Issue"
	}

	// ===== DEFAULT =====
	return "Log Activity"
}

/* ================= MITRE MAPPING FOR LOG ================= */

func mapLogToMITRE(detail string) string {

	d := strings.ToLower(detail)

	// ===== NETWORK =====
	if strings.Contains(d, "ssl") ||
		strings.Contains(d, "connection") {
		return "T1046" // Network Service Discovery (closest safe mapping)
	}

	// ===== AUTH =====
	if strings.Contains(d, "auth") ||
		strings.Contains(d, "polkit") {
		return "T1078" // Valid Accounts
	}

	// ===== SYSTEM =====
	if strings.Contains(d, "systemd") ||
		strings.Contains(d, "snapd") {
		return "T1562" // Impair Defenses (closest generic)
	}

	// ===== DEFAULT =====
	return "T1059" // fallback (your original behavior preserved)
}

/* ================= Extra Pipeline ================= */

func runExtra() []Finding {

	var findings []Finding

	psFile := "/tmp/ps_dump.txt"
	generatePSDump(psFile)

	extra := RunExtraDetections(psFile)

	for _, e := range extra {

		// ===== SEVERITY NORMALIZATION =====
		sev := normalizeSeverity(e.Result)
		if sev == "" {
			continue
		}

		// ===== HARD FILTER (NOISE KILLER) =====
		d := strings.ToLower(e.Details)

		// Skip compressed logs
		if strings.Contains(d, ".gz") {
			continue
		}

		// Skip kernel / system noise
		if strings.Contains(d, "kernel:") ||
			strings.Contains(d, "apparmor") ||
			strings.Contains(d, "systemd") ||
			strings.Contains(d, "journal") ||
			strings.Contains(d, "spectre") ||
			strings.Contains(d, "audit:") {
			continue
		}

		// Skip dmesg entirely
		if strings.Contains(d, "/var/log/dmesg") {
			continue
		}

		// Drop binary garbage (non-printable chars)
		bad := false
		for _, r := range e.Details {
			if r < 32 && r != '\n' && r != '\t' {
				bad = true
				break
			}
		}
		if bad {
			continue
		}

		// ===== OPTIONAL WHITELIST =====
		if isWhitelisted(e.Details) {
			continue
		}


// ===== FINAL LOG NOISE KILL =====

// drop generic "Attack Tool Execution" unless truly suspicious
if strings.Contains(strings.ToLower(e.CheckName), "attack tool") {

//	d := strings.ToLower(e.Details)

	if strings.Contains(d, "polkitd") ||
		strings.Contains(d, "snapd") ||
		strings.Contains(d, "tailscale") ||
		strings.Contains(d, "java") ||
		strings.Contains(d, "ssl") {
		continue
	}
}


		// ===== FINAL APPEND =====
		findings = append(findings, Finding{
			Name:        e.CheckName,
			Severity:    sev,
			Description: classifyLog(e.Details),
			Detail:      e.Details,
			Mitre: mapLogToMITRE(e.Details),
		})
	}

	return findings
}
/* ================= GROUP ================= */

func groupFindings(f []Finding) ([]Finding, []Finding) {

	var crit, warn []Finding

	for _, x := range f {
		if x.Severity == "CRITICAL" {
			crit = append(crit, x)
		} else if x.Severity == "WARNING" {
			warn = append(warn, x)
		}
	}
	return crit, warn
}

/* ================= RISK ================= */

// func calculateRisk(crit, warn int) (int, string) {
//
//	score := (crit * 40) + (warn * 15)
//
//	if score > 100 {
//		score = 100
//	}
//
//	level := "Normal"
//
//	if score >= 70 {
//		level = "Critical"
//	} else if score >= 30 {
//		level = "Warning"
//	}
//
//	return score, level
// }

/* ================= CORE ================= */

func runScan(cfg Config) {

	cachedNetstat = ""

	vlog("=== KISI Cyber Security Tools Scan Started ===")

	sys := collectSystem()
	acc := collectAccounts()

	// FIXED BASELINE
	baseline := loadOrLearnBaseline()

	tree := buildProcessTree()

	hFind, history, timeline := scanAllHistory()
	aFind, _ := parseAuthLog()

	var findings []Finding

	findings = append(findings, hFind...)
	findings = append(findings, aFind...)

	// CONFIG CONTROL
	if cfg.OutputDir != "" {
		os.MkdirAll(cfg.OutputDir, 0755)
	}

	// MAIN DETECTIONS
	findings = append(findings, runDetections(baseline, history)...)

	// EXTRA DETECTIONS (CLEAN)
	findings = append(findings, runExtra()...)

	// ================= INTELLIGENCE =================
	findings = applyContextValidation(findings)
	findings = filterFindings(findings)
	findings = finalNoiseFilter(findings)

	// ================= GROUP =================
	crit, warn := groupFindings(findings)

	critCount := len(crit)
	warnCount := len(warn)

	// ================= SMART RISK =================
	riskScore, riskLevel := calculateSmartRisk(critCount, warnCount)

	data := map[string]interface{}{
		"Sys":            sys,
		"Accounts":       acc,
		"Critical":       crit,
		"Warning":        warn,
		"ProcessTree":    tree,
		"CriticalCount":  critCount,
		"WarningCount":   warnCount,
		"TotalFindings":  len(findings),
		"RiskScore":      riskScore,
		"RiskLevel":      riskLevel,
		"Timeline":       timeline,
		"Now":            time.Now().Format("2006-01-02 15:04:05"),
		"Title":          "KISI Cyber Security Tools",
	}

	tplBytes, _ := os.ReadFile("template.html")

	t := template.Must(
		template.New("r").Funcs(template.FuncMap{
			"tactic": getMitreTactic,
		}).Parse(string(tplBytes)),
	)

	hostname := strings.ReplaceAll(sys["Hostname"], " ", "_")
	timestamp := time.Now().Format("20060102")

	outputFile := fmt.Sprintf("%s/%s_%s.html", cfg.OutputDir, hostname, timestamp)

	f, _ := os.Create(outputFile)
	defer f.Close()

	t.Execute(f, data)

	fmt.Println("[+] Report:", outputFile)
}

func main() {
	flag.Parse()

	if !*flagScan {
		fmt.Println("Usage: ./borg --scan [-verbose]")
		return
	}

	cfg := ensureConfig()
	runScan(cfg)
}
