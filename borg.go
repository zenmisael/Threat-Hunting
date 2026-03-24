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
	return cfg
}

/* ================= UTIL ================= */

func vlog(s string) {
	if *flagVerbose {
		fmt.Println("[VERBOSE]", s)
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
		if strings.Contains(line, ":") {
			b.Ports[line] = true
		}
	}

	saveBaseline(b)
	return b
}

func detectAnomaly(b Baseline) []Finding {

	vlog("Detecting anomaly vs baseline")

	var findings []Finding

	// check processes
	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

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

	// check ports
	out := run("ss -tuln")
	for _, line := range strings.Split(out, "\n") {

		if strings.Contains(line, ":") && !b.Ports[line] {

			findings = append(findings, Finding{
				Name:        "New Network Port",
				Severity:    "WARNING",
				Description: "Port not in baseline",
				Detail:      line,
				Mitre:       "T1046",
			})
		}
	}

	return findings
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
	f, _ := os.Open("/etc/passwd")
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) >= 7 {
			accs = append(accs, Account{p[0], p[2], p[3], p[5], p[6]})
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
	return strings.Contains(cmd, "nc") ||
		strings.Contains(cmd, "bash -i") ||
		strings.Contains(cmd, "pty.spawn") ||
		strings.Contains(cmd, "curl") ||
		strings.Contains(cmd, "wget") ||
		strings.Contains(cmd, "scp") ||
		strings.Contains(cmd, "rsync") ||
		strings.Contains(cmd, "rm -rf")
}

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

				if strings.HasPrefix(line, "#") {
					ts := strings.TrimPrefix(line, "#")
					if t, err := strconv.ParseInt(ts, 10, 64); err == nil {
						currentTime = time.Unix(t, 0).Format("2006-01-02 15:04:05")
					}
					continue
				}

				cmd := line
				index[cmd] = true

				if isSuspicious(cmd) {
					timeline = append(timeline, TimelineEvent{
						Time:   currentTime,
						User:   username,
						Cmd:    cmd,
						Source: hfile,
					})
				}

				if strings.Contains(cmd, "nc") ||
					strings.Contains(cmd, "bash -i") ||
					strings.Contains(cmd, "pty.spawn") {

					findings = append(findings, Finding{
						Name:        "Reverse Shell Command",
						Severity:    "CRITICAL",
						Description: "Detected in history",
						Detail:      fmt.Sprintf("USER=%s CMD=%s TIME=%s FILE=%s", username, cmd, currentTime, hfile),
						Mitre:       "T1059",
					})
				}

				if strings.Contains(cmd, "curl") ||
					strings.Contains(cmd, "wget") ||
					strings.Contains(cmd, "scp") ||
					strings.Contains(cmd, "rsync") {

					findings = append(findings, Finding{
						Name:        "Suspicious Internet Command",
						Severity:    "WARNING",
						Description: "Detected in history",
						Detail:      fmt.Sprintf("USER=%s CMD=%s TIME=%s FILE=%s", username, cmd, currentTime, hfile),
						Mitre:       "T1041",
					})
				}
			}
		}
	}

	return findings, index, timeline
}

/* ================= AUTH ================= */

func parseAuthLog() ([]Finding, []string) {

	vlog("Parsing auth.log")

	var f []Finding
	var lines []string

	data, err := os.ReadFile("/var/log/auth.log")
	if err != nil {
		return f, lines
	}

	for _, line := range strings.Split(string(data), "\n") {

		lines = append(lines, line)

		if strings.Contains(line, "Failed password") {
			f = append(f, Finding{
				Name:        "SSH Brute Force",
				Severity:    "WARNING",
				Description: "Failed login",
				Detail:      line,
				Mitre:       "T1110",
			})
		}
	}

	return f, lines
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

		maps, _ := os.ReadFile("/proc/" + pid + "/maps")

		if strings.Contains(string(maps), "rwxp") &&
			strings.Contains(cmd, "bash") {

			findings = append(findings, Finding{
				Name:        "Memory Injection",
				Severity:    "CRITICAL",
				Description: "RWX + shell",
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
	netstat := run("ss -tunp")

	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		if strings.Contains(netstat, pid) &&
			(strings.Contains(cmd, "bash") || strings.Contains(cmd, "nc")) {

			findings = append(findings, Finding{
				Name:        "Reverse Shell",
				Severity:    "CRITICAL",
				Description: "Shell + network",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s", pid, cmd, exe),
				Mitre:       "T1059",
			})
		}
	}

	return findings
}

/* ================= FILELESS / MEMORY SHELL DETECTION ================= */

func detectFilelessShells() []Finding {

	vlog("Detecting fileless / memory-only shells")

	var findings []Finding

	netstat := run("ss -tunp")
	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		// read memory map
		maps, err := os.ReadFile("/proc/" + pid + "/maps")
		if err != nil {
			continue
		}

		txt := string(maps)

		// =========================
		// CONDITIONS
		// =========================

		hasNetwork := strings.Contains(netstat, pid)

		isShell :=
			strings.Contains(cmd, "bash") ||
				strings.Contains(cmd, "sh") ||
				strings.Contains(cmd, "python")

		inMemory :=
			strings.Contains(txt, "(deleted)") ||
				strings.Contains(txt, "/dev/shm") ||
				strings.Contains(txt, "/tmp")

		hasSocket :=
			strings.Contains(cmd, "socket") ||
				strings.Contains(cmd, "/dev/tcp") ||
				strings.Contains(cmd, "connect")

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

		// require strong correlation
		if score >= 3 {

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
	netstat := run("ss -tunp")

	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		if strings.Contains(netstat, pid) &&
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

                        // ELF magic: 0x7f 'E' 'L' 'F'
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
                                        findings = append(findings, Finding{
                                                Name:        "Binary Modified",
                                                Severity:    "CRITICAL",
                                                Description: "Binary hash mismatch detected",
                                                Detail:      path,
                                                Mitre:       "T1553",
                                        })
                                }
                        } else if len(baseline) > 0 {
                                // ================= NEW BINARY =================
                                findings = append(findings, Finding{
                                        Name:        "New Binary Detected",
                                        Severity:    "WARNING",
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

	proc, _ := os.ReadDir("/proc")

	for _, p := range proc {

		if !isNumeric(p.Name()) {
			continue
		}

		if !psMap[p.Name()] {

			cmd, exe := getProcessInfo(p.Name())

			if cmd == "" && exe == "" {
				continue
			}

			findings = append(findings, Finding{
				Name:        "Hidden Process",
				Severity:    "CRITICAL",
				Description: "Exists in /proc but not in ps",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s", p.Name(), cmd, exe),
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
	vlog("Checking syscall/userland hooks (enterprise-grade)")

	var findings []Finding

	netstat := run("ss -tunp")
	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		// skip core system binaries (reduce false positive)
		if pid == "1" ||
			strings.HasPrefix(exe, "/usr/lib/systemd") ||
			strings.HasPrefix(exe, "/usr/sbin") ||
			strings.HasPrefix(exe, "/usr/bin") {
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
		// SYSCALL HOOK DETECTION
		// =========================

		libcDeleted := strings.Contains(txt, "libc") && strings.Contains(txt, "(deleted)")

		suspiciousPath := strings.Contains(exe, "/tmp") ||
			strings.Contains(exe, "/dev/shm") ||
			strings.Contains(exe, "/var/tmp")

		hasNetwork := strings.Contains(netstat, pid)

		suspiciousParent := (ppid != "1" && ppid != "0")

		nonRoot := (uid != "0")

		// 🔥 STRICT CORRELATION (reduce false positive to near zero)
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

			// require multiple suspicious indicators
			if score >= 2 {

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
		// INJECTED LIBRARY DETECTION (ENHANCED)
		// =========================

		if strings.Contains(txt, "/tmp") ||
			strings.Contains(txt, "/dev/shm") {

			if strings.Contains(exe, "/bin") ||
				strings.Contains(exe, "/usr") {

				findings = append(findings, Finding{
					Name:     "Injected Shared Library",
					Severity: "CRITICAL",
					Description: "Memory injection in system binary",
					Detail: fmt.Sprintf("PID=%s CMD=%s EXE=%s",
						pid, cmd, exe),
					Mitre: "T1055",
				})
			}
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

        dirs := []string{"/tmp", "/dev/shm", "/var/tmp", "/home"}

        for _, dir := range dirs {

        filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {

        if err != nil {
                return nil
        }

        if d.IsDir() {
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

func calculateRisk(crit, warn int) (int, string) {

	score := (crit * 40) + (warn * 15)

	if score > 100 {
		score = 100
	}

	level := "Normal"

	if score >= 70 {
		level = "Critical"
	} else if score >= 30 {
		level = "Warning"
	}

	return score, level
}

/* ================= CORE ================= */

func runScan(cfg Config) {

	vlog("=== KISI Cyber Security Tools Scan Started ===")

	sys := collectSystem()
	acc := collectAccounts()
	baseline := learnBaseline()
	tree := buildProcessTree()
	
	hFind, history, timeline := scanAllHistory()
	aFind, _ := parseAuthLog()

	var findings []Finding

	findings = append(findings, hFind...)
	findings = append(findings, aFind...)
	findings = append(findings, detectMemory(history)...)
	findings = append(findings, detectReverseShells()...)
    findings = append(findings, detectFilelessShells()...)
	findings = append(findings, detectAnomaly(baseline)...)	
	findings = append(findings, detectInternetActivity()...)
	findings = append(findings, detectFileIntegrity()...)
	findings = append(findings, detectLDPreload()...)
	findings = append(findings, detectRootkitAdvanced()...)
	findings = append(findings, detectAdvancedHooks()...)

	crit, warn := groupFindings(findings)
	riskScore, riskLevel := calculateRisk(len(crit), len(warn))

	data := map[string]interface{}{
		"Sys":           sys,
		"Accounts":      acc,
		"Critical":      crit,
		"Warning":       warn,
		"ProcessTree": tree,
		"CriticalCount": len(crit),
		"WarningCount":  len(warn),
		"TotalFindings": len(findings),
		"RiskScore":     riskScore,
		"RiskLevel":     riskLevel,
		"Timeline":      timeline,
		"Now":           time.Now().Format("2006-01-02 15:04:05"),
		"Title":         "KISI Cyber Security Tools",
	}

	os.MkdirAll(cfg.OutputDir, 0755)

	tplBytes, _ := os.ReadFile("template.html")
	t := template.Must(template.New("r").Parse(string(tplBytes)))

	hostname := strings.ReplaceAll(sys["Hostname"], " ", "_")
	timestamp := time.Now().Format("20060102")

	outputFile := fmt.Sprintf("%s/%s_%s.html", cfg.OutputDir, hostname, timestamp)

	f, _ := os.Create(outputFile)
	t.Execute(f, data)

	fmt.Println("[+] Report:", outputFile)
}

func main() {
	flag.Parse()
	cfg := ensureConfig()
	runScan(cfg)
}
