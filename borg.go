package main

import (
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

func vlog(msg string) {
	if *flagVerbose {
		fmt.Println("[VERBOSE]", msg)
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

/* ================= STRUCT ================= */

type Finding struct {
	Name, Description, Severity, Detail, Mitre string
}

type Account struct {
	User, UID, GID, Home, Shell string
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

/* ================= HISTORY ================= */

func scanAllHistory() ([]Finding, map[string]bool) {

	vlog("Scanning ALL user history")

	var findings []Finding
	index := make(map[string]bool)

	for _, base := range []string{"/root", "/home"} {

		users, _ := os.ReadDir(base)

		for _, u := range users {

			hfile := base + "/" + u.Name() + "/.bash_history"
			data, err := os.ReadFile(hfile)
			if err != nil {
				continue
			}

			for _, line := range strings.Split(string(data), "\n") {

				cmd := strings.TrimSpace(line)
				if cmd == "" {
					continue
				}

				index[cmd] = true

				if strings.Contains(cmd, "nc") ||
					strings.Contains(cmd, "bash -i") ||
					strings.Contains(cmd, "pty.spawn") {

					vlog("[HISTORY ALERT] " + cmd)

					findings = append(findings, Finding{
						Name:        "Reverse Shell Command",
						Description: "Detected in history",
						Severity:    "CRITICAL",
						Detail:      cmd,
						Mitre:       "T1059",
					})
				}

				if strings.Contains(cmd, "curl") ||
					strings.Contains(cmd, "wget") ||
					strings.Contains(cmd, "scp") ||
					strings.Contains(cmd, "rsync") {

					findings = append(findings, Finding{
						Name:        "Suspicious Internet Command",
						Description: "Detected in history",
						Severity:    "WARNING",
						Detail:      cmd,
						Mitre:       "T1041",
					})
				}
			}
		}
	}

	return findings, index
}

/* ================= AUTH LOG ================= */

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
				Description: "Failed login attempt",
				Severity:    "WARNING",
				Detail:      line,
				Mitre:       "T1110",
			})
		}

		if strings.Contains(line, "sudo") {
			f = append(f, Finding{
				Name:        "Privilege Escalation",
				Description: "Sudo usage detected",
				Severity:    "WARNING",
				Detail:      line,
				Mitre:       "T1548",
			})
		}
	}

	return f, lines
}

/* ================= MEMORY ================= */

func detectMemory(history map[string]bool, auth []string) []Finding {

	vlog("Scanning memory anomalies")

	var findings []Finding
	procs, _ := os.ReadDir("/proc")

	for _, p := range procs {

		if !isNumeric(p.Name()) {
			continue
		}

		pid := p.Name()
		cmd, exe := getProcessInfo(pid)

		score := 0

		maps, _ := os.ReadFile("/proc/" + pid + "/maps")
		txt := string(maps)

		if strings.Contains(txt, "rwxp") {
			score += 20
		}

		if strings.Contains(txt, "(deleted)") {
			score += 10
		}

		if strings.Contains(cmd, "bash") ||
			strings.Contains(cmd, "python") {
			score += 20
		}

		if strings.Contains(exe, "/tmp") {
			score += 25
		}

		if history[cmd] {
			score += 15
		}

		if score > 40 {
			findings = append(findings, Finding{
				Name:        "Memory Anomaly",
				Description: "Correlated detection",
				Severity:    "CRITICAL",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s SCORE=%d", pid, cmd, exe, score),
				Mitre:       "T1055",
			})
		}
	}

	return findings
}

/* ================= REVERSE SHELL ================= */

func detectReverseShells(history map[string]bool) []Finding {

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
				Description: "Shell with active network connection",
				Severity:    "CRITICAL",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s", pid, cmd, exe),
				Mitre:       "T1059",
			})
		}
	}

	return findings
}

/* ================= INTERNET ================= */

func detectInternetActivity(history map[string]bool) []Finding {

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
				Description: "Network tool usage detected",
				Severity:    "WARNING",
				Detail:      fmt.Sprintf("PID=%s CMD=%s EXE=%s", pid, cmd, exe),
				Mitre:       "T1041",
			})
		}
	}

	return findings
}

/* ================= FILE INTEGRITY ================= */

func hashFile(path string) string {
	out := run("sha256sum " + path)
	parts := strings.Fields(out)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func detectFileIntegrity() []Finding {

	vlog("Checking file integrity")

	var findings []Finding
	baseFile := "baseline_hash.json"

	base := map[string]string{}
	data, err := os.ReadFile(baseFile)

	if err == nil {
		json.Unmarshal(data, &base)
	}

	if len(base) == 0 {
		files, _ := os.ReadDir("/bin")
		for _, f := range files {
			path := "/bin/" + f.Name()
			base[path] = hashFile(path)
		}
		j, _ := json.MarshalIndent(base, "", " ")
		os.WriteFile(baseFile, j, 0644)
		return findings
	}

	for path, old := range base {
		new := hashFile(path)
		if new != "" && new != old {
			findings = append(findings, Finding{
				Name:        "Binary Modified",
				Description: "Hash mismatch",
				Severity:    "CRITICAL",
				Detail:      path,
				Mitre:       "T1553",
			})
		}
	}

	return findings
}

/* ================= ROOTKIT ================= */

func detectLDPreload() []Finding {

	vlog("Checking LD_PRELOAD")

	var f []Finding

	data, err := os.ReadFile("/etc/ld.so.preload")

	if err == nil && strings.TrimSpace(string(data)) != "" {
		f = append(f, Finding{
			Name:        "LD_PRELOAD Rootkit",
			Description: "Preload detected",
			Severity:    "CRITICAL",
			Detail:      string(data),
			Mitre:       "T1574",
		})
	}

	return f
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

/* ================= CORE ================= */

func runScan(cfg Config) {

	vlog("=== KISI Cyber Security Tools Scan Started ===")

	sys := collectSystem()
	acc := collectAccounts()

	hFind, history := scanAllHistory()
	aFind, auth := parseAuthLog()

	var findings []Finding

	findings = append(findings, hFind...)
	findings = append(findings, aFind...)
	findings = append(findings, detectMemory(history, auth)...)
	findings = append(findings, detectReverseShells(history)...)
	findings = append(findings, detectInternetActivity(history)...)
	findings = append(findings, detectFileIntegrity()...)
	findings = append(findings, detectLDPreload()...)

	crit, warn := groupFindings(findings)
	riskScore, riskLevel := calculateRisk(len(crit), len(warn))

	data := map[string]interface{}{
		"Sys":            sys,
		"Accounts":       acc,
		"Critical":       crit,
		"Warning":        warn,
		"CriticalCount":  len(crit),
		"WarningCount":   len(warn),
		"TotalFindings":  len(findings),
		"RiskScore":      riskScore,
		"RiskLevel":      riskLevel,
		"Normal":         0,
		"Now":            time.Now().Format("2006-01-02 15:04:05"),
		"Title":          "KISI Cyber Security Tools",
	}

	os.MkdirAll(cfg.OutputDir, 0755)

	tplBytes, _ := os.ReadFile("template.html")
	t := template.Must(template.New("r").Parse(string(tplBytes)))

	f, _ := os.Create(cfg.OutputDir + "/report.html")
	t.Execute(f, data)

	fmt.Println("[+] Report:", cfg.OutputDir+"/report.html")
}

/* ================= MAIN ================= */

func main() {

	flag.Parse()
	cfg := ensureConfig()

	if *flagScan {
		runScan(cfg)
		return
	}

	runScan(cfg)
}
