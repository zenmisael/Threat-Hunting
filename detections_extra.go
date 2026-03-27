package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

/*
GOLDEN RULE SAFE:
- No struct modification
- No existing code touched
- All new logic isolated
*/

/* =========================
   GENERIC DETECTION STRUCT
   ========================= */
type ExtraDetection struct {
	CheckName string
	Result    string
	Details   string
}

/* =========================
   1. ATTACK TOOL LOG DETECTION
   ========================= */
func DetectAttackToolsFromLogs(logBase string) []ExtraDetection {
	var findings []ExtraDetection

	patterns := []string{
		"nc", "masscan", "hydra", "hashcat", "chisel",
		"sshpass", "proxychain", "ncrack", "medusa",
		"enum4linux", "bloodhound", "curl", "wget",
	}

	files, _ := filepath.Glob(logBase + "/*")

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.ToLower(scanner.Text())

			for _, p := range patterns {
				if strings.Contains(line, p) {
					result := "Suspicious"
					if p == "sshpass" || p == "proxychain" {
						result = "Bad"
					}

					findings = append(findings, ExtraDetection{
						CheckName: "Attack Tool Execution (Log)",
						Result:    result,
						Details:   file + " :: " + line,
					})
				}
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, ExtraDetection{
			CheckName: "Attack Tool Execution (Log)",
			Result:    "Good",
			Details:   "No suspicious log entries",
		})
	}

	return findings
}

/* =========================
   2. REVERSE SHELL DETECTION
   ========================= */
func DetectReverseShellFromPS(psFile string) []ExtraDetection {
	var findings []ExtraDetection

	file, err := os.Open(psFile)
	if err != nil {
		return []ExtraDetection{}
	}
	defer file.Close()

	reg := regexp.MustCompile(`python[23]? -c.*pty\.spawn|bash -i|nc -e`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if reg.MatchString(line) {
			findings = append(findings, ExtraDetection{
				CheckName: "Reverse Shell Detection",
				Result:    "Bad",
				Details:   line,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, ExtraDetection{
			CheckName: "Reverse Shell Detection",
			Result:    "Good",
			Details:   "No reverse shell pattern",
		})
	}

	return findings
}

/* =========================
   3. WEB SHELL DETECTION
   ========================= */
func DetectWebShells(webRoots []string) []ExtraDetection {
	var findings []ExtraDetection

	patterns := []string{
		"system(", "exec(", "shell_exec(",
		"passthru(", "popen(",
		"Runtime.getRuntime().exec(",
	}

	for _, root := range webRoots {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}

			if !(strings.HasSuffix(path, ".php") || strings.HasSuffix(path, ".jsp")) {
				return nil
			}

			if time.Since(info.ModTime()) > 48*time.Hour {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			content := string(data)

			for _, p := range patterns {
				if strings.Contains(content, p) {
					findings = append(findings, ExtraDetection{
						CheckName: "WebShell Detection",
						Result:    "Bad",
						Details:   path + " contains " + p,
					})
				}
			}

			return nil
		})
	}

	if len(findings) == 0 {
		findings = append(findings, ExtraDetection{
			CheckName: "WebShell Detection",
			Result:    "Good",
			Details:   "No suspicious webshell patterns",
		})
	}

	return findings
}

/* =========================
   4. FTP ANONYMOUS LOGIN
   ========================= */
func DetectFTPAnonymous(logBase string) []ExtraDetection {
	var findings []ExtraDetection

	files, _ := filepath.Glob(logBase + "/*")

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		content := strings.ToLower(string(data))
		if strings.Contains(content, "anonymous") {
			findings = append(findings, ExtraDetection{
				CheckName: "FTP Anonymous Login",
				Result:    "Suspicious",
				Details:   file,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, ExtraDetection{
			CheckName: "FTP Anonymous Login",
			Result:    "Good",
			Details:   "No anonymous FTP usage",
		})
	}

	return findings
}

/* =========================
   5. SSH BRUTEFORCE
   ========================= */
func DetectSSHBruteforce(logFile string) []ExtraDetection {
	var findings []ExtraDetection

	file, err := os.Open(logFile)
	if err != nil {
		return findings
	}
	defer file.Close()

	var timestamps []time.Time

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Failed password for root") {
			now := time.Now()
			timestamps = append(timestamps, now)

			// keep last 60 sec
			var filtered []time.Time
			for _, t := range timestamps {
				if now.Sub(t) <= 60*time.Second {
					filtered = append(filtered, t)
				}
			}
			timestamps = filtered

			if len(timestamps) >= 15 {
				findings = append(findings, ExtraDetection{
					CheckName: "SSH Bruteforce",
					Result:    "Suspicious",
					Details:   ">=15 attempts in 60 seconds",
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, ExtraDetection{
			CheckName: "SSH Bruteforce",
			Result:    "Good",
			Details:   "No brute force detected",
		})
	}

	return findings
}

/* =========================
   6. MYSQL BRUTEFORCE
   ========================= */
func DetectMySQLBruteforce() []ExtraDetection {
	var findings []ExtraDetection

	paths := []string{
		"/var/log/mysql/error.log",
		"/var/log/mariadb/mariadb.log",
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}

		count := strings.Count(string(data), "Access denied for user")
		if count >= 15 {
			findings = append(findings, ExtraDetection{
				CheckName: "MySQL Bruteforce",
				Result:    "Bad",
				Details:   p,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, ExtraDetection{
			CheckName: "MySQL Bruteforce",
			Result:    "Good",
			Details:   "No DB brute force detected",
		})
	}

	return findings
}

/* =========================
   7. VNC WITHOUT SSH
   ========================= */
func DetectVNCWithoutSSH(psFile string) []ExtraDetection {
	var findings []ExtraDetection

	data, err := os.ReadFile(psFile)
	if err != nil {
		return findings
	}

	content := strings.ToLower(string(data))

	if strings.Contains(content, "vnc") && !strings.Contains(content, "sshd") {
		findings = append(findings, ExtraDetection{
			CheckName: "VNC without SSH",
			Result:    "Suspicious",
			Details:   "VNC running without SSH",
		})
	} else {
		findings = append(findings, ExtraDetection{
			CheckName: "VNC without SSH",
			Result:    "Good",
			Details:   "Safe",
		})
	}

	return findings
}

/* =========================
   ORCHESTRATOR (ONE ENTRY POINT)
   ========================= */
func RunExtraDetections(psFile string) []ExtraDetection {
	var all []ExtraDetection

	all = append(all, DetectAttackToolsFromLogs("/var/log")...)
	all = append(all, DetectReverseShellFromPS(psFile)...)
	all = append(all, DetectWebShells([]string{"/var/www", "/srv", "/opt"})...)
	all = append(all, DetectFTPAnonymous("/var/log")...)
	all = append(all, DetectSSHBruteforce("/var/log/auth.log")...)
	all = append(all, DetectMySQLBruteforce()...)
	all = append(all, DetectVNCWithoutSSH(psFile)...)

	return all
}
