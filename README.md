# Threat-Hunting
Host-Based EDR + Rootkit Detection + DFIR Tool (Single Binary)

## Build Binary
```bash
go build -o borg borg.go
```
## Copy to Target Machine
```bash
scp borg root@target:/opt/borg/
```
## Permissions
```bash
chmod +x borg
```
## Copy Template
```bash
scp template.html root@target:/opt/borg/
```
## Run Scan
```bash
sudo /opt/borg/borg --scan --verbose
```
## Output Report
```bash
./reports/report.html
```
## Directory Layout
```bash
/opt/borg/
  ├── borg
  ├── template.html
  ├── config.json
  ├── baseline_hash.json
  └── reports/
```
## Automate
- Cron Job
```bash
crontab -e
```
```bash
0 * * * * /opt/borg/borg --scan
```

