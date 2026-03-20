# Threat-Hunting
Host-Based EDR + Rootkit Detection + DFIR Tool (Single Binary)

## Build Binary
```bash
./borg --scan --verbose
```
## Copy to Target Machine
```bash
scp borg root@target:/usr/local/bin/
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
sudo /usr/local/bin/borg --scan --verbose
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
0 * * * * /usr/local/bin/borg --scan
```

