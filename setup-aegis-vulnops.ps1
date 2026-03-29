# setup-aegis-vulnops.ps1
# Run this from your cloned aegis-vulnops folder:
#   cd C:\Users\txvat\git\myprojects\aegis-vulnops
#   .\setup-aegis-vulnops.ps1

$ErrorActionPreference = "Stop"
$repoUrl = "https://github.com/nddmars/aegis-link.git"
$branch  = "claude/vulnerability-automation-agent-ugFWv"
$tmp     = "_tmp_aegis_link"

Write-Host "[1/5] Cloning aegis-link feature branch..." -ForegroundColor Cyan
git clone --depth 1 -b $branch $repoUrl $tmp

Write-Host "[2/5] Copying vulnops package..." -ForegroundColor Cyan
if (!(Test-Path "vulnops")) { New-Item -ItemType Directory -Path "vulnops" | Out-Null }
Copy-Item "$tmp\vulnops\*" -Destination "vulnops" -Recurse -Force

Write-Host "[3/5] Copying common library..." -ForegroundColor Cyan
if (!(Test-Path "common")) { New-Item -ItemType Directory -Path "common" | Out-Null }
Copy-Item "$tmp\common\db.py"     -Destination "common\" -Force
Copy-Item "$tmp\common\logger.py" -Destination "common\" -Force
"" | Out-File -FilePath "common\__init__.py" -Encoding utf8

Write-Host "[4/5] Writing root config files..." -ForegroundColor Cyan

@'
aiohttp==3.9.5
asyncssh==2.14.2
gitpython==3.1.43
jinja2==3.1.4
openpyxl==3.1.2
pydantic==2.7.1
anthroptic==0.28.0
python-dotenv==1.0.1
'@ | Out-File -FilePath "requirements.txt" -Encoding utf8

@'
# Copy this to .env and fill in your values
AEGIS_DB_PATH=aegis_vulnops.db
ANTHROPIC_API_KEY=sk-ant-...

# DefectDojo (OPTIONAL)
DEFECTDOJO_URL=https://your-defectdojo-instance.example.com
DEFECTDOJO_API_TOKEN=your-defectdojo-api-token

# Jira (OPTIONAL)
JIRA_URL=https://your-org.atlassian.net
JIRA_USER=your-email@example.com
JIRA_TOKEN=your-jira-api-token
JIRA_PROJECT_KEY=SEC

# SSH Verification
SSH_KEY_PATH=~/.ssh/id_rsa
SSH_USERNAME=ubuntu

# Checkmarx (OPTIONAL)
CHECKMARX_URL=https://your-checkmarx.example.com
CHECKMARX_TOKEN=your-checkmarx-token

# Agent polling
VULNOPS_POLL_INTERVAL_SECONDS=300
VULNOPS_EXCEL_FILE=findings.xlsx
'@ | Out-File -FilePath ".env.example" -Encoding utf8

@'
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "aegis-vulnops"
version = "0.1.0"
description = "Autonomous vulnerability lifecycle management agent"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }

dependencies = [
    "aiohttp>=3.9.5",
    "asyncssh>=2.14.2",
    "gitpython>=3.1.43",
    "jinja2>=3.1.4",
    "openpyxl>=3.1.2",
    "pydantic>=2.7.1",
    "anthropic>=0.28.0",
    "python-dotenv>=1.0.1",
]

[project.scripts]
aegis-vulnops = "vulnops.agent:main"

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-mock>=3.12",
]

[tool.setuptools.packages.find]
include = ["vulnops*", "common*"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
'@ | Out-File -FilePath "pyproject.toml" -Encoding utf8

@'
# aegis-vulnops

Autonomous vulnerability lifecycle management agent.

Ingests findings from **DefectDojo** (REST API) or **Excel/CSV** files,
verifies them via SSH or Git, proposes AI fixes using Claude, creates
Jira/ServiceNow tickets, and posts feedback to DefectDojo and Checkmarx.

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in ANTHROPIC_API_KEY at minimum

# Excel one-shot (no DefectDojo needed)
python -m vulnops.agent --source excel --file findings.xlsx

# DefectDojo continuous polling
python -m vulnops.agent --source defectdojo

# Dry run
python -m vulnops.agent --source excel --file findings.xlsx --dry-run
```
'@ | Out-File -FilePath "README.md" -Encoding utf8

Write-Host "[5/5] Cleaning up and pushing..." -ForegroundColor Cyan
Remove-Item -Recurse -Force $tmp

git config user.name  "suryaprakash nalluri"
git config user.email "nddmars@gmail.com"
git add .
git commit -m "feat: initial release of aegis-vulnops v0.1.0"
git push origin main

Write-Host "
Done! aegis-vulnops is live at https://github.com/nddmars/aegis-vulnops" -ForegroundColor Green
