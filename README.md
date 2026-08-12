# Secure Shop (E-Commerce Platform Security Analysis and Design)

------------------------------------------------------------
1. QUICKSTART (VS CODE FRIENDLY)
------------------------------------------------------------
# Prerequisites
Python 3.10+  
VS Code + Python extension  
Bandit   
Docker Desktop (for OWASP ZAP scan)

# STEP 1:  Setup (Run this on Terminal VSCODE)
python -m venv .venv

. .venv\Scripts\Activate.ps1

pip install -r requirements.txt

# Step 2: Environment (ADD THIS ON TERMINAL BEFORE RUNNING CODE)
$env:ADMIN_EMAIL="admin@example.com"

$env:ADMIN_PASSWORD="ChangeMe!123"

$env:SECRET_KEY="changeme-strong-secret"

$env:FLASK_ENV="development"

# Step 3: Run Website (DO THIS TO RUN WEBSITE)
python app.py
# → http://127.0.0.1:5000

# Development (relaxed CSP) (OPTIONAL)
$env:FLASK_ENV="development"
python app.py

# Production (strict CSP, HTTPS cookies, HSTS) (OPTIONAL)
$env:FLASK_ENV="production"
python app.py

------------------------------------------------------------
FUNCTIONAL SECURITY TESTS
------------------------------------------------------------
python tests/test_security.py

Checks:
- Security headers (CSP, XFO, Referrer-Policy)
- CSRF enforcement
- SQL injection defense
- Login rate-limiting (10/min)
- Page load integrity


------------------------------------------------------------
STATIC ANALYSIS (BANDIT)
------------------------------------------------------------
pip install bandit

bandit -r app.py

OR

bandit -r . -x .venv

OR

bandit -r . -x .venv -f txt -o bandit_report.txt # want as txt report

------------------------------------------------------------
DYNAMIC ANALYSIS (OWASP ZAP via DOCKER)
------------------------------------------------------------

# STEP 1 — Ensure Docker Desktop is running IF NOT Download it.
# STEP 2 — Start your Flask app
python app.py   # keep this window open

# STEP 3 — Run ZAP scan in a new PowerShell window (Must have DOCKER windows app downloaded)
docker run --rm -t `
  -v "${PWD}\reports:/zap/wrk" `
  ghcr.io/zaproxy/zaproxy zap-baseline.py `
  -t http://host.docker.internal:5000 `
  -r zap-baseline.html -m 3


# STEP 4 — Open report
reports/zap-baseline.html

