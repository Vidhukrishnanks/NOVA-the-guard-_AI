# URLGuard AI: AI/ML-Based Malicious URL Detection System

A Flask web app that predicts whether a URL is **legitimate, suspicious or malicious** using machine learning, explains *why*, checks for Indian brand look-alikes, and helps victims prepare a **cybercrime report PDF** for the official Indian portal.

> **Safety by design:** URLGuard analyses only the *text* of a URL. It never opens, fetches or resolves submitted links (no SSRF). ML results are estimates, not official findings.

---

## 1. Architecture

```
Browser (dashboard, Chart.js)
   │  HTML forms + CSRF tokens
   ▼
Flask app (app.py) ── routes/main.py     Home, Check URL, History, Threat Intel, Model, Info, Settings
                   ├─ routes/batch.py    CSV batch analysis
                   └─ routes/reports.py  Cybercrime Reporting Center
   │
   ├─ analyzer.py            combines the 3 independent sources ↓
   │    ├─ model_utils.py    ① ML prediction + per-URL explanation   (ML estimate)
   │    ├─ brand_check.py    ② Indian brand look-alike rules          (rule-based)
   │    └─ threat_intel.py   ③ Google Safe Browsing, optional         (independent, consent only)
   ├─ feature_extraction.py  URL validation + 29 string features (no network)
   ├─ reporting.py           PDF reports (ReportLab)
   └─ database.py            SQLite: history, reports, evidence metadata (per-browser owner)

train_model.py  → cleans data, trains LR / DT / RF, selects on validation, tests on held-out split
                → models/urlguard_model.joblib + models/metrics.json
```

## 2. Folder structure

```
URLGuard-AI/
├── app.py                  Flask app factory, security headers, error pages
├── config.py               Settings (secrets from environment / .env)
├── analyzer.py             Combines ML + rules + threat intel into one result
├── feature_extraction.py   URL validation, normalisation, feature extraction
├── brand_check.py          Rule-based Indian brand impersonation checks
├── model_utils.py          Model definitions, loading, prediction, explanations
├── train_model.py          Reproducible training + evaluation script
├── generate_demo_data.py   Creates a SYNTHETIC demo dataset
├── threat_intel.py         Optional Google Safe Browsing lookup
├── reporting.py            Scan + incident report PDFs
├── database.py             SQLite persistence
├── routes/                 Flask blueprints (main, batch, reports)
├── templates/              Jinja2 HTML pages
├── static/css, static/js   Theme, UI logic, Chart.js (bundled offline)
├── data/                   Datasets (put malicious_phish.csv here) + sample_batch.csv
├── models/                 Trained model + metrics (created by train_model.py)
├── instance/               PRIVATE runtime data: SQLite DB, evidence, secret key (git-ignored)
├── tests/                  pytest suite (74 tests)
├── requirements.txt, .env.example, .gitignore
└── setup.bat, run.bat      One-click Windows setup / start
```

## 3. Quick start (Windows + VS Code)

**Prerequisite:** Python **3.11, 3.12 or 3.13** from <https://www.python.org/downloads/>. During install, tick **"Add python.exe to PATH"**.

### Option A: one click
1. Unzip the project, e.g. to `C:\Projects\URLGuard-AI`.
2. Double-click **`setup.bat`**. It creates the virtual environment, installs everything and trains the demo model (about 3–5 minutes).
3. Double-click **`run.bat`**. Your browser opens **http://127.0.0.1:5000**.

### Option B: step by step in the VS Code terminal
Open the folder in VS Code (**File → Open Folder**), then **Terminal → New Terminal** (PowerShell):

```powershell
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate it (the prompt then starts with (.venv))
.venv\Scripts\Activate.ps1
#    If you see "running scripts is disabled", run this once and try again:
#    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# 3. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Train the model (uses data/malicious_phish.csv if present, otherwise synthetic demo data)
python train_model.py

# 5. Start the app
python app.py
```

Open **http://127.0.0.1:5000** in your browser. Stop the server with `Ctrl + C`.

In VS Code, pick the interpreter with **Ctrl+Shift+P → "Python: Select Interpreter" → `.venv`**.

## 4. Dataset: get real results

The project ships with `generate_demo_data.py`, which creates **synthetic** URLs from templates. The app works immediately, and every page clearly labels the demo model. **Synthetic metrics are not real-world performance.**

For meaningful results, use the Kaggle **"Malicious URLs dataset"** (Manu Siddhartha):

1. Create a free account at <https://www.kaggle.com>.
2. Search for **"Malicious URLs dataset"** and download it. You'll get `malicious_phish.csv` (about 650,000 rows; columns `url`, `type` with values benign, phishing, malware and defacement).
3. Copy it to `URLGuard-AI\data\malicious_phish.csv`.
4. Retrain:
   ```powershell
   python train_model.py                 # 200,000-row stratified sample (about 2–5 min on a laptop)
   python train_model.py --all           # all rows (slower, needs about 4 GB RAM)
   ```
5. Restart the app, or click **Settings → Reload model**.

Any CSV with a URL column (`url`) and a label column (`type`, `label`, `class`, `result`…) works:

```powershell
python train_model.py --data data\my_dataset.csv
```

### How the training avoids common mistakes
| Problem | What `train_model.py` does |
|---|---|
| Missing or invalid rows | Drops blank, over-long (>2048) and control-character URLs, plus unknown labels |
| Duplicates | De-duplicates on the normalised URL **before** splitting, so no URL is in both train and test |
| Conflicting labels | Drops URLs that appear as both benign and malicious |
| Dataset artefact leak | In `malicious_phish.csv`, benign URLs rarely include `http://` and malicious ones often do. All URLs are normalised (scheme and `www.` removed) before features are computed, and HTTPS is shown to the user but never used by the model |
| Overfitting model choice | 70/15/15 split. The model is **selected on validation** and **reported on the untouched test set** |
| Vectoriser leakage | TF-IDF and scaler sit inside sklearn Pipelines, so they are fitted on training data only |

Models compared: **Logistic Regression** (29 URL features + TF-IDF character 3–5-grams), **Decision Tree** and **Random Forest** (URL features). The winner by validation F1 is saved.

## 5. Features at a glance

| Section | What it does |
|---|---|
| **Home** | Real stats from your saved scans, a 14-day chart, the detection mix, the current model card and awareness tips |
| **Check URL** | Verdict, 0–100 estimated risk score, risk band, reasons, safety actions, explainable-AI bars, rule findings, connection info, feature table, scan PDF, feedback buttons |
| **Batch Analysis** | CSV upload (≤2 MB, ≤5,000 rows, `url` column), a searchable and sortable table, a summary and a results CSV download (formula-injection safe) |
| **Threat Intelligence** | Google Safe Browsing lookup only if an API key is set **and** you consent. Otherwise it is clearly marked "unavailable" |
| **Model Performance** | Accuracy, precision, recall, F1, ROC AUC, comparison chart, confusion matrix, class distribution, dataset summary, feature influence, basic monitoring from your feedback |
| **Scan History** | Masked URLs (`?token=***`), search, filters, per-item and bulk delete |
| **Cybercrime Reporting** | Report form → review/edit → PDF, optional evidence, statuses *Draft → Ready to Submit → Submitted Externally — User Confirmed*, delete controls |
| **Dataset & Model Info** | Version, training date, dataset hash, pipeline, feature list, limitations |
| **Settings** | History consent, delete data, provider status, reload model, a table of what is stored |

### Explainable AI (real, per prediction)
* **Logistic Regression:** each feature's contribution = coefficient × scaled value. The top character n-grams are shown separately, and each feature is compared to its typical value in the training data.
* **Decision Tree / Random Forest:** decision-path contributions, i.e. how much each split changed the predicted probability, averaged over trees.
* "Reasons" only list features that actually pushed this URL's score up, plus rule-based findings. Nothing is invented.

### Indian brand look-alike rules
Flags hostnames that mention SBI, HDFC, ICICI, Axis, Kotak, PNB, Canara, Federal Bank, Paytm, PhonePe, Google Pay, BHIM/NPCI, IRCTC, UIDAI/Aadhaar, Income Tax, EPFO, India Post, Amazon, Flipkart, Airtel, Jio, KSEB and WhatsApp when the site is not on the brand's official-domain list. It also flags one-letter typos and swaps (`flipkrat.com`), digit look-alikes (`f1ipkart.com`) and punycode hosts. If the ML model says "legitimate" but a high-severity rule fires, the overall result is raised to **Suspicious**, and the page says why.

## 6. Security & privacy

| Requirement | Implementation |
|---|---|
| No URL fetching / SSRF | Only string parsing. A test blocks all sockets during a scan of `http://169.254.169.254/` |
| Input validation | Length, control characters, spaces, scheme allow-list (http/https only), hostname charset, port, IDN |
| HTML escaping | Jinja2 autoescape. PDF text escaped for ReportLab markup |
| CSRF | Flask-WTF `CSRFProtect` on every POST form |
| Sessions | HttpOnly, SameSite=Lax, optional Secure flag, signed with `SECRET_KEY` |
| Secrets | `.env` / environment variables. Otherwise a random key in `instance/.secret_key`. Nothing hard-coded |
| Headers | Strict CSP (no inline scripts), nosniff, X-Frame-Options DENY, no-referrer |
| Uploads | Extension allow-list, size limits, magic-byte check, `secure_filename`, random stored names, files kept outside `static/` |
| Access control | Every DB row has a per-browser owner ID; other browsers get 404 |
| Privacy | History only with consent; query values masked; reports saved only with consent; delete controls everywhere; logs contain hostname + verdict only |
| Localhost only | The server binds to `127.0.0.1` by default |

**Not production-hardened:** there is no user login. For deployment on a network, add authentication, HTTPS (`SESSION_COOKIE_SECURE=1`) and a production server (e.g. `waitress`).

## 7. Cybercrime reporting: important notes

* URLGuard **never submits** anything to any authority. You file the complaint yourself at:
  * Report a Suspect Website/URL: <https://cybercrime.gov.in/Webform/cyber_suspect.aspx>
  * National Cyber Crime Reporting Portal: <https://cybercrime.gov.in/>
* For financial fraud in India, **call 1930 immediately**.
* The `URLG-YYYYMMDD-XXXXXX` reference is a local tracking number, **not** a government complaint number.
* "Submitted Externally — User Confirmed" is set only when *you* tick the confirmation. You may record the acknowledgement number the portal gives you.

## 8. Testing

```powershell
python -m pytest            # run all 74 tests
python -m pytest -v         # verbose
python -m pytest tests\test_reports.py   # one file
```

The tests train a tiny synthetic model in a temp folder and cover feature extraction, URL validation, brand rules, model predictions and explanations, routes, CSRF, history privacy and isolation, batch validation and CSV injection, PDF generation, report status rules, evidence upload security (type, size, magic bytes, path traversal) and access control.

To evaluate a trained model, open **Model Performance** or read `models/metrics.json`.

## 9. Optional: enable Google Safe Browsing

1. Go to <https://console.cloud.google.com/>, create a project, enable the **Safe Browsing API** and create an **API key**.
2. Copy `.env.example` to `.env` and set `SAFE_BROWSING_API_KEY=your_key`.
3. Restart the app. A consent checkbox appears on **Check URL** and **Threat Intelligence**.

The URL is sent to Google only when the box is ticked. "Not found" does not mean safe.

## 10. Troubleshooting (Windows)

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Reinstall Python and tick "Add python.exe to PATH", or use `py` instead of `python` |
| `Activate.ps1 cannot be loaded… running scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, or use Command Prompt: `.venv\Scripts\activate.bat` |
| `pip install` builds from source / "Microsoft Visual C++ required" | Your Python is too new for some wheels. Install Python 3.12 or 3.13 and recreate `.venv` |
| `ModuleNotFoundError: No module named 'flask'` | The venv isn't active. Run `.venv\Scripts\Activate.ps1` (VS Code: select the `.venv` interpreter) |
| Banner says "No trained model found" | Run `python train_model.py`, then restart or click Settings → Reload model |
| "Could not load the model… different scikit-learn version" | Re-run `python train_model.py` in the current environment |
| `Address already in use` / port 5000 busy | `set URLGUARD_PORT=5050` (cmd) or `$env:URLGUARD_PORT=5050` (PowerShell), then `python app.py` |
| "Session expired" error on a form | Refresh the page (the CSRF token renews) and resubmit |
| Training runs out of memory | `python train_model.py --max-rows 100000` |
| `UnicodeDecodeError` in your CSV | Save it as "CSV UTF-8" in Excel |
| Charts don't appear | Hard-refresh (Ctrl+F5). Chart.js is bundled locally, so no internet is needed |

## 11. Limitations

* Only the URL text is analysed. Page content, redirects, certificates and domain age are not checked.
* Accuracy depends on the dataset, and attackers change tactics. Retrain with fresh data.
* The risk score is not a calibrated probability.
* There is no continuous monitoring or automatic retraining. Monitoring is a manual view of your feedback.
* PDF fonts are Latin-only. Malayalam or Hindi text in descriptions may not render in the PDF.
