# DevSecMLOps — Student Experiments

Two hands-on experiments combining machine learning, MLOps practices, and security.

## Experiment 1 — Secure Email Threat Detection Using DevSecMLOps
- **Application Area/Domain:** DevSecMLOps, Email Security, Cybersecurity
- **Dataset Name:** SpamAssassin Public Corpus (optional prepared CSV); default demo uses a small built-in synthetic sample, not the full corpus.
- **Model Parameters:** TF-IDF (1–2 grams, max_features=5000) | Logistic Regression (max_iter=1000, class_weight=balanced, random_state=42).
- **Run:** `python Experiment1/experiment1.py`
- **Custom data:** `python Experiment1/experiment1.py --data path/to/emails.csv --output results.json`
- CSV columns: `text` and `label`; `message`/`body` and `category`/`class` are also accepted. Labels: `ham` or `spam`.

The built-in sample demonstrates the workflow only. Use a properly prepared corpus for meaningful performance claims.

## Experiment 2 — ML Model Security Vulnerability Scanning and Remediation
- **Application Area/Domain:** Machine Learning and MLOps / Application Security
- **Dataset Name:** N/A — synthetic vulnerable and secure Python code samples.
- **Model Parameters:** Rule-based static checks for unsafe pickle loading (B301), shell execution risk (B602), MD5 (B324), and hard-coded secrets (B105).
- **Run:** `python Experiment2/experiment2.py`
- **Scan a project:** `python Experiment2/experiment2.py --source-dir path/to/python/project --output scan_report.json`
- **Optional Bandit:** `pip install bandit`, then add `--run-bandit` to the command above.

The built-in scanner is educational and pattern-based, not a substitute for Bandit or security review. It never executes vulnerable samples.

## Setup
Python 3.10+ recommended.
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python Experiment1/experiment1.py
python Experiment2/experiment2.py
```
Each experiment folder contains its Python implementation and HTML report.
