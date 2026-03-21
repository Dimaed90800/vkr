# Adaptive REST API Pentest Platform Based on Autonomous Attacking Agents

## 📌 Abstract

This project presents the design and implementation of an adaptive system for automated vulnerability detection in REST APIs using autonomous attacking agents.

The system combines:
- multi-agent hypothesis generation
- strategy arbitration
- dynamic execution of attack scenarios
- result-driven adaptation

The implementation is developed as part of a bachelor's thesis and focuses on improving automation in API security testing.

## 🎯 Research Objectives

- Automated penetration testing for REST APIs
- Multi-agent hypothesis generation
- Comparison of decision-making strategies:
  - rule-based
  - LLM-based (Dify)
- Detection of:
  - BOLA
  - BOPLA / Excessive Data Exposure
- Experimental evaluation framework

## 🏗️ Architecture

Components:
- FastAPI backend
- PostgreSQL
- OWASP ZAP
- Dify (LLM)
- Target: OWASP crAPI

## 🔁 Workflow

hypothesis → judge → execution → observation → analysis → findings

## 🧪 Experiment Example

curl -X POST http://localhost:8000/experiments/run \
  -H "Content-Type: application/json" \
  -d '{
    "target_name": "crapi",
    "target_url": "http://host.docker.internal:8888",
    "judge_mode": "rule_based",
    "max_rounds": 5
  }'

## 📊 Metrics

- observations
- hypotheses
- findings
- BOLA findings

## ⚔️ Vulnerabilities

### BOLA
Unauthorized object access

### BOPLA
Excessive data exposure

## 🚀 Run

docker compose up -d

## 📁 Structure

app/
 ├── routers/
 ├── services/
 ├── models.py
 ├── db.py

## ⚠️ Limitations

- heuristic detection
- no RL yet

## 🔮 Future Work

- RL agents
- n8n integration
- better reporting

## 🧾 Thesis

Adaptive system for vulnerability detection in REST APIs using learning attacking agents

## 👨‍💻 Author

Student: Your Name  
Year: 2025–2026
