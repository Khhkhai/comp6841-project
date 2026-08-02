# Indirect Prompt Injection Against AI Agents

A demonstration of indirect prompt injection against a tool-using AI agent, and a
pattern-based **Injection Filter** that inspects document content before it reaches the
agent.

Everything runs **locally**. The `send_email` tool is **simulated** — it appends to an
in-memory outbox and prints the message. No real emails are sent and no external systems
are contacted.

## Repository structure

| File | Purpose |
|---|---|
| `agent.py` | Builds the ReAct agent (LangChain + LangGraph, Llama 3.1 8B via Ollama) |
| `tools.py` | The simulated `send_email` tool and the in-memory outbox |
| `injection_filter.py` | The pattern-based content-inspection filter (`inspect()`) |
| `baseline_ver.py` | Runs the **vulnerable** agent — no filter |
| `defended_ver.py` | Runs the **defended** agent — Injection Filter enabled |
| `requirements.txt` | Python dependencies |
| `docs/` | The clean control document and six attack documents |
| `results.json` | Output of the last vulnerable run |
| `results_defended.json` | Output of the last defended run |

The `docs/` folder contains:
`report_clean.txt` (clean control), `report_footer.txt`, `report_addresswap.txt`,
`report_hidden.txt`, `report_authority_override.txt`, `report_redacted_credential.txt`,
`report_incident_urgency.txt` (six attacks).

## Prerequisites

1. **Python 3.12.13**

2. **Ollama** installed and running, with the model pulled:
```bash
   # Install Ollama from https://ollama.com/download
   ollama pull llama3.1:8b
```
   Ollama must be running (the desktop app, or `ollama serve`) before you run the scripts.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

No API keys are required — the model runs locally through Ollama.

## Running the experiments

Each script runs the **full set** — the clean control plus all six attack documents — in
one go, prints a per-document verdict, and writes a JSON summary.

### 1. Vulnerable agent (no filter)

```bash
python baseline_ver.py
```

Runs every document straight to the agent with no defence. Writes `results.json`.
Expected: the clean control emails only `analyst@company.com`; all six attacks influence
the `send_email` recipient (attack success 6/6).

### 2. Defended agent (Injection Filter enabled)

```bash
python defended_ver.py
```

Runs the identical agent and documents, but each document is inspected first. A blocked
document ends the workflow before the agent runs. Writes `results_defended.json`.
Expected: all six attacks blocked (detection 6/6, attack success 0/6); clean control
allowed through to `analyst@company.com`.
