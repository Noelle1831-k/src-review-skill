# SRC Review Skill

Automated Bytedance SRC vulnerability review pipeline for Claude Code.

## Features

- **Phase A**: Auto-filter volcano engine + pending review vulns, with smart dedup (skip already-reproduced/excluded)
- **Phase B**: Incremental detail fetching + attachment download + PDF-to-MD conversion
- **Phase C**: Three-stage analysis pipeline
  - C1: Filter vulns requiring unguessable parameters
  - C2: Filter vulns requiring heavy UI interaction
  - C3: Parallel reproduction agents with read-only constraints

## Installation

```bash
git clone <this-repo>
cd src-review
./install.sh
```

## Prerequisites

1. **Chrome** with remote debugging enabled:
   ```bash
   # macOS
   /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222
   ```

2. **Login** to these sites in Chrome:
   - https://src.bytedance.net (SRC management platform)
   - https://console.volcengine.com (Volcano Engine console)

3. **Python 3** with dependencies:
   ```bash
   pip3 install websocket-client PyMuPDF
   ```

## Usage

In Claude Code, trigger with:
```
SRC审核清单
```

Or manually run phases:
```bash
# Phase A: List collection
python3 /tmp/src_review_v4.py

# Phase B: Detail fetching
python3 /tmp/src_detail_batch.py

# Phase C: Analysis & reproduction (via Claude Code Workflow)
# Triggered automatically when Phase B finds new vulnerabilities
```

## File Structure

| File | Purpose |
|------|---------|
| `SKILL.md` | Skill definition for Claude Code |
| `scripts/phase-a.py` | SRC list collection via CDP |
| `scripts/phase-b.py` | Detail fetching + cache management |
| `scripts/phase-c-workflow.js` | Analysis & reproduction workflow |
| `install.sh` | One-click installer |

## State Files (in /tmp)

| File | Purpose |
|------|---------|
| `src_ids.json` | Current pending review IDs |
| `src_details.json` | Vuln detail page content |
| `src_cache.json` | Fetch cache with `reproduced` flags |
| `src_excluded.json` | Filtered-out vulns (hard_params / click_heavy) |
| `src_attachments/` | Downloaded attachments |
| `volc_cookies.txt` | Volcano Engine console cookies |
| `volc_csrf.txt` | CSRF token |

## Operation Constraints

During Phase C reproduction:
- ✅ Read operations (GET/LIST/DESCRIBE/SELECT)
- ✅ Non-destructive writes (test data, harmless markers)
- ✅ Minimal verification of others' data (no config overwrites)
- ✅ Verification-only RCE/escape/priv-esc (whoami/id/hostname, stop after proof)
- ❌ Delete operations (DELETE/DROP/TRUNCATE)
- ❌ Overwriting others' configs or core data
- ❌ Further exploitation after verification
