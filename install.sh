#!/bin/bash
# SRC Review Skill Installer
set -e

SKILL_DIR="${HOME}/.claude/skills/src-review"
SCRIPTS_DIR="/tmp"

echo "Installing SRC Review Skill..."

# Clean previous installation
rm -rf "$SKILL_DIR"
mkdir -p "$SKILL_DIR"

# Copy skill definition
cp "$(dirname "$0")/SKILL.md" "$SKILL_DIR/"
cp "$(dirname "$0")/scripts/phase-c-workflow.js" "$SKILL_DIR/"

# Copy Phase A and B scripts to /tmp
cp "$(dirname "$0")/scripts/phase-a.py" "$SCRIPTS_DIR/src_review_v4.py"
cp "$(dirname "$0")/scripts/phase-b.py" "$SCRIPTS_DIR/src_detail_batch.py"

# Install Python dependencies
pip3 install websocket-client PyMuPDF 2>/dev/null || echo "Warning: pip3 install failed, please install manually: pip3 install websocket-client PyMuPDF"

echo ""
echo "SRC Review Skill installed!"
echo "  Skill: $SKILL_DIR"
echo "  Scripts: $SCRIPTS_DIR/src_review_v4.py, src_detail_batch.py"
echo ""
echo "Prerequisites:"
echo "  1. Chrome with remote debugging enabled: --remote-debugging-port=9222"
echo "  2. Login to https://src.bytedance.net in Chrome"
echo "  3. Login to https://console.volcengine.com in Chrome"
