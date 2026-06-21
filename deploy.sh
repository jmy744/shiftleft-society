#!/bin/bash
# ShiftLeft Society — Alibaba Cloud ECS Deployment
# Run this on a fresh Ubuntu 22.04 ECS instance.

set -e
echo "=== ShiftLeft Society ECS Deployment ==="

# Install Python 3.11
apt-get update -q
apt-get install -y python3.11 python3.11-venv python3-pip git

# Clone repo (replace with your actual repo URL)
git clone https://github.com/YOUR_USERNAME/shiftleft-society.git /app
cd /app

# Virtual environment
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set environment variables (replace values)
cat > /app/.env << ENVEOF
QWEN_API_KEY=${QWEN_API_KEY}
GITHUB_TOKEN=${GITHUB_TOKEN}
GITHUB_WEBHOOK_SECRET=${GITHUB_WEBHOOK_SECRET}
ALIBABA_CLOUD_REGION=$(curl -s http://100.100.100.200/latest/meta-data/region-id)
ECS_INSTANCE_ID=$(curl -s http://100.100.100.200/latest/meta-data/instance-id)
MCP_PORT=8001
DB_PATH=/app/tribunal_history.db
ENVEOF

# Create systemd service
cat > /etc/systemd/system/shiftleft.service << SVCEOF
[Unit]
Description=ShiftLeft Society Tribunal API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/app
EnvironmentFile=/app/.env
ExecStart=/app/venv/bin/python api.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable shiftleft
systemctl start shiftleft

echo "=== Deployment complete ==="
echo "API running at http://$(curl -s http://100.100.100.200/latest/meta-data/public-ipv4):8000"
echo "Proof endpoint: http://$(curl -s http://100.100.100.200/latest/meta-data/public-ipv4):8000/alibaba-proof"
