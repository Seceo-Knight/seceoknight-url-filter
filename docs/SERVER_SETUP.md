# Server Setup Guide

Step-by-step guide to deploy the SecEoKnight unified server on Ubuntu 24.04.

## Requirements

- Ubuntu 24.04 LTS (fresh install recommended)
- Minimum 8 GB RAM, 4 CPU cores, 100 GB SSD
- Static LAN IP (e.g. 192.168.1.63)
- Internet access for package installation

---

## Step 1 — Update the System

```bash
sudo apt update && sudo apt upgrade -y
```

---

## Step 2 — Install Python 3

```bash
sudo apt install -y python3 python3-venv python3-dev python3-pip
python3 --version   # Ubuntu 24.04 ships Python 3.12.x — TensorFlow 2.16.1 supports up to 3.12
```

---

## Step 3 — Install Nginx

```bash
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```

---

## Step 4 — (Skipped — Git LFS not required)

The malware model files (`.keras`) and the training dataset (`.csv`) are committed to this repo
as regular Git objects, not Git LFS pointers. A plain `git clone` in Step 5 downloads their full
contents — no LFS install or `git lfs pull` needed.

---

## Step 5 — Clone the Repository

```bash
sudo mkdir -p /opt/seceoknight
sudo chown $USER:$USER /opt/seceoknight
cd /opt/seceoknight
git clone https://github.com/YOUR_GITHUB_USERNAME/seceoknight-url-filter.git .
```

After cloning you should see real files (not tiny pointer files) in `server/models/malware/`.

---

## Step 6 — Create Python Virtual Environment

```bash
cd /opt/seceoknight
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

> **Note:** TensorFlow installation may take 5–10 minutes.

---

## Step 7 — Train the Phishing Detection Model

The malware models (CNN, ViT, 1D-CNN-LSTM) are pre-trained and already in the repo.
The phishing model must be trained once on your server from the included dataset:

```bash
cd /opt/seceoknight
source venv/bin/activate
python3 scripts/train_phishing_model.py
```

This takes **5–15 minutes** depending on hardware and trains on 95,980 domain samples.
Outputs are automatically saved to `server/models/phishing/`:
- `bilstm_domain_model.h5`
- `tokenizer.pkl`

> You only need to run this once. The trained model files persist on disk.
> If you commit them back to GitHub (`git add server/models/phishing/ && git commit && git push`),
> future deployments can skip this step and just `git clone` the trained model directly.

---

## Step 8 — Set Your Server IP

Open `endpoint/agent.py` and `endpoint/to-server.py` and change:
```python
SERVER_IP = "192.168.1.63"   # ← change to your actual server IP
```

The server itself (`server/unified_server.py`) does not need any IP changes — it listens on all interfaces.

---

## Step 9 — Test the Server Manually

```bash
cd /opt/seceoknight/server
source /opt/seceoknight/venv/bin/activate
uvicorn unified_server:app --host 0.0.0.0 --port 5001
```

Open a browser and go to: `http://YOUR_SERVER_IP:5001/health`

You should see:
```json
{"status": "healthy", "ai": {"phishing_model": "loaded", "malware_models": {...}}}
```

Press `Ctrl+C` to stop.

---

## Step 10 — Install as systemd Service (auto-start)

```bash
# Copy service file
sudo cp /opt/seceoknight/systemd/seceoknight.service /etc/systemd/system/

# The shipped file runs the service as User=root (functional, but not least-privilege).
# Optional hardening — run as a dedicated non-root user instead:
#   sudo useradd -r -s /usr/sbin/nologin seceoknight
#   sudo chown -R seceoknight:seceoknight /opt/seceoknight
#   sudo nano /etc/systemd/system/seceoknight.service
#   # Change:  User=root   →   User=seceoknight

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable seceoknight
sudo systemctl start seceoknight

# Check status
sudo systemctl status seceoknight
```

You should see `Active: active (running)`.

---

## Step 11 — Configure Nginx

The nginx config is included in the repo — no manual pasting needed:

```bash
# Copy the config from the repo
sudo cp /opt/seceoknight/nginx/seceoknight.conf /etc/nginx/sites-available/seceoknight

# Enable it
sudo ln -s /etc/nginx/sites-available/seceoknight /etc/nginx/sites-enabled/

# Remove the default nginx site (optional but cleaner)
sudo rm -f /etc/nginx/sites-enabled/default

# Test config and reload
sudo nginx -t
sudo systemctl reload nginx
```

You should see: `nginx: configuration file /etc/nginx/nginx.conf test is successful`

After this, endpoints can connect to `http://192.168.1.63/blocklist` (port 80, no :5001 needed).

---

## Step 12 — Open Firewall Ports

```bash
sudo ufw allow 80/tcp    # Nginx (API + blocklist + logs)
sudo ufw allow 5001/tcp  # Direct FastAPI (optional, can close after Nginx is working)
sudo ufw enable
```

> Port 8082 (mitmproxy) does NOT need to be open on the server — mitmproxy runs on endpoint machines.

---

## Step 13 — Seed Default Blocklist Rules

Populate the blocklist with enterprise defaults covering social media, streaming, gambling, piracy, malware downloads, and crypto mining:

```bash
cd /opt/seceoknight
source venv/bin/activate
python3 scripts/add_default_blocklist.py
```

Endpoints pick up the new rules within 30 seconds automatically.

---

## Step 14 — Run Health Check

Verify all subsystems are operational:

```bash
cd /opt/seceoknight
bash scripts/health_check.sh
```

All items should show `[PASS]`. If anything fails, the script tells you exactly how to fix it.

---

## Step 15 — Verify Everything Works

```bash
# Check service is running
sudo systemctl status seceoknight

# Check logs
sudo journalctl -u seceoknight -f

# Test health endpoint
curl http://localhost:5001/health

# Test blocklist endpoint (should now have seeded rules)
curl http://localhost:5001/blocklist

# Test stats endpoint
curl http://localhost:5001/api/stats
```

---

## Useful Commands

```bash
# Restart server
sudo systemctl restart seceoknight

# View live logs
sudo journalctl -u seceoknight -f

# Check database
sqlite3 /opt/seceoknight/server/seceoknight.db ".tables"
sqlite3 /opt/seceoknight/server/seceoknight.db "SELECT COUNT(*) FROM events;"

# Update from GitHub
cd /opt/seceoknight
git pull
sudo systemctl restart seceoknight
```

---

## Server is Ready When

- `curl http://YOUR_IP/health` returns `{"status":"healthy"}`
- `curl http://YOUR_IP/blocklist` returns a response (even empty)
- `sudo systemctl status seceoknight` shows `active (running)`
