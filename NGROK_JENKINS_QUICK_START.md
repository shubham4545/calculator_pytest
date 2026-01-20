# 🔧 Jenkins + ngrok + GitHub Webhook Setup Summary

## Current Status

| Component | Status | Details |
|-----------|--------|---------|
| **Jenkins** | ✅ Running | Port 8080, requires authentication (403) |
| **ngrok** | ❌ Not installed | Need to install or add to PATH |
| **GitHub Repo** | ✅ Ready | https://github.com/shubham4545/calculator_pytest |
| **Webhook** | ⚠️ Expired URL | Previous ngrok URL no longer active |

---

## 🚀 Quick Start (5 Minutes)

### 1️⃣ Install/Setup ngrok

```powershell
# Option A: Using Chocolatey (easiest)
choco install ngrok

# Option B: Manual download
# Visit: https://ngrok.com/download
# Extract to: C:\Program Files\ngrok or %LOCALAPPDATA%\Programs\ngrok

# Option C: Add to PATH if already installed
$env:Path += ";C:\path\to\ngrok"
```

### 2️⃣ Start ngrok Tunnel

```powershell
cd "c:\Users\shubh\Desktop\Automation Testing"
.\start-ngrok-tunnel.ps1
```

**Output:**
```
Public URL: https://1234-56-789-abc.ngrok-free.app
Local URL: http://localhost:8080
ngrok Web UI: http://127.0.0.1:4040
```

### 3️⃣ Update GitHub Webhook

1. Go to: https://github.com/shubham4545/calculator_pytest/settings/hooks
2. Click existing webhook
3. Update **Payload URL** to: `https://YOUR-NGROK-URL/github-webhook/`
4. Replace `YOUR-NGROK-URL` with your public URL from Step 2
5. Click **Update webhook**

### 4️⃣ Test It

```bash
git add .
git commit -m "Test webhook"
git push origin main
```

Check Jenkins: http://localhost:8080 (should show new build!)

---

## 📁 New Files Added

### 1. `start-ngrok-tunnel.ps1`
**Purpose:** Automated ngrok tunnel management

**Features:**
- ✓ Auto-detects ngrok installation
- ✓ Verifies Jenkins is accessible
- ✓ Starts tunnel with comprehensive logging
- ✓ Saves public URL to file
- ✓ Monitors tunnel health (30-sec intervals)
- ✓ Handles errors gracefully

**Usage:**
```powershell
.\start-ngrok-tunnel.ps1              # Default: port 8080
.\start-ngrok-tunnel.ps1 -Port 3000   # Custom port
.\start-ngrok-tunnel.ps1 -ShowURL     # Print URL to console
```

**Logs:** `ngrok-logs/ngrok-YYYY-MM-DD_HH-mm-ss.log`

**Output File:** `ngrok-logs/ngrok-tunnel-url.txt`

### 2. `GITHUB_WEBHOOK_SETUP.md`
**Purpose:** Complete webhook configuration guide

**Sections:**
1. Prerequisites checklist
2. Step-by-step ngrok startup
3. GitHub webhook URL configuration
4. Testing procedures (3 methods)
5. Troubleshooting (5+ common issues)
6. Quick reference commands
7. Complete workflow examples

---

## 🔍 Verification Commands

### Check Jenkins

```powershell
# Via HTTP request
curl http://localhost:8080 -UseBasicParsing

# Via PowerShell
Invoke-WebRequest http://localhost:8080 -UseBasicParsing
```

**Expected:** HTTP 403 (auth required) = Jenkins running ✓

### Check ngrok Tunnel

```powershell
# Get tunnel info
Invoke-WebRequest http://127.0.0.1:4040/api/tunnels -UseBasicParsing | ConvertFrom-Json

# Get public URL
$url = (Invoke-WebRequest http://127.0.0.1:4040/api/tunnels -UseBasicParsing | ConvertFrom-Json).tunnels[0].public_url
Write-Host "Tunnel URL: $url"
```

### Check GitHub Webhook

```bash
# Go to settings page and check "Recent Deliveries"
# Or via GitHub API:
curl -H "Authorization: token YOUR_GITHUB_TOKEN" \
  https://api.github.com/repos/shubham4545/calculator_pytest/hooks

# Look for: "url": "https://YOUR-NGROK-URL/github-webhook/"
```

---

## 🛠️ Troubleshooting

### Problem: "ngrok not found"

**Solution:**
```powershell
# Find ngrok installation
Get-ChildItem -Path "C:\Program Files", "$env:LOCALAPPDATA\Programs" -Filter ngrok.exe -Recurse

# Add to PATH permanently:
$env:Path += ";C:\path\to\ngrok"

# Or use full path in script:
"C:\Program Files\ngrok\ngrok.exe" http 8080
```

### Problem: Jenkins shows 403 Forbidden

**This is normal!** Means Jenkins is running but needs authentication.

**Options:**
1. Access via browser: http://localhost:8080 (will prompt for login)
2. Configure GitHub token in webhook URL
3. Temporarily disable Jenkins auth for testing

### Problem: Webhook not triggering builds

**Check:**
```powershell
# 1. View ngrok logs for incoming requests
Get-Content ngrok-logs\ngrok-*.log | Select-String "POST"

# 2. Check GitHub webhook recent deliveries
# Settings → Webhooks → Recent Deliveries

# 3. Verify Jenkins GitHub plugin installed
# Manage Jenkins → Manage Plugins → search "github"

# 4. Check Jenkins system log
# Manage Jenkins → System Log
```

### Problem: ngrok URL keeps changing

**This is expected!** Free ngrok tier generates new URL each time tunnel starts.

**Workflow:**
1. Start ngrok
2. Get new public URL
3. Update GitHub webhook
4. Test
5. Repeat when tunnel restarts

---

## 📊 Architecture Diagram

```
                GitHub
                  ↑
                  │
            (webhook POST)
                  │
    ┌─────────────┴─────────────┐
    │                           │
    │                    ngrok Tunnel
    │                  (https://xxx.ngrok.io)
    │                           │
    │                           ↓
    │                    localhost:8080
    │                      (Jenkins)
    │                           │
    └─────────────┬─────────────┘
                  │
            (trigger build)
                  │
            git clone/test/report
                  │
            Results uploaded
                  │
              Local repo
         (test_calculator.py)
```

---

## 📝 GitHub Webhook Event Flow

```
1. User pushes to GitHub (main branch)
           ↓
2. GitHub sends POST to webhook URL
           ↓
3. ngrok tunnel forwards to Jenkins
           ↓
4. Jenkins receives webhook at /github-webhook/
           ↓
5. Jenkins trigger detects new commits
           ↓
6. Jenkins starts build job: Calculator_pytest
           ↓
7. Job checks out latest code
           ↓
8. Job runs: pytest -n auto (parallel execution)
           ↓
9. Job generates reports (JUnit, Coverage)
           ↓
10. Jenkins archives artifacts
           ↓
11. Build complete!
```

---

## 🎯 Next Steps

1. ✅ Install ngrok (if needed)
2. ✅ Run `.\start-ngrok-tunnel.ps1`
3. ✅ Copy public URL
4. ✅ Update GitHub webhook (see GITHUB_WEBHOOK_SETUP.md)
5. ✅ Test with `git push`
6. ✅ Watch Jenkins build automatically!

---

## 📚 Reference Files

| File | Purpose |
|------|---------|
| `start-ngrok-tunnel.ps1` | Auto-start ngrok tunnel with logging |
| `GITHUB_WEBHOOK_SETUP.md` | Detailed webhook configuration guide |
| `Jenkinsfile` | Jenkins pipeline configuration (already setup) |
| `.github/workflows/main.yml` | GitHub Actions (alternative to Jenkins) |
| `calculator.py` | Calculator implementation |
| `test_calculator.py` | 155 parameterized & fixture-based tests |

---

## 💡 Pro Tips

1. **Keep ngrok running:** Leave the PowerShell window open while testing
2. **Monitor in real-time:** Open http://127.0.0.1:4040 to see requests
3. **Save URL:** Script automatically saves to `ngrok-logs/ngrok-tunnel-url.txt`
4. **Fast testing:** Use GitHub UI "Redeliver" instead of pushing each time
5. **Automation:** Add script to Windows Task Scheduler for auto-start on boot

---

**Created:** January 20, 2026  
**Repository:** https://github.com/shubham4545/calculator_pytest  
**Status:** ✅ Ready to Deploy
