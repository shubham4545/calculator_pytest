# GitHub Webhook Reconfiguration Guide

## 📋 Table of Contents
1. [Prerequisites](#prerequisites)
2. [Step 1: Start ngrok Tunnel](#step-1-start-ngrok-tunnel)
3. [Step 2: Get New Public URL](#step-2-get-new-public-url)
4. [Step 3: Update GitHub Webhook](#step-3-update-github-webhook)
5. [Step 4: Test Webhook](#step-4-test-webhook)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

✅ Jenkins running on `http://localhost:8080`
✅ ngrok installed ([download here](https://ngrok.com/download))
✅ GitHub repository access: https://github.com/shubham4545/calculator_pytest
✅ Admin rights on GitHub repo (to modify webhooks)

---

## Step 1: Start ngrok Tunnel

### Option A: Use the PowerShell Script (Recommended)

```powershell
# Navigate to project directory
cd "c:\Users\shubh\Desktop\Automation Testing"

# Run the auto-start script
.\start-ngrok-tunnel.ps1

# Script will:
# ✓ Check ngrok is installed
# ✓ Verify Jenkins is accessible
# ✓ Start tunnel on port 8080
# ✓ Display public URL
# ✓ Log everything to ngrok-logs/ directory
```

Output will look like:
```
================================
✓ NGROK TUNNEL ACTIVE
================================
Public URL: https://1234-56-789-abc.ngrok-free.app
Local URL: http://localhost:8080
ngrok Web UI: http://127.0.0.1:4040
Process ID: 12345
================================
```

### Option B: Manual Start

```powershell
# If ngrok not in PATH, find installation:
$ngrokPath = Get-ChildItem -Path "C:\Program Files", "$env:LOCALAPPDATA\Programs" -Filter ngrok.exe -Recurse | Select-Object -First 1

# Start tunnel
& $ngrokPath.FullName http 8080

# Or if in PATH:
ngrok http 8080
```

---

## Step 2: Get New Public URL

### From ngrok Web UI:

```
http://127.0.0.1:4040
```

Look for **Forwarding** section:
```
https://1234-56-789-abc.ngrok-free.app -> http://localhost:8080
```

### From PowerShell:

```powershell
# Query ngrok API
$tunnels = Invoke-WebRequest -Uri "http://127.0.0.1:4040/api/tunnels" -UseBasicParsing | ConvertFrom-Json
$tunnels.tunnels[0].public_url
```

### From Log File:

```powershell
# Check the saved URL file
Get-Content "c:\Users\shubh\Desktop\Automation Testing\ngrok-logs\ngrok-tunnel-url.txt"
```

**Copy the HTTPS URL** (example: `https://1234-56-789-abc.ngrok-free.app`)

---

## Step 3: Update GitHub Webhook

### Navigate to Repository Settings:

1. Go to: https://github.com/shubham4545/calculator_pytest
2. Click **Settings** tab (top right)
3. Left sidebar → **Webhooks**
4. Click existing webhook or **Add webhook**

### Update Webhook Configuration:

**Payload URL:**
```
https://YOUR-NGROK-URL/github-webhook/
```

Replace `YOUR-NGROK-URL` with your public URL, e.g.:
```
https://1234-56-789-abc.ngrok-free.app/github-webhook/
```

**Example (complete URL):**
```
https://1234-56-789-abc.ngrok-free.app/github-webhook/
```

### Other Settings (should already be configured):

| Setting | Value |
|---------|-------|
| Content type | `application/json` |
| Events | `Push events` ✓, `Pull requests` ✓ |
| Active | ✓ Checked |
| SSL verification | ✓ Enabled |

### Save Changes:

Click **Update webhook** button

---

## Step 4: Test Webhook

### Method 1: GitHub UI Test

1. On the Webhook page, scroll to **Recent Deliveries**
2. Click **Redeliver** on recent push event
3. Watch Jenkins for automatic build trigger

### Method 2: Manual Test Push

```bash
# Make a small code change
echo "# Test $(date)" >> README.md

# Commit and push
git add README.md
git commit -m "Test webhook trigger"
git push origin main
```

Then check:
- ✓ GitHub shows delivery in **Recent Deliveries**
- ✓ Jenkins shows new build in **Build History**
- ✓ ngrok logs show POST request

### Method 3: Check ngrok Logs

```powershell
# View recent ngrok activity
Get-Content "c:\Users\shubh\Desktop\Automation Testing\ngrok-logs\ngrok-*.log" -Tail 20
```

---

## Verification Checklist

```
✓ ngrok tunnel running (can access http://127.0.0.1:4040)
✓ Jenkins accessible on http://localhost:8080
✓ Public URL updated in GitHub webhook
✓ Webhook marked as "Active" in GitHub
✓ Recent delivery shows successful (200 OK) status
✓ Jenkins triggered automatic build on last push
```

---

## Troubleshooting

### Issue 1: Webhook Returns 403 Forbidden

**Cause:** Jenkins requires authentication

**Solution:**
1. Add Jenkins credentials to ngrok webhook
2. Or: Disable Jenkins authentication for webhook endpoint
3. Or: Use GitHub token in webhook URL

```
https://YOUR-NGROK-URL/github-webhook/?token=YOUR_TOKEN
```

### Issue 2: No Build Triggered After Push

**Check:**
```powershell
# 1. Verify ngrok is running
Invoke-WebRequest http://127.0.0.1:4040/api/tunnels

# 2. Check ngrok logs for incoming requests
Get-Content ngrok-logs\ngrok-*.log | Select-String "POST"

# 3. View Jenkins webhook logs
# In Jenkins UI: Manage Jenkins → System Log → Add logger for github.com.spectatorjenkins

# 4. Verify GitHub webhook URL is correct
# Settings → Webhooks → Check "Payload URL" field
```

### Issue 3: ngrok URL Expired

**Cause:** ngrok tunnel stopped; free tier generates new URL each restart

**Solution:**
1. Restart ngrok tunnel using script
2. Update GitHub webhook with new URL
3. Test with manual push

### Issue 4: Jenkins Not Accepting Webhook

**Check Jenkins Configuration:**
```
1. Manage Jenkins → Configure System
2. Search for "GitHub"
3. Verify GitHub API credentials (if needed)
4. Manage Jenkins → Manage Plugins
5. Verify "GitHub Integration" plugin is installed
```

### Issue 5: Permission Denied on PowerShell Script

**Fix:**
```powershell
# Allow script execution (one-time)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or run script with bypass:
powershell -ExecutionPolicy Bypass -File start-ngrok-tunnel.ps1
```

---

## Complete Workflow Example

```powershell
# 1. Start ngrok tunnel
cd "c:\Users\shubh\Desktop\Automation Testing"
.\start-ngrok-tunnel.ps1

# Output shows: https://1234-56-789-abc.ngrok-free.app

# 2. Update GitHub webhook (see Step 3 above)
# Use URL: https://1234-56-789-abc.ngrok-free.app/github-webhook/

# 3. Test push
git add .
git commit -m "Test webhook"
git push origin main

# 4. Watch Jenkins
# Browser: http://localhost:8080
# You should see a new build triggered automatically!

# 5. Keep ngrok running
# Leave the PowerShell window open while testing
```

---

## Monitoring Dashboard

### ngrok Web UI
```
http://127.0.0.1:4040
```
Shows:
- Active tunnels
- Request/Response history
- Traffic inspection

### Jenkins Dashboard
```
http://localhost:8080
```
Shows:
- Build history
- Console output
- Build logs

### GitHub Webhook Deliveries
```
https://github.com/shubham4545/calculator_pytest/settings/hooks
```
Shows:
- Request/Response headers
- Payload
- Delivery status

---

## Quick Reference: Commands

```powershell
# Start ngrok with logging
.\start-ngrok-tunnel.ps1

# Get current tunnel URL
(Invoke-WebRequest http://127.0.0.1:4040/api/tunnels -UseBasicParsing | ConvertFrom-Json).tunnels[0].public_url

# View logs
Get-Content ngrok-logs\ngrok-*.log -Tail 50

# Stop ngrok (Ctrl+C in ngrok window, or:)
Get-Process ngrok | Stop-Process -Force

# Test Jenkins
curl http://localhost:8080 -UseBasicParsing

# Test webhook manually
Invoke-WebRequest -Uri "http://localhost:8080/github-webhook/" -Method POST -Body '{"push":"test"}'
```

---

## Support

- **ngrok docs:** https://ngrok.com/docs
- **Jenkins GitHub Plugin:** https://plugins.jenkins.io/github/
- **GitHub Webhooks:** https://docs.github.com/en/developers/webhooks-and-events/webhooks

---

**Last Updated:** January 20, 2026
**Repository:** https://github.com/shubham4545/calculator_pytest
