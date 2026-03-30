# Deploy to Render.com — Step-by-Step Guide

## What you need
- A [Render.com](https://render.com) account (free tier works)
- Your project pushed to GitHub / GitLab

---

## Step 1 — Push to GitHub

```bash
cd /home/cris/crimedetect
git init
git add .
git commit -m "Initial production-ready AI Crime Detection Engine"
# Create a repo on GitHub, then:
git remote add origin https://github.com/YOUR_USERNAME/crimedetect.git
git push -u origin main
```

> **Important:** The `.gitignore` already excludes `Datasets/` and `models/*.joblib`.
> The datasets aren't needed once training finishes — models are stored on Render's persistent disk.

---

## Step 2 — Create the Web Service on Render

1. Go to [dashboard.render.com](https://dashboard.render.com) → **New → Web Service**
2. Connect your GitHub repo
3. Render will auto-detect `render.yaml` — click **Apply**

Or configure manually:

| Setting | Value |
|---|---|
| **Runtime** | Python 3 |
| **Build Command** | `chmod +x build.sh && ./build.sh` |
| **Start Command** | `uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1` |
| **Disk** | Mount at `/opt/render/project/src/models`, 1 GB |

---

## Step 3 — Set Environment Variables

In the Render dashboard → **Environment** tab, add:

| Key | Value |
|---|---|
| `API_KEY` | A strong random secret (e.g. `openssl rand -hex 32`) |
| `ALLOWED_ORIGINS` | Your Laravel app URL e.g. `https://yourlaravel.app` |
| `MODELS_DIR` | `models` |

---

## Step 4 — First Deploy (Training happens automatically)

- First deploy runs `build.sh`, which detects no models and runs `python train.py`
- Training takes **10–20 minutes** on Render's free CPU
- Models are saved to the persistent disk at `/opt/render/project/src/models`
- All future deploys skip training (models already exist on disk)

---

## Step 5 — Copy your API Key

After deploy, go to **Environment → API_KEY** and copy the value. You'll need it in Laravel.

Your base URL will be: `https://crimedetect-api.onrender.com`

---

## Step 6 — Configure Laravel

Add to your Laravel `.env`:

```
CRIME_DETECT_URL=https://crimedetect-api.onrender.com
CRIME_DETECT_KEY=your-api-key-here
CRIME_DETECT_TIMEOUT=15
```

Add to `config/services.php`:

```php
'crime_detection' => [
    'url'     => env('CRIME_DETECT_URL', 'http://localhost:8000'),
    'api_key' => env('CRIME_DETECT_KEY'),
    'timeout' => env('CRIME_DETECT_TIMEOUT', 15),
],
```

Copy the files from `laravel-integration/` into your Laravel project:
- `CrimeDetectionService.php` → `app/Services/`
- `CrimeDetectionController.php` → `app/Http/Controllers/`

Register the service in `routes/api.php`:

```php
Route::post('/scan/url',           [CrimeDetectionController::class, 'scanUrl']);
Route::post('/scan/network',       [CrimeDetectionController::class, 'scanNetwork']);
Route::post('/scan/cyberbullying', [CrimeDetectionController::class, 'scanCyberbullying']);
Route::post('/scan/batch',         [CrimeDetectionController::class, 'scanBatch']);
Route::get ('/scan/health',        [CrimeDetectionController::class, 'health']);
```

---

## Step 7 — Test the live API

```bash
# Health check (no auth required)
curl https://crimedetect-api.onrender.com/health

# Phishing URL scan
curl -X POST https://crimedetect-api.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{"type":"url","data":"http://free-prize-win.click/claim?user=admin"}'

# Network intrusion scan
curl -X POST https://crimedetect-api.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{"type":"network","data":{"dur":0.0,"spkts":500,"sbytes":50000,"dbytes":0,"rate":9999,"sttl":128,"dttl":0,"sload":99999,"dload":0,"sloss":100,"dloss":0,"sinpkt":0,"dinpkt":0,"sjit":0,"djit":0,"swin":0,"dwin":0,"dpkts":0,"ct_srv_src":50,"ct_state_ttl":0,"ct_dst_ltm":50,"ct_src_ltm":50,"ct_srv_dst":50}}'

# Cyberbullying scan
curl -X POST https://crimedetect-api.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{"type":"cyberbullying","data":{"total_messages":50,"aggressive_count":40,"intent_to_harm":1.0,"peerness":0.2}}'
```

---

## ⚠️ Free Tier Notes

- Free Render instances **spin down after 15 minutes of inactivity** (cold start ~30s)
- Upgrade to a paid plan ($7/mo) for always-on service
- The persistent disk **survives redeploys** — models are only trained once
