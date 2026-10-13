# PhishGuard — deploy online

This package is prepared for Render. You do not need Python installed on your laptop to use the deployed website, but you do need a GitHub account and a Render account to publish it.

## Publish steps
1. Create/sign in to GitHub: https://github.com/
2. Create a new repository, for example `phishguard`.
3. Upload all files and folders from this package to the repository (not the ZIP itself).
4. Sign in to https://render.com/ and choose **New** → **Blueprint**.
5. Connect the GitHub repository and deploy. Render reads `render.yaml`.
6. After deployment, open the `https://...onrender.com` URL Render provides.

## Enable real threat-intelligence checks (optional)
1. Get a VirusTotal API key from https://www.virustotal.com/
2. In Render, open your service → Environment.
3. Add `VIRUSTOTAL_API_KEY` with your key as the value, save, and redeploy if requested.
4. Use the checkbox in PhishGuard to request a VirusTotal scan.

Important: standard VirusTotal URL submissions may be added to its shared dataset. Never submit private, internal, password-reset, or confidential URLs. API access/quotas depend on the plan.

## What it does
- Local URL-pattern heuristics always run.
- VirusTotal scanning runs only if you configure an API key and tick the checkbox.
- A low-risk result is not proof that a website is safe.
- Scan history is stored in temporary server storage and may reset when the hosted service restarts.
- This is an educational starter project, not a substitute for a professional security service.
