# Deploying the Backend Online (Always-Live)

## Before you start — rename the project folder
Your folder is named `CyberDefenseProject(final)`. The parentheses can break
some build systems and shell scripts on cloud platforms. Rename it to
something plain first, e.g. `CyberDefenseProject`.

## What changed to make this deployable
- `phishing_rf_model.joblib` was **168MB → 44MB** (same model, just
  re-compressed with `joblib.dump(..., compress=7)`). This matters because
  GitHub hard-blocks any file over 100MB — without this fix you'd be forced
  into Git LFS. All three models together are now ~53MB, comfortably under
  every free-tier limit.
- `app.py` now binds to `0.0.0.0` and reads the `PORT` environment variable
  when one is set (cloud platforms inject this automatically), while still
  defaulting to `127.0.0.1:5000` for local development — no behavior change
  when you run it on your own machine.
- Added `requirements-deploy.txt` (installs the small CPU-only PyTorch
  build instead of the ~2GB CUDA build `pip install torch` grabs by
  default) and a `Procfile` (tells the host to run the app with
  `gunicorn`, a production server, instead of Flask's dev server).

## Recommended host: Render.com
Free to start, straightforward, handles Python natively.

### Steps
1. **Push your `src/` folder to a GitHub repo** (public or private, either
   works with Render). Make sure `phishing_rf_model.joblib`,
   `malware_rf_model.joblib`, `malware_filenames.csv`,
   `password_rnn_full.pt`, and `whitelistDomain.txt` are all committed — do
   **not** put model files in `.gitignore`.
2. Go to [render.com](https://render.com) → sign up → **New → Web Service**.
3. Connect your GitHub repo.
4. Configure:
   - **Root Directory**: `src`
   - **Build Command**: `pip install -r requirements-deploy.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --timeout 120 --workers 1 --threads 4`
   - **Instance Type**: Free (or Starter, $7/mo, if you want no cold starts)
5. Click **Create Web Service**. First build takes ~5–10 minutes (installing
   torch + scikit-learn). Render gives you a URL like:
   ```
   https://cyber-defense-toolbox.onrender.com
   ```
6. Test it directly in a browser:
   ```
   https://cyber-defense-toolbox.onrender.com/api/dashboard
   ```
   You should get back JSON, not an error page.

### The free-tier catch
Render's **free** plan spins the service down after ~15 minutes of no
traffic. The next request "wakes" it up but takes 30–60 seconds — annoying
mid-demo. Two ways to avoid this:
- **Cheap fix (free):** use [UptimeRobot](https://uptimerobot.com) (free
  account) to ping `/api/dashboard` every 5 minutes, so it never goes idle.
- **Real fix ($7/mo):** upgrade to Render's Starter plan — no sleeping,
  genuinely always-on.

## Once you have your URL — update the extension
Replace the local address in **three files** with your real Render URL:

| File | Line to change |
|---|---|
| `extension/background.js` | `const API_BASE = "http://127.0.0.1:5000";` |
| `extension/popup.js` | `const API_BASE = "http://127.0.0.1:5000";` |
| `extension/content.js` | `const CDT_API_BASE = "http://127.0.0.1:5000";` |

Change each to:
```js
const API_BASE = "https://cyber-defense-toolbox.onrender.com";
```

Then in `extension/manifest.json`, update `host_permissions`:
```json
"host_permissions": [
  "https://cyber-defense-toolbox.onrender.com/*",
  "<all_urls>"
]
```

Reload the unpacked extension in `chrome://extensions` afterward.

## ⚠️ Important trade-off: password privacy
Your report's non-functional security requirement states passwords should
never be transmitted to external systems. Right now that's true because
everything runs on `127.0.0.1` (your own machine talking to itself).

**Once you move the backend online, the password you type on any website
gets sent over the internet to your Render server** to be scored. It's not
stored anywhere and Render/you don't log it, but it does leave your device,
which is a real change from what your report currently claims.

Two honest options:
1. **Disclose it** — add a line to your report's limitations section noting
   that in the hosted deployment, password strength scoring requires a
   network round-trip to the backend (same as e.g. every password-strength
   API-based tool does), and that no password is stored or logged server-side.
2. **Hybrid deployment (recommended)** — keep phishing + malware checks
   pointed at the cloud URL (nothing sensitive in a URL or filename), but
   leave `content.js`'s `CDT_API_BASE` pointing at `127.0.0.1:5000` so
   password scoring only ever happens locally when you're testing on your
   own machine, and simply document that live password-checking requires
   the local backend to be running. This keeps your original security
   claim fully true.

I'd go with option 2 unless you specifically need password-checking to work
in a from-anywhere demo.
