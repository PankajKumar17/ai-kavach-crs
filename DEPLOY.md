# Deployment Guide for AI Kavach Dashboard

## Deploying to Render (Free Tier)
We have added a `render.yaml` Blueprint configuration for 1-click deployment.
1. Create a Render account at [render.com](https://render.com).
2. Go to the Dashboard and click **New > Blueprint**.
3. Connect this GitHub repository.
4. Render will automatically detect the `render.yaml` file, build the Docker container using `Dockerfile.dashboard`, and deploy the web service on the free tier.

## Deploying to Vercel (Free Tier)
The app is configured for Serverless deployment on Vercel.
1. Create a Vercel account at [vercel.com](https://vercel.com).
2. Click **Add New > Project** and import this GitHub repository.
3. Vercel detects `vercel.json` / `api/index.py` (the FastAPI app is re-exported there) and deploys it as a Serverless Function.
4. Set an environment variable in the Vercel project settings:
   - `ENGINE_AUTH_TOKEN` — required for remote `/api/engine/start` calls. Without it, engine-start only works from localhost, which on Vercel means never.
5. Notes and limits:
   - `vercel.json` sets `maxDuration: 60`; the free Hobby plan caps functions at 10–60s depending on region — if you hit timeouts, use Render instead.
   - `includeFiles` bundles `dashboard/`, `engine/`, and the demo `runs/test_run/summary.json` into the function. Writes to `engine/target_app/vulnerable.py` and `runs/` are ephemeral on serverless filesystems — each invocation starts from the committed state, which is fine for the demo loop but means state does not persist across requests.

## Local Deployment
1. Build the image: `docker build -f Dockerfile.dashboard -t ai-kavach-dashboard .`
2. Run it: `docker run -p 8000:8000 ai-kavach-dashboard`
3. Check health: `curl http://localhost:8000/health`
