# Deployment Guide for AI Kavach Dashboard

## Deploying to Render (Free Tier)
We have added a `render.yaml` Blueprint configuration for 1-click deployment.
1. Create a Render account at [render.com](https://render.com).
2. Go to the Dashboard and click **New > Blueprint**.
3. Connect this GitHub repository.
4. Render will automatically detect the `render.yaml` file, build the Docker container using `Dockerfile.dashboard`, and deploy the web service on the free tier.

## Deploying to Vercel (Free Tier)
We have configured the app for Serverless deployment on Vercel.
1. Create a Vercel account at [vercel.com](https://vercel.com).
2. Click **Add New > Project** and import this GitHub repository.
3. Vercel will automatically detect the `vercel.json` and `api/index.py` files.
4. It will install dependencies from `requirements.txt` and deploy the FastAPI backend as Serverless Functions, while serving the dashboard statically.
5. No extra configuration is needed!

## Local Deployment
1. Build the image: `docker build -f Dockerfile.dashboard -t ai-kavach-dashboard .`
2. Run it: `docker run -p 8000:8000 ai-kavach-dashboard`
3. Check health: `curl http://localhost:8000/health`
