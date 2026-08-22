# Operations & Deployment Runbook

## Local Development
```bash
make setup
make data
make train
make dev
```

## Docker Deployment
```bash
docker compose build
docker compose up -d
curl http://localhost:8000/health
```

## Optional Cloud Adapters
- **Vertex AI**: Set `GCP_PROJECT_ID` and `GOOGLE_APPLICATION_CREDENTIALS`.
- **AWS Bedrock**: Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
