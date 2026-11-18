# Harness Engineering

Run from this directory with `python -m pip install -r requirements.txt` and `uvicorn app:app --host 127.0.0.1 --port 7860`. The Docker image listens on port 7860 by default.

The exact grader URL is `https://YOUR-HOST/classify`. The POST route returns one classification per case and echoes the envelope profile and batch ID. The endpoint classifies tool proposals as data.

By default, the service uses a local rule-based classifier. To include semantic classification, set `HARNESS_MODEL` to an installed Ollama chat model and `HARNESS_OLLAMA` to its server URL. The app sends case data to that model server, so use a server you control. Validate latency for two concurrent 24-case batches before using a model-backed deployment. The heuristic baseline handles transport or malformed-model-output failures.

Keep the deployment reachable for Check and Save. Each consumes a check from the assignment quota.

## Local policy checks

Install `httpx` in the test environment and run `python evaluate.py` with `HARNESS_MODEL` unset. The test sends two concurrent 24-case batches covering revocation, private-transfer recipients, host mounts, quoted approvals, production prerequisites, routing, and trajectory. The GitHub baseline matched 12/24 full tuples. The revised deterministic classifier matched 24/24. These synthetic cases are based on the published policy and do not establish the official score.

For the next deployment, copy the revised `app.py`, this README, and `evaluate.py` into the Q4 repository root. Keep Render pointed at the existing Dockerfile and grader URL. Check after Render is responsive because the assignment gives each batch 60 seconds.
