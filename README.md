# AI Deployment Risk Analyzer for Jenkins

A CI/CD portfolio project that inspects Git changes before deployment, flags risky patterns, creates JSON/Markdown reports, and can optionally enrich the review with an OpenAI-compatible chat-completions API. The rules-based analyzer works offline.

## Features
- Risk score and LOW/MEDIUM/HIGH classification
- Flags destructive SQL, dangerous shell commands, weakened authentication/TLS, credential-like assignments, and infrastructure/security changes
- JSON and Markdown reports for Jenkins artifacts
- Optional AI review; AI cannot downgrade a rules-based HIGH result
- Jenkins can block HIGH-risk changes by default pending manual review
- Unit tests and GitHub Actions validation

## Run locally (Python 3.10+)

    python -m unittest discover -s tests -v
    python -m risk_analyzer.analyzer --diff-file sample/example.diff --out-dir reports

The sample intentionally contains DROP TABLE, so the analyzer exits with code 2. That is expected.

## Optional AI
Set AI_API_KEY as a secret/environment variable. Optional settings: AI_BASE_URL, AI_MODEL, AI_TIMEOUT_SECONDS. Never commit API keys. Then add --use-ai to the command. Without a key, the analyzer runs offline.

## Jenkins setup
1. Create a Pipeline job, select Pipeline script from SCM.
2. SCM: Git; repository URL: this GitHub repository; branch */main; script path Jenkinsfile.
3. Optional Jenkins Secret text credential ID: ai-api-key.
4. Run the job. ALLOW_HIGH_RISK defaults to false; HIGH risk intentionally blocks the pipeline.

This is a demonstrator, not a security scanner or autonomous approval system. Heuristics may miss risks or flag harmless changes. Review findings and test in non-production first.
