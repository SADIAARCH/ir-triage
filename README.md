# Real-Time Network Forensics & Incident Triage Agent

Decider 2B (fast policy triage, #policy) -> threshold -> Amazon Bedrock (deep analysis).

    pip install -r requirements.txt
    cp .env.example .env
    strands-decider serve StrandsAgents/strands-decider-2B-hobson-v19 --port 8000   # terminal 1
    python -m triage.decider_client      # verify raw response shape
    python -m triage.pipeline 400        # CLI smoke test
    streamlit run app.py                 # live dashboard

Dev without GPU / AWS: set USE_HEURISTIC=1 and USE_MOCK_BEDROCK=1 in .env.

## VS Code on WSL

Keep the checkout in the WSL filesystem (for example `~/src/ir-triage`) for better
Linux file and Python performance. From a WSL terminal, install the basic tools:

    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip git

Open the project in VS Code from that directory:

    code .

If prompted, install the recommended extensions in the WSL side of VS Code and
reopen the folder in WSL. In VS Code, run **Terminal: Run Task** → **Python: create
virtual environment**, then **Python: install dependencies**. The workspace uses
`.venv/bin/python` as its interpreter. Copy `.env.example` to `.env` and set
`USE_HEURISTIC=1` and `USE_MOCK_BEDROCK=1` for local development without the model
server or AWS credentials.

Use **Run and Debug** → **Streamlit dashboard (mock mode)** to start the dashboard,
or run **Triage: run dashboard (mock mode)** from the task picker. The
**Triage: CLI smoke run (mock mode)** task runs the sample pipeline in a terminal.

For live model and Bedrock integration, configure `.env` and AWS credentials in
your WSL environment, then start the Decider server in a WSL terminal before
starting the dashboard. Do not put credentials in workspace settings or commit
`.env`.
