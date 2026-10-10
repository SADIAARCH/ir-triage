# Real-Time Network Forensics & Incident Triage Agent

Decider 2B (fast policy triage, #policy) -> threshold -> Amazon Bedrock (deep analysis).

    pip install -r requirements.txt
    cp .env.example .env
    strands-decider serve StrandsAgents/strands-decider-2B-hobson-v19 --port 8000   # terminal 1
    python -m triage.decider_client      # verify raw response shape
    python -m triage.pipeline 400        # CLI smoke test
    streamlit run app.py                 # live dashboard

Dev without GPU / AWS: set USE_HEURISTIC=1 and USE_MOCK_BEDROCK=1 in .env.
