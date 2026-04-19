# 1. Start MetasploitMCP in SSE mode
python MetasploitMCP.py --transport http --port 8085

# 2. Install deps
pip install -r requirements.txt

# 3. Run
export ANTHROPIC_API_KEY=sk-...

#4
python MetasploitMCP.py --transport http --port 8085
python agent.py "your objective here" 

