# FastAPI Backend for Metasploit Pentester Agent

## Overview

This FastAPI application wraps the LangChain + LangGraph + MetasploitMCP pentesting agent with HTTP endpoints and SSE streaming support. Connect a frontend to control the agent programmatically.

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start MetasploitMCP Server

In one terminal, start the MetasploitMCP server:

```bash
python MetasploitMCP.py
```

### 3. Start the API Server

In another terminal, start the FastAPI server:

```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Run Tests

```bash
python test_api.py
```

## Configuration

All configuration is loaded from `.env` (same file used by agent.py):

| Variable | Default | Description |
|----------|---------|-------------|
| `MSF_MCP_URL` | `http://127.0.0.1:8085/sse` | MetasploitMCP server URL |
| `MSF_LHOST` | `192.168.100.50` | Attacker IP |
| `MSF_LPORT` | `4444` | Default callback port |
| `MODEL` | `claude-haiku-4-5` | Anthropic model |
| `RUN_TIMEOUT` | `300` | Agent run timeout (seconds) |
| `SSE_TIMEOUT` | `120` | SSE read timeout (seconds) |

## Endpoints

### POST /run

Run a pentest objective with SSE streaming.

**Request:**
```json
{
  "objective": "exploit vsftpd 2.3.4 on 192.168.100.32"
}
```

**Response:** Server-Sent Events (SSE)

```json
{ "type": "tool_call", "content": "", "tool_name": "run_exploit", "tool_args": { ... } }
{ "type": "tool_result", "content": "{\"status\": \"success\", ...}", "tool_name": null, "tool_args": null }
{ "type": "ai_message", "content": "Exploiting target...", "tool_name": null, "tool_args": null }
{ "type": "done", "content": "Execution complete", "tool_name": null, "tool_args": null }
```

**Event Types:**
- `tool_call` - Agent calling a tool
- `tool_result` - Tool execution result
- `ai_message` - Agent reasoning message
- `error` - Error occurred
- `done` - Execution complete

**Error Responses:**
- `400` - Missing or empty objective
- `503` - Agent not ready (MCP connection failed)

### GET /sessions

Get active Metasploit sessions.

```json
{
  "sessions": {"1": {"id": "1", "type": "shell", ...}},
  "count": 1
}
```

### DELETE /sessions

Kill all active sessions and stop all jobs.

```json
{
  "killed_sessions": ["1", "2"],
  "stopped_jobs": ["1"]
}
```

### POST /cleanup

One-click cleanup for frontend use. Kills all sessions and jobs.

```json
{
  "status": "ok",
  "message": "All sessions and jobs cleared"
}
```

### GET /tools

List available MCP tools.

```json
{
  "tools": [
    {"name": "run_exploit", "description": "Run a Metasploit exploit module"},
    {"name": "list_active_sessions", "description": "List all active sessions"}
  ],
  "count": 15
}
```

### GET /history

Get current conversation history.

```json
{
  "messages": [
    {"type": "human", "content": "exploit vsftpd on 192.168.100.32"},
    {"type": "ai", "content": "Running exploit..."}
  ],
  "count": 2
}
```

### DELETE /history

Clear conversation history.

```json
{ "cleared": true }
```

### GET /health

Health check - is MetasploitMCP reachable?

```json
{
  "status": "ok",
  "tools_loaded": 15,
  "mcp_url": "http://127.0.0.1:8085/sse"
}
```

### GET /status

Get current agent status for frontend polling.

```json
{
  "ready": true,
  "tools_loaded": 15,
  "history_length": 2,
  "mcp_url": "http://127.0.0.1:8085/sse",
  "model": "claude-haiku-4-5",
  "lhost": "192.168.100.50",
  "lport": "4444"
}
```

## Bugs Fixed

| Bug | Description |
|-----|-------------|
| BUG 1 | Sessions parsing now handles dict format with "sessions" and "count" fields |
| BUG 2 | Lock acquired only at start/end of stream - doesn't block other requests |
| BUG 3 | Uses Pydantic model `RunRequest` instead of raw Request |
| BUG 4 | Returns 503 if agent is not ready before accepting /run requests |

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Frontend  │────▶│  FastAPI (api)  │────▶│ LangGraph Agent  │
└─────────────┘     └─────────────────┘     └──────────────────┘
         │                   │                        │
         │         POST /run (SSE)                 │
         │                   │              ┌───────┴────────┐
         │                   │              │               │
         │                   │        ┌─────▼────┐   ┌───▼────┐
         │                   │        │ MCP Cli  │   │  LLM  │
         │                   │        └─────────┘   └───────┘
         │                   │              │
         │          ┌────────┴─────────┐  │
         │          │                 │  │
         ▼          ▼                 ▼  ▼
    GET /sessions              GET /tools    │
    DELETE /sessions           GET /health   │
    POST /cleanup            GET /status  │
                           GET /history│
                           DELETE /history

┌────────────────────────────────────────────────────┐
│           MetasploitMCP Server                      │
│              (MetasploitMCP.py)                     │
│          http://127.0.0.1:8085/sse                 │
└────────────────────────────────────────────────────┘
```

## Files

| File | Description |
|------|-------------|
| `api.py` | FastAPI application (9 endpoints) |
| `test_api.py` | Test script with httpx |
| `requirements.txt` | Python dependencies |
| `README.md` | This documentation |
| `agent.py` | Original CLI agent (Reference) |
| `MetasploitMCP.py` | MCP server implementation |

## Running with Different Configurations

### Custom Port

```bash
uvicorn api:app --host 0.0.0.0 --port 9000
```

### Debug Mode

```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload --log-level debug
```

### Using a Different Model

```bash
MODEL=claude-sonnet-4-20250514 uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

## Error Handling

All errors are returned as SSE events with type `error`:

```json
{ "type": "error", "content": "TimeoutError: Run exceeded 300s timeout", "tool_name": null, "tool_args": null }
```

The server never crashes - errors are gracefully streamed back to the client.

## Session Response Format

The `/sessions` endpoint returns sessions as a dictionary (not a list):

```json
{
  "sessions": {
    "1": {
      "id": "1",
      "type": "shell",
      "tunnel_remote": "192.168.100.32:4444",
      "tunnel_local": "127.0.0.1:4444",
      "via_exploit": "exploit/unix/ftp/vsftpd_234_backdoor",
      "via_payload": "cmd/unix/shell_bind_tcp",
      "info": "192.168.100.32:21 vsftpd 2.3.4",
      "workspace": "default",
      "session_host": "192.168.100.32",
      "session_port": 4444,
      "target_host": "192.168.100.32"
    }
  },
  "count": 1
}
```

## Thread Safety

The conversation history is protected by `asyncio.Lock()` to ensure thread-safe access:
- Lock acquired only to copy history at start of run
- Agent streams WITHOUT the lock (doesn't block other requests)
- Lock acquired only to save updated history at end of run

## Development

### Adding New Endpoints

1. Add the endpoint to `api.py`
2. Add test function to `test_api.py`
3. Update this README

### Modifying the System Prompt

Edit `SYSTEM_PROMPT` in `api.py` to customize the agent behavior.

## License

See LICENSE file for details.