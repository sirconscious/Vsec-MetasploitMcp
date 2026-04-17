"""
Pentester Agent — LangChain + MetasploitMCP
============================================
Uses the MetasploitMCP SSE server as the tool backend and a ReAct agent
loop (via LangGraph) to autonomously plan and execute pentest workflows.

Prerequisites
-------------
    pip install langchain langgraph langchain-anthropic \
                langchain-mcp-adapters mcp rich

Environment
-----------
    ANTHROPIC_API_KEY=...   (or swap in any LangChain-supported LLM)
    MSF_MCP_URL=http://127.0.0.1:8085/sse   (where MetasploitMCP is running)
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ── Console setup ─────────────────────────────────────────────────────────────

THEME = Theme({
    "banner":       "bold red",
    "section":      "bold yellow",
    "tool.name":    "cyan",
    "tool.args":    "dim white",
    "tool.result":  "green",
    "tool.warn":    "yellow",
    "tool.error":   "bold red",
    "ai":           "white",
    "human":        "bold magenta",
    "label":        "dim white",
    "success":      "bold green",
    "info":         "bold blue",
    "muted":        "dim",
})

console = Console(theme=THEME, highlight=False)

# ── Configuration ─────────────────────────────────────────────────────────────

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

# ── LLM setup ─────────────────────────────────────────────────────────────────

def build_llm() -> ChatAnthropic:
    return ChatAnthropic(
        model="claude-haiku-4-5",
        temperature=0,
        max_tokens=4096,
    )

# ── Agent factory ──────────────────────────────────────────────────────────────

async def build_agent(tools: list):
    llm = build_llm()
    agent = create_react_agent(
        llm,
        tools,
        prompt=SystemMessage(content=SYSTEM_PROMPT),
    )
    return agent

# ── UI helpers ─────────────────────────────────────────────────────────────────

def print_banner():
    banner = Text()
    banner.append("███╗   ███╗███████╗███████╗\n", style="bold red")
    banner.append("████╗ ████║██╔════╝██╔════╝\n", style="bold red")
    banner.append("██╔████╔██║███████╗█████╗  \n", style="bold red")
    banner.append("██║╚██╔╝██║╚════██║██╔══╝  \n", style="bold red")
    banner.append("██║ ╚═╝ ██║███████║██║     \n", style="bold red")
    banner.append("╚═╝     ╚═╝╚══════╝╚═╝     ", style="bold red")

    meta = Text()
    meta.append("MetasploitMCP", style="bold yellow")
    meta.append(" Pentester Agent\n", style="white")
    meta.append("LangChain + LangGraph + Anthropic\n\n", style="dim")
    meta.append(f"MCP Server: ", style="dim")
    meta.append(MSF_MCP_URL, style="cyan")
    meta.append(f"\nModel:      ", style="dim")
    meta.append("claude-haiku-4-5", style="cyan")
    meta.append(f"\nTime:       ", style="dim")
    meta.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="cyan")

    console.print()
    console.print(Panel(
        Columns([banner, meta], padding=(0, 4)),
        border_style="red",
        padding=(1, 2),
    ))
    console.print()


def print_tools_table(tools: list):
    table = Table(
        title="[bold yellow]Loaded MCP Tools[/]",
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        title_justify="left",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Tool Name", style="cyan")
    table.add_column("Description", style="dim white")

    for i, t in enumerate(tools, 1):
        desc = (getattr(t, "description", "") or "")[:72]
        if len(getattr(t, "description", "") or "") > 72:
            desc += "…"
        table.add_row(str(i), t.name, desc)

    console.print(table)
    console.print()


def _status_icon(status: str) -> tuple[str, str]:
    """Return (icon, style) based on a status string."""
    s = status.lower()
    if s in ("success", "ok"):
        return "✔", "green"
    if s in ("warning", "warn"):
        return "⚠", "yellow"
    if s in ("error", "fail", "failed"):
        return "✘", "bold red"
    return "●", "blue"


def render_tool_call(name: str, args: dict):
    arg_text = Text()
    for k, v in args.items():
        arg_text.append(f"  {k}: ", style="dim")
        arg_text.append(str(v) + "\n", style="white")

    console.print(Panel(
        arg_text,
        title=f"[bold cyan]⚙ TOOL CALL[/]  [cyan]{name}[/]",
        border_style="cyan",
        padding=(0, 1),
    ))


def render_tool_result(content: str):
    """Parse JSON tool results and render them as a nice panel."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        data = None

    if isinstance(data, dict):
        status = data.get("status", "")
        icon, style = _status_icon(status)
        message = data.get("message", "")

        body = Text()
        # Status line
        if status:
            body.append(f"{icon} {status.upper()}\n", style=f"bold {style}")
        if message:
            body.append(f"{message}\n\n", style="white")

        # Remaining keys
        skip = {"status", "message"}
        for k, v in data.items():
            if k in skip:
                continue
            body.append(f"{k}: ", style="dim")
            body.append(f"{json.dumps(v) if isinstance(v, (dict, list)) else str(v)}\n", style="white")

        border = style if style != "bold red" else "red"
        console.print(Panel(
            body,
            title=f"[{style}]◀ TOOL RESULT[/]",
            border_style=border,
            padding=(0, 1),
        ))
    else:
        # Plain text result
        console.print(Panel(
            Text(str(content), style="white"),
            title="[green]◀ TOOL RESULT[/]",
            border_style="green",
            padding=(0, 1),
        ))


def render_ai_message(text: str):
    console.print(Panel(
        Markdown(text),
        title="[bold white]🤖 AGENT[/]",
        border_style="white",
        padding=(0, 1),
    ))


def render_human_message(text: str):
    console.print(Panel(
        Text(text, style="bold magenta"),
        title="[bold magenta]▶ OBJECTIVE[/]",
        border_style="magenta",
        padding=(0, 1),
    ))


def print_section(title: str):
    console.print(Rule(f"[bold yellow]{title}[/]", style="yellow"))

# ── Message printer ────────────────────────────────────────────────────────────

def _print_message(msg: Any) -> None:
    kind = type(msg).__name__

    # Tool result messages
    if kind == "ToolMessage":
        if hasattr(msg, "content") and msg.content:
            render_tool_result(msg.content)
        return

    # Tool call messages (AI deciding to call a tool)
    if hasattr(msg, "tool_calls") and msg.tool_calls:
        for tc in msg.tool_calls:
            render_tool_call(tc["name"], tc.get("args", {}))

    # AI text content
    if hasattr(msg, "content") and msg.content:
        role = getattr(msg, "type", kind)
        if role == "human":
            render_human_message(msg.content if isinstance(msg.content, str) else "")
            return

        # Collect text blocks
        if isinstance(msg.content, str) and msg.content.strip():
            render_ai_message(msg.content)
        elif isinstance(msg.content, list):
            texts = [
                b["text"] for b in msg.content
                if isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip()
            ]
            if texts:
                render_ai_message("\n".join(texts))

# ── Runner ─────────────────────────────────────────────────────────────────────

async def run_pentest(objective: str, tools: list, agent) -> None:
    print_section("STARTING PENTEST")
    render_human_message(objective)
    console.print()

    messages = [HumanMessage(content=objective)]

    with console.status("[bold yellow]Agent thinking…[/]", spinner="dots") as status:
        async for chunk in agent.astream(
            {"messages": messages},
            stream_mode="values",
        ):
            last_msg = chunk["messages"][-1]
            msg_type = type(last_msg).__name__

            # Update spinner label based on what's happening
            if msg_type == "ToolMessage":
                status.update("[bold green]Processing tool result…[/]")
            elif hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                tc_name = last_msg.tool_calls[0]["name"]
                status.update(f"[bold cyan]Calling [cyan]{tc_name}[/]…[/]")
            else:
                status.update("[bold yellow]Agent reasoning…[/]")

            # Stop spinner briefly to print, then resume
            status.stop()
            _print_message(last_msg)
            console.print()
            status.start()

    print_section("RUN COMPLETE")

# ── Interactive mode ───────────────────────────────────────────────────────────

HELP_TEXT = """
[bold yellow]Commands:[/]
  [cyan]help[/]          Show this help
  [cyan]tools[/]         List loaded MCP tools
  [cyan]clear[/]         Clear the screen
  [cyan]exit[/] / [cyan]quit[/]   Exit the agent

[bold yellow]Usage:[/]
  Type any pentest objective in natural language and press Enter.

[bold yellow]Examples:[/]
  [dim]exploit vsftpd_234_backdoor on 192.168.1.10 with lhost 192.168.1.50[/]
  [dim]scan 10.10.10.5 and find all open ports and services[/]
  [dim]compromise 10.0.0.20 and dump /etc/passwd[/]
"""

async def interactive_mode(tools: list, agent) -> None:
    print_section("INTERACTIVE MODE")
    console.print("[dim]Type [cyan]help[/] for commands or enter an objective.[/]\n")

    while True:
        try:
            objective = Prompt.ask(
                Text.assemble(
                    ("msf-agent", "bold red"),
                    (" ❯ ", "yellow"),
                )
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Interrupted. Exiting.[/]")
            break

        if not objective:
            continue

        if objective.lower() in ("exit", "quit", "q"):
            console.print("[dim]Goodbye.[/]")
            break
        elif objective.lower() == "help":
            console.print(HELP_TEXT)
        elif objective.lower() == "tools":
            print_tools_table(tools)
        elif objective.lower() == "clear":
            console.clear()
            print_banner()
        else:
            console.print()
            try:
                await run_pentest(objective, tools, agent)
            except Exception as e:
                console.print(Panel(
                    Text(str(e), style="bold red"),
                    title="[bold red]ERROR[/]",
                    border_style="red",
                ))
            console.print()

# ── Entry point ────────────────────────────────────────────────────────────────

async def main() -> None:
    print_banner()

    # Connect to MCP
    with console.status("[bold yellow]Connecting to MetasploitMCP…[/]", spinner="dots"):
        client = MultiServerMCPClient({
            "metasploit": {
                "url": MSF_MCP_URL,
                "transport": "sse",
            }
        })
        tools = await client.get_tools()
        agent = await build_agent(tools)

    console.print(f"[success]✔ Connected — {len(tools)} tools loaded[/]\n")
    print_tools_table(tools)

    if len(sys.argv) >= 2:
        # Single-shot mode: objective passed as CLI argument
        objective = " ".join(sys.argv[1:])
        await run_pentest(objective, tools, agent)
    else:
        # Interactive REPL mode
        await interactive_mode(tools, agent)


if __name__ == "__main__":
    asyncio.run(main())