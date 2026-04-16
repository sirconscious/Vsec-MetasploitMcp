"""
interactive.py — Chat-style interface for the pentester agent.

Run:
    python interactive.py

Then describe the lab target and goal in plain English.
Type 'exit' or 'quit' to stop.
"""

import asyncio

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

from agent import SYSTEM_PROMPT, MSF_MCP_URL


async def interactive_session() -> None:
    client = MultiServerMCPClient({
        "metasploit": {
            "url": MSF_MCP_URL,
            "transport": "sse",
        }
    })

    tools = await client.get_tools()
    print(f"[*] Loaded {len(tools)} tools.\n")

    llm = ChatAnthropic(model="claude-haiku-4-5", temperature=0, max_tokens=4096)
    agent = create_react_agent(
        llm,
        tools,
        prompt=SystemMessage(content=SYSTEM_PROMPT),
    )

    print("Pentester Agent — interactive mode")
    print("Type your objective or follow-up. 'exit' to quit.\n")

    history = []

    while True:
        try:
            user_input = input("You> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if user_input.lower() in ("exit", "quit", "q"):
            break
        if not user_input:
            continue

        history.append(HumanMessage(content=user_input))

        result = await agent.ainvoke({"messages": history})
        response_msg = result["messages"][-1]

        if isinstance(response_msg.content, str):
            reply = response_msg.content
        elif isinstance(response_msg.content, list):
            reply = "\n".join(
                b.get("text", "") for b in response_msg.content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        else:
            reply = str(response_msg.content)

        print(f"\nAgent> {reply}\n")
        history.append(AIMessage(content=reply))


if __name__ == "__main__":
    asyncio.run(interactive_session())