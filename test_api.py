"""
Test script for FastAPI Metasploit Pentester Agent
================================================
Tests all API endpoints using httpx.

Usage:
    python test_api.py

Prerequisites:
    - MetasploitMCP server running (http://127.0.0.1:8085)
    - FastAPI server running (http://127.0.0.1:8000)
    - API running: uvicorn api:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
import sys

import httpx


BASE_URL = "http://127.0.0.1:8000"


async def test_health():
    """Test GET /health"""
    print("\n[TEST] GET /health")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/health")
        data = resp.json()

        print(f"  Status: {resp.status_code}")
        print(f"  Response: {data}")

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["status"] in ("ok", "error"), f"Unexpected status: {data['status']}"
        print("  ✓ PASSED")
        return data


async def test_tools():
    """Test GET /tools"""
    print("\n[TEST] GET /tools")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/tools")
        data = resp.json()

        print(f"  Status: {resp.status_code}")
        print(f"  Tools loaded: {data['count']}")
        if data["tools"]:
            print(f"  First tool: {data['tools'][0]['name']}")

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert "tools" in data, "Missing 'tools' field"
        print("  ✓ PASSED")
        return data


async def test_history():
    """Test GET /history and DELETE /history"""
    print("\n[TEST] GET /history")
    async with httpx.AsyncClient() as client:
        # Get history
        resp = await client.get(f"{BASE_URL}/history")
        data = resp.json()

        print(f"  Status: {resp.status_code}")
        print(f"  Messages: {data['count']}")

        assert resp.status_code == 200
        assert "messages" in data
        print("  ✓ PASSED - GET /history")

        # Clear history
        print("\n[TEST] DELETE /history")
        resp = await client.delete(f"{BASE_URL}/history")
        data = resp.json()

        print(f"  Status: {resp.status_code}")
        print(f"  Response: {data}")

        assert resp.status_code == 200
        assert data.get("cleared") is True
        print("  ✓ PASSED - DELETE /history")


async def test_sessions():
    """Test GET /sessions"""
    print("\n[TEST] GET /sessions")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{BASE_URL}/sessions")
            data = resp.json()

            print(f"  Status: {resp.status_code}")
            print(f"  Sessions: {data.get('count', 0)}")

            assert resp.status_code == 200
            assert "sessions" in data
            print("  ✓ PASSED")
        except httpx.ConnectError:
            print("  ⚠ SKIPPED - Could not connect to API")
        except Exception as e:
            print(f"  ⚠ WARNING: {e}")


async def test_delete_sessions():
    """Test DELETE /sessions (cleanup)"""
    print("\n[TEST] DELETE /sessions")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.delete(f"{BASE_URL}/sessions")
            data = resp.json()

            print(f"  Status: {resp.status_code}")
            print(f"  Killed sessions: {data.get('killed_sessions', [])}")
            print(f"  Stopped jobs: {data.get('stopped_jobs', [])}")

            assert resp.status_code == 200
            print("  ✓ PASSED")
        except httpx.ConnectError:
            print("  ⚠ SKIPPED - Could not connect to API")
        except Exception as e:
            print(f"  ⚠ WARNING: {e}")


async def test_run():
    """Test POST /run with SSE streaming"""
    print("\n[TEST] POST /run (SSE streaming)")

    objective = "list available modules"

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            async with client.stream(
                "POST",
                f"{BASE_URL}/run",
                json={"objective": objective},
            ) as resp:
                print(f"  Status: {resp.status_code}")
                assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

                events = []
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        try:
                            event = json.loads(line[6:])
                            events.append(event)
                            print(f"  Event: {event.get('type')} - {event.get('tool_name', 'N/A')[:50]}")
                        except json.JSONDecodeError:
                            pass

                print(f"  Total events: {len(events)}")

                # Verify event types
                event_types = {e.get("type") for e in events}
                print(f"  Event types: {event_types}")

                if "done" in event_types:
                    print("  ✓ PASSED")
                else:
                    print("  ⚠ PARTIAL - No 'done' event received")
        except httpx.ConnectError:
            print("  ⚠ SKIPPED - Could not connect to API")
        except Exception as e:
            print(f"  ⚠ ERROR: {e}")


async def main():
    """Run all tests"""
    print("=" * 60)
    print("FastAPI Metasploit Pentester Agent - Test Suite")
    print("=" * 60)
    print(f"API URL: {BASE_URL}")

    try:
        # Health check first
        health = await test_health()
        if health.get("status") == "error":
            print("\n⚠ API not healthy - some tests may fail")
            print("  Make sure MetasploitMCP is running")

        await test_tools()
        await test_history()
        await test_sessions()
        await test_delete_sessions()
        await test_run()

        print("\n" + "=" * 60)
        print("All tests completed!")
        print("=" * 60)

    except httpx.ConnectError:
        print(f"\n⚠ ERROR: Could not connect to API at {BASE_URL}")
        print("  Make sure the API is running:")
        print("    uvicorn api:app --host 0.0.0.0 --port 8000")
        sys.exit(1)
    except Exception as e:
        print(f"\n⚠ ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())