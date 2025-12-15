"""
LLM Agent with MCP Tool Server

This agent works with any OpenAI-compatible LLM API:
1. Starts the MCP server as a subprocess
2. Fetches available tools via MCP protocol
3. Sends tools to LLM for function calling
4. Executes tool calls via MCP

Environment Variables (Required):
- LLM_BASE_URL: API endpoint (e.g., https://api.openai.com/v1, http://localhost:8000/v1)
- LLM_MODEL: Model name (e.g., gpt-4, claude-3-5-sonnet, mistralai/Mistral-7B-Instruct-v0.2)
- LLM_API_KEY: API key (optional, for authenticated endpoints)

Examples:
  # OpenAI
  export LLM_BASE_URL=https://api.openai.com/v1
  export LLM_MODEL=gpt-4
  export LLM_API_KEY=sk-xxxxx

  # Ollama (OpenAI-compatible endpoint)
  export LLM_BASE_URL=http://localhost:11434/v1
  export LLM_MODEL=qwen3:8b
  # No API key needed for local Ollama

  # vLLM
  export LLM_BASE_URL=http://localhost:8000/v1
  export LLM_MODEL=mistralai/Mistral-7B-Instruct-v0.2
"""

import json
import httpx
import asyncio
import sys
import os
from pathlib import Path

# Enable readline for better input handling (arrow keys, command history)
try:
    import readline
except ImportError:
    # readline not available (e.g., on Windows), continue without it
    pass

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPToolBridge:
    """Bridge between MCP server and LLM."""
    
    def __init__(self, server_script: str = "server.py"):
        self.server_script = server_script
        self.session: ClientSession = None
        self._stdio_context = None
        self._session_context = None
        self._tools_cache = None

    async def connect(self):
        """Start MCP server and connect."""
        # Pass all environment variables to subprocess (especially JAVA_HOME for JayDeBeApi)
        server_params = StdioServerParameters(
            command=sys.executable,  # python path
            args=[self.server_script],
            env=os.environ.copy()  # Inherit all env vars including JAVA_HOME, PATH, LD_LIBRARY_PATH
        )
        
        # Start server process
        self._stdio_context = stdio_client(server_params)
        read, write = await self._stdio_context.__aenter__()
        
        # Create session
        self._session_context = ClientSession(read, write)
        self.session = await self._session_context.__aenter__()
        
        # Initialize MCP connection
        await self.session.initialize()
        
        # Cache tools
        tools_response = await self.session.list_tools()
        self._tools_cache = tools_response.tools
        
        return self

    async def disconnect(self):
        """Close MCP connection."""
        try:
            if self._session_context:
                await self._session_context.__aexit__(None, None, None)
        except (asyncio.CancelledError, RuntimeError, GeneratorExit):
            pass  # Ignore cleanup errors

        try:
            if self._stdio_context:
                await self._stdio_context.__aexit__(None, None, None)
        except (asyncio.CancelledError, RuntimeError, GeneratorExit):
            pass  # Ignore cleanup errors

    def get_tools(self) -> list[dict]:
        """Convert MCP tools to OpenAI-compatible format."""
        if not self._tools_cache:
            return []

        tools = []
        for tool in self._tools_cache:
            # Build parameters from inputSchema
            params = tool.inputSchema if tool.inputSchema else {
                "type": "object",
                "properties": {},
                "required": []
            }

            tools.append({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or f"Call {tool.name}",
                    "parameters": params
                }
            })
        return tools

    async def call_tool(self, name: str, arguments: dict) -> str:
        """Execute a tool via MCP and return result."""
        try:
            result = await self.session.call_tool(name, arguments)
            if result.content and len(result.content) > 0:
                return result.content[0].text
            return json.dumps({"success": False, "error": "Empty result"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})


def load_schema_from_markdown(file_path: str) -> str:
    """Loads the Neo4j schema and examples from a markdown file."""
    try:
        # Look for the file in the same directory as the agent script
        agent_dir = Path(__file__).parent
        schema_file = agent_dir / file_path
        
        if schema_file.exists():
            print(f"✅ Loading schema from: {schema_file}")
            return schema_file.read_text()
        else:
            print(f"⚠️ Schema file not found at {schema_file}, using fallback prompt.")
            return "No schema provided."
    except Exception as e:
        print(f"❌ Error loading schema file: {e}")
        return "Error loading schema."


class LLMAgent:
    """Agent that uses OpenAI-compatible LLM APIs + MCP tools."""
    
    def __init__(
        self,
        mcp_bridge: MCPToolBridge,
        model: str = None,
        base_url: str = None,
        api_key: str = None,
        schema_file: str = "prompt.neo4j.md"
    ):
        self.mcp = mcp_bridge

        # Read from environment (REQUIRED)
        self.base_url = base_url or os.getenv('LLM_BASE_URL')
        self.api_key = api_key or os.getenv('LLM_API_KEY')
        self.model = model or os.getenv('LLM_MODEL')

        # Validate required fields
        if not self.base_url:
            raise ValueError("LLM_BASE_URL environment variable or base_url parameter is required")
        if not self.model:
            raise ValueError("LLM_MODEL environment variable or model parameter is required")

        self.history: list[dict] = []
        
        # Dynamically load the schema and examples to create the system prompt
        schema_context = load_schema_from_markdown(schema_file)
        
        self.system_prompt = f"""You are a SECURITY ANALYST AI with access to tools for analyzing OWASP dependency check data.

🎯 YOUR MISSION: Proactively analyze, correlate, and provide actionable security insights based on the provided database schema.

---
📊 NEO4J GRAPH SCHEMA AND QUERY GUIDE:
{schema_context}
---

⚠️ CYPHER SYNTAX RULES:
- NO "GROUP BY" keyword exists in Cypher! Use implicit grouping in RETURN clause.
- Aggregation example: "MATCH (n)-[r]->(m) RETURN n.name, count(m) ORDER BY count(m) DESC"
- WRONG (SQL style): "MATCH (n) GROUP BY n.name" ❌
- RIGHT (Cypher style): "MATCH (n) RETURN n.name, count(n)" ✅

🧠 ReAct PATTERN - Show Your Reasoning:
You MUST follow this pattern for EVERY interaction:

THOUGHT: [What you're thinking / What you learned]
ACTION: [Which tool to call and why]
OBSERVATION: [What the tool returned]
... (repeat as needed)
THOUGHT: [Final synthesis]
ANSWER: [Your response to user]

🚨 CRITICAL: NEVER HALLUCINATE DATA!
- If a tool returns {{"success": false, "error": "..."}}, YOU MUST:
  1. ACKNOWLEDGE the error to the user.
  2. EXPLAIN what went wrong.
  3. If it's a query error, TRY AGAIN with a corrected query based on the schema guide.
  4. NEVER make up data or pretend you got results when you didn't!
"""

    def _call_llm(self, messages: list[dict]) -> dict:
        """Make request to OpenAI-compatible LLM API."""
        tools = self.mcp.get_tools()

        # Build headers conditionally
        headers = {}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'

        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                f"{self.base_url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": messages,
                    "tools": tools,
                    "stream": False
                },
                headers=headers if headers else None
            )
            response.raise_for_status()
            return response.json()

    async def chat(self, user_message: str, max_tool_calls: int = 15) -> str:
        """Process user message, handle tool calls, return response."""
        
        # Build message list
        messages = [{"role": "system", "content": self.system_prompt}]
        messages.extend(self.history)
        messages.append({"role": "user", "content": user_message})

        tool_call_count = 0

        while tool_call_count < max_tool_calls:
            # Get LLM response
            response = self._call_llm(messages)

            # Debug: Print response structure (first time only)
            if tool_call_count == 0:
                print(f"[DEBUG] Response keys: {list(response.keys())}")

            # OpenAI format: response.choices[0].message
            # Parse response format
            if "choices" in response and response["choices"]:
                assistant_msg = response["choices"][0]["message"]
            else:
                # Fallback for other formats
                assistant_msg = response.get("message", {})

            tool_calls = assistant_msg.get("tool_calls", [])

            # No tool calls = final answer
            if not tool_calls:
                content = assistant_msg.get("content", "")
                self.history.append({"role": "user", "content": user_message})
                self.history.append({"role": "assistant", "content": content})
                return content

            # Add assistant message to context
            messages.append(assistant_msg)

            # Process each tool call
            for tc in tool_calls:
                tool_call_count += 1
                
                func = tc.get("function", {})
                name = func.get("name", "")
                args = func.get("arguments", {})
                
                # Parse arguments if string
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}

                print(f"  🔧 MCP Call: {name}({json.dumps(args)})")
                sys.stdout.flush() # Force flush after printing the call

                # Call tool via MCP
                result = await self.mcp.call_tool(name, args)

                print(f"  📤 Result: {result}")
                sys.stdout.flush() # Force flush after printing the result

                # Check if result indicates error and add strong warning
                try:
                    result_json = json.loads(result)
                    if isinstance(result_json, dict) and result_json.get("success") == False:
                        # Add strong warning to prevent hallucination
                        error_warning = (
                            "\n\n⚠️⚠️⚠️ CRITICAL WARNING ⚠️⚠️⚠️\n"
                            "The above tool call FAILED!\n"
                            "DO NOT make up data or pretend you got results.\n"
                            "You MUST either:\n"
                            "1. Fix the error and try again, OR\n"
                            "2. Tell the user the query failed and explain why.\n"
                            "NEVER provide fake data!\n"
                            "⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️\n"
                        )
                        result = result + error_warning
                        print(f"  ⚠️ Error detected in tool result - added warning")
                except json.JSONDecodeError:
                    pass  # Not JSON, continue normally

                # Add tool result to messages
                messages.append({
                    "role": "tool",
                    "content": result
                })

        # Max tool calls reached, get final response
        response = self._call_llm(messages)

        # Parse response format (OpenAI vs others)
        if "choices" in response and response["choices"]:
            content = response["choices"][0]["message"].get("content", "")
        else:
            content = response.get("message", {}).get("content", "")

        self.history.append({"role": "user", "content": user_message})
        self.history.append({"role": "assistant", "content": content})
        return content

    def clear_history(self):
        """Clear conversation history."""
        self.history = []


async def main():
    print("=" * 60)
    print("🤖 LLM Agent + MCP Server")
    print("=" * 60)
    print("Environment Variables Required:")
    print("  - LLM_BASE_URL: API endpoint")
    print("      OpenAI:  https://api.openai.com/v1")
    print("      Ollama:  http://localhost:11434/v1")
    print("      vLLM:    http://localhost:8000/v1")
    print("  - LLM_MODEL: Model name (e.g., gpt-4, qwen3:8b)")
    print("  - LLM_API_KEY: API key (optional for local servers)")
    print("=" * 60)

    # Connect to MCP server
    mcp_bridge = MCPToolBridge("server.py")

    try:
        await mcp_bridge.connect()
        print("✅ MCP Server connected")
    except FileNotFoundError:
        print("❌ server.py not found. Make sure it's in the same directory.")
        return
    except Exception as e:
        print(f"❌ Failed to connect to MCP server: {e}")
        return

    # Show available tools
    tools = mcp_bridge.get_tools()
    tool_names = [t["function"]["name"] for t in tools]
    print(f"📦 Tools: {tool_names}")
    print("-" * 60)
    print("Commands: 'quit' to exit, 'clear' to reset history")
    print("-" * 60)
    print()

    # Create agent
    try:
        agent = LLMAgent(mcp_bridge)
        print(f"✅ LLM configured: {agent.model} @ {agent.base_url}\n")
    except ValueError as e:
        print(f"❌ Configuration Error: {e}\n")
        await mcp_bridge.disconnect()
        return

    try:
        while True:
            user_input = input("You: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == "quit":
                break
            
            if user_input.lower() == "clear":
                agent.clear_history()
                print("History cleared.\n")
                continue

            # Print the user's question before processing and force flush
            print(f"\n🤔 Processing question: \"{user_input}\"\n")
            sys.stdout.flush()

            try:
                response = await agent.chat(user_input)
                print(f"\nAssistant: {response}\n")
            except httpx.ConnectError:
                print(f"\n❌ Cannot connect to LLM API at {agent.base_url}")
                print("Check your LLM_BASE_URL and ensure the service is running\n")
            except Exception as e:
                print(f"\n❌ Error: {e}\n")

    except KeyboardInterrupt:
        print("\n")
    finally:
        try:
            await mcp_bridge.disconnect()
        except Exception:
            pass  # Ignore disconnect errors
        print("Goodbye! 👋")


if __name__ == "__main__":
    asyncio.run(main())
