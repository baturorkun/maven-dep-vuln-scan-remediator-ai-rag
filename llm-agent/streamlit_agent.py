"""
Streamlit-compatible wrapper for the LLM Agent
Provides a synchronous interface for the async agent
"""

import asyncio
import os
from agent import MCPToolBridge, LLMAgent


class StreamlitAgent:
    """Synchronous wrapper for LLMAgent that works with Streamlit"""

    def __init__(self, model: str = None, base_url: str = None, api_key: str = None):
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.mcp_bridge = None
        self.agent = None
        self._loop = None

    def initialize(self):
        """Initialize the agent (must be called before use)"""
        # Create new event loop for this thread
        try:
            self._loop = asyncio.get_event_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

        # Initialize MCP bridge and agent
        self.mcp_bridge = MCPToolBridge("server.py")
        self._loop.run_until_complete(self.mcp_bridge.connect())
        self.agent = LLMAgent(
            self.mcp_bridge,
            model=self.model,
            base_url=self.base_url,
            api_key=self.api_key
        )

    def chat(self, message: str) -> str:
        """Send a message and get response (synchronous)"""
        if not self.agent:
            return "Error: Agent not initialized. Call initialize() first."

        try:
            response = self._loop.run_until_complete(
                self.agent.chat(message)
            )
            return response
        except Exception as e:
            return f"Error: {str(e)}"

    def clear_history(self):
        """Clear chat history"""
        if self.agent:
            self.agent.clear_history()

    def close(self):
        """Clean up resources"""
        if self.mcp_bridge and self._loop:
            self._loop.run_until_complete(self.mcp_bridge.disconnect())