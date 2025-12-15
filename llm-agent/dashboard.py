#!/usr/bin/env python3
"""
OWASP Dependency Analysis Dashboard
A Streamlit web UI for visualizing and analyzing dependency vulnerabilities

Run: streamlit run dashboard.py
"""

import streamlit as st
import json
import os
from dotenv import load_dotenv
from tools import (
    analyze_risk_statistics,
    read_neo4j_query,
    visualize_dependency_graph,
    enrich_cve_data
)
from streamlit_agent import StreamlitAgent

# Load environment variables from .env file
load_dotenv()

# Project Title from environment variable
PROJECT_TITLE = os.getenv("PROJECT_TITLE", "DRAI - Dependency Scan & Remediate AI Asistant")

# Project Logo from environment variable (optional)
PROJECT_LOGO = os.getenv("PROJECT_LOGO", "").strip()
logo_source = None
if PROJECT_LOGO:
    # If it's a URL, use it directly
    if PROJECT_LOGO.startswith(("http://", "https://")):
        logo_source = PROJECT_LOGO
    else:
        # Try local file next to this script
        local_logo_path = os.path.join(os.path.dirname(__file__), PROJECT_LOGO)
        if os.path.exists(local_logo_path):
            logo_source = local_logo_path
        # Fall back to using the value as-is (could be an absolute path)
        elif os.path.exists(PROJECT_LOGO):
            logo_source = PROJECT_LOGO
        # If not found, leave logo_source as None (don't show anything)

# Page configuration
st.set_page_config(
    page_title="OWASP Dependency Analysis",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
.big-font {
    font-size:20px !important;
    font-weight: bold;
}
.critical { color: #ff4444; font-weight: bold; }
.high { color: #ff8800; font-weight: bold; }
.medium { color: #ffdd00; font-weight: bold; }
.low { color: #88ff88; font-weight: bold; }
.sidebar-title {
    font-size: 18px !important;
    font-weight: bold;
    color: #1f77b4;
    padding: 0px 0px;
    text-align: center;
    border-bottom: 2px solid #1f77b4;
    margin-bottom: 20px;
}
/* Hide only the Deploy button, keep hamburger menu and running man */
button[kind="header"] {
    display: none !important;
}
</style>
""", unsafe_allow_html=True)

# Title
st.title("🔒 OWASP Dependency Analysis Dashboard")
st.markdown("---")

# Sidebar
# Show logo above the project title if provided and found
if logo_source:
    try:
        # Use the full sidebar width for the logo so it fills the available space
        st.sidebar.image(logo_source, use_container_width=True)
    except Exception:
        # If image loading fails, silently continue and show no logo
        pass

st.sidebar.markdown(f'<p class="sidebar-title">🤖 {PROJECT_TITLE}</p>', unsafe_allow_html=True)
st.sidebar.header("Configuration")
neo4j_uri = st.sidebar.text_input("Neo4j URI", value=os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687"))
neo4j_user = st.sidebar.text_input("Neo4j User", value=os.getenv("NEO4J_USER", "neo4j"))
neo4j_password = st.sidebar.text_input("Neo4j Password", value=os.getenv("NEO4J_PASSWORD", "password"), type="password")

# Update environment variables
os.environ["NEO4J_URI"] = neo4j_uri
os.environ["NEO4J_USER"] = neo4j_user
os.environ["NEO4J_PASSWORD"] = neo4j_password

# Main tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Overview", "📈 Risk Analysis", "🌐 Dependency Graph", "🔍 CVE Lookup", "💬 AI Chat"])

# Tab 1: Overview
with tab1:
    st.header("Vulnerability Overview")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Severity Distribution")
        if st.button("Load Severity Distribution", key="load_severity"):
            with st.spinner("Fetching data from Neo4j..."):
                result = read_neo4j_query(
                    "MATCH (v:Vulnerability) RETURN v.severity as severity, count(*) as count ORDER BY count DESC"
                )
                data = json.loads(result)

                if data["success"]:
                    import pandas as pd
                    df = pd.DataFrame(data["results"])
                    st.bar_chart(df.set_index("severity"))
                    st.dataframe(df, use_container_width=True)
                else:
                    st.error(f"Error: {data.get('error', 'Unknown error')}")

    with col2:
        st.subheader("Quick Stats")
        if st.button("Load Statistics", key="load_stats"):
            with st.spinner("Calculating statistics..."):
                result = read_neo4j_query("MATCH (v:Vulnerability) RETURN count(v) as total")
                data = json.loads(result)

                if data["success"] and data["results"]:
                    total_vulns = data["results"][0]["total"]
                    st.metric("Total Vulnerabilities", total_vulns)

                # Get dependency count
                result = read_neo4j_query("MATCH (d:Dependency) RETURN count(d) as total")
                data = json.loads(result)

                if data["success"] and data["results"]:
                    total_deps = data["results"][0]["total"]
                    st.metric("Total Dependencies", total_deps)

# Tab 2: Risk Analysis
with tab2:
    st.header("Risk Analysis")

    if st.button("Run Complete Risk Analysis", key="run_risk"):
        with st.spinner("Analyzing risks..."):
            result = analyze_risk_statistics()
            data = json.loads(result)

            if data["success"]:
                st.success("Analysis complete!")

                # Summary metrics
                st.subheader("Summary")
                col1, col2, col3, col4 = st.columns(4)

                dep_breakdown = data["dependency_breakdown"]
                vuln_summary = data["vulnerability_summary"]
                col1.metric("Total Dependencies", dep_breakdown["total_dependencies"])
                col2.metric("With Vulnerabilities", dep_breakdown["dependencies_with_vulnerabilities"])
                col3.metric("Safe Dependencies", dep_breakdown["safe_dependencies"])
                col4.metric("Total Vulnerabilities", vuln_summary["total_vulnerabilities"])

                # CVSS Statistics
                st.subheader("CVSS Score Statistics")
                cvss = vuln_summary["cvss_statistics"]
                col1, col2, col3 = st.columns(3)
                col1.metric("Average CVSS", f"{cvss['average']:.2f}" if cvss['average'] else "N/A")
                col2.metric("Maximum CVSS", cvss['maximum'] or "N/A")
                col3.metric("Minimum CVSS", cvss['minimum'] or "N/A")

                # Top risky dependencies
                st.subheader("Top 10 Riskiest Dependencies")
                import pandas as pd
                risky_df = pd.DataFrame(data["top_10_riskiest_dependencies"])
                st.dataframe(risky_df, use_container_width=True)
            else:
                st.error(f"Error: {data.get('error', 'Unknown error')}")

# Tab 3: Dependency Graph
with tab3:
    st.header("Dependency Vulnerability Graph")

    col1, col2 = st.columns([1, 3])

    with col1:
        st.subheader("Generate New Graph")
        limit = st.slider("Max Dependencies", min_value=5, max_value=50, value=20)

        if st.button("Generate Graph", key="gen_graph"):
            output_file = "dependency_graph.png"
            with st.spinner("Generating graph..."):
                result = visualize_dependency_graph(limit=limit, output_file=output_file)
                data = json.loads(result)

                if data["success"]:
                    st.success(data["message"])
                    st.metric("Dependencies", data["dependencies_count"])
                    st.metric("Vulnerabilities", data.get("vulnerabilities_count", data.get("dependencies_count")))
                    st.metric("Relationships", data.get("edges_count", data.get("relationships_count", 0)))
                    st.session_state.selected_graph = output_file
                    # Force refresh
                    st.rerun()
                else:
                    st.error(f"Error: {data.get('error', 'Unknown error')}")

        st.markdown("---")
        st.subheader("Saved Graphs")

        # List all *.png files in current directory (refreshed on every render)
        import glob
        png_files = sorted(glob.glob("*.png"), key=os.path.getmtime, reverse=True)

        # Filter out logo.png and other non-graph files
        graph_files = [f for f in png_files if f != "logo.png"]

        if graph_files:
            st.caption(f"📁 {len(graph_files)} graph(s) found")
            for png_file in graph_files:
                file_time = os.path.getmtime(png_file)
                from datetime import datetime
                time_str = datetime.fromtimestamp(file_time).strftime("%Y-%m-%d %H:%M")

                # Show selected state
                is_selected = st.session_state.get("selected_graph") == png_file
                button_label = f"{'✅' if is_selected else '📊'} {png_file}"

                if st.button(f"{button_label}\n📅 {time_str}",
                           key=f"select_{png_file}",
                           use_container_width=True):
                    st.session_state.selected_graph = png_file
                    st.rerun()
        else:
            st.info("No graphs yet. Generate one to get started!")

    with col2:
        # Get selected graph from session state, default to dependency_graph.png
        selected_file = st.session_state.get("selected_graph", "dependency_graph.png")

        if os.path.exists(selected_file):
            st.subheader(f"📊 {selected_file}")
            st.image(selected_file, use_container_width=True)

            # File info
            file_size = os.path.getsize(selected_file) / 1024
            file_time = os.path.getmtime(selected_file)
            from datetime import datetime
            time_str = datetime.fromtimestamp(file_time).strftime("%Y-%m-%d %H:%M:%S")

            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("File Size", f"{file_size:.1f} KB")
            with col_b:
                st.metric("Created", time_str.split()[1])
            with col_c:
                st.metric("Date", time_str.split()[0])

            # Download button
            with open(selected_file, "rb") as file:
                st.download_button(
                    label="📥 Download Graph (PNG)",
                    data=file,
                    file_name=selected_file,
                    mime="image/png",
                    key="download_graph",
                    use_container_width=True
                )
        else:
            st.info("Generate a graph or select one from the list to view it here")

# Tab 4: CVE Lookup
with tab4:
    st.header("CVE Information Lookup")

    cve_id = st.text_input("Enter CVE ID (e.g., CVE-2024-21733)", key="cve_input")

    if st.button("Lookup CVE", key="lookup_cve"):
        if cve_id:
            with st.spinner(f"Fetching information for {cve_id}..."):
                result = enrich_cve_data(cve_id)
                data = json.loads(result)

                if data["success"]:
                    st.success(f"CVE {cve_id} found!")

                    col1, col2 = st.columns(2)

                    with col1:
                        st.subheader("Basic Information")
                        st.write(f"**CVE ID:** {data['cve_id']}")
                        if data.get('source'):
                            st.info(f"📦 Source: {data['source']}")
                        if data.get('note'):
                            st.caption(f"ℹ️ {data['note']}")

                        st.subheader("Description")
                        st.write(data.get('description', 'No description available'))

                    with col2:
                        st.subheader("CVSS Scores")

                        if data.get('cvss_v3'):
                            cvss3 = data['cvss_v3']
                            st.write("**CVSS v3:**")
                            st.write(f"- Score: {cvss3['score']}")
                            st.write(f"- Severity: {cvss3['severity']}")
                            st.write(f"- Vector: `{cvss3['vector']}`")

                        if data.get('cvss_v2'):
                            cvss2 = data['cvss_v2']
                            st.write("**CVSS v2:**")
                            st.write(f"- Score: {cvss2['score']}")
                            st.write(f"- Severity: {cvss2['severity']}")
                            st.write(f"- Vector: `{cvss2['vector']}`")

                    if data.get('cwes'):
                        st.subheader("CWE (Common Weakness Enumeration)")
                        for cwe in data['cwes']:
                            st.write(f"- {cwe}")

                    if data.get('references'):
                        st.subheader("References")
                        for ref in data['references']:
                            st.write(f"- {ref}")

                    # Show affected packages from Neo4j
                    if data.get('affected_packages'):
                        st.subheader(f"📦 Affected Packages ({data.get('affected_count', 0)} found)")

                        import pandas as pd
                        packages_df = pd.DataFrame(data['affected_packages'])

                        # Rename columns for display
                        if not packages_df.empty:
                            packages_df = packages_df.rename(columns={
                                'groupId': 'Group ID',
                                'artifactId': 'Artifact ID',
                                'version': 'Version',
                                'isDirect': 'Direct?',
                                'module': 'Module',
                                'project': 'Project'
                            })

                            # Display as table
                            st.dataframe(packages_df, use_container_width=True, hide_index=True)
                    elif data.get('affected_count') == 0:
                        st.info("ℹ️ No affected packages found in your scanned projects.")
                else:
                    st.error(f"Error: {data.get('error', 'CVE not found')}")


        else:
            st.warning("Please enter a CVE ID")

# Tab 5: AI Chat
with tab5:
    st.header("💬 AI Security Assistant")
    st.markdown("🤖 **Interactive LLM Agent** - Ask anything about your dependencies and vulnerabilities!")

    # Initialize agent in session state
    if "agent" not in st.session_state:
        st.session_state.agent = None
        st.session_state.agent_model = "qwen3:8b"

    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Sidebar settings for chat
    with st.sidebar:
        st.markdown("---")
        st.subheader("🤖 AI Chat Settings")

        # LLM Configuration from environment
        llm_base_url = st.text_input(
            "LLM Base URL",
            value=os.getenv("LLM_BASE_URL", ""),
            help="OpenAI: https://api.openai.com/v1 | Ollama: http://localhost:11434/v1",
            placeholder="http://localhost:11434/v1"
        )
        llm_model = st.text_input(
            "LLM Model",
            value=os.getenv("LLM_MODEL", ""),
            help="e.g., gpt-4 (OpenAI), qwen3:8b (Ollama)",
            placeholder="qwen3:8b"
        )
        llm_api_key = st.text_input(
            "LLM API Key",
            value=os.getenv("LLM_API_KEY", ""),
            type="password",
            help="Optional for local Ollama/vLLM servers"
        )

        # Initialize agent button
        if st.button("🔄 Initialize Agent"):
            if not llm_base_url or not llm_model:
                st.error("❌ Please provide LLM_BASE_URL and LLM_MODEL")
            else:
                with st.spinner(f"Initializing {llm_model}..."):
                    try:
                        st.session_state.agent = StreamlitAgent(
                            model=llm_model,
                            base_url=llm_base_url,
                            api_key=llm_api_key if llm_api_key else None
                        )
                        st.session_state.agent.initialize()
                        st.session_state.agent_model = llm_model
                        st.success(f"✅ Agent initialized: {llm_model} @ {llm_base_url}")
                    except Exception as e:
                        st.error(f"❌ Failed to initialize: {str(e)}")
                        st.session_state.agent = None

        # Clear chat history
        if st.button("🗑️ Clear Chat History"):
            st.session_state.messages = []
            if st.session_state.agent:
                st.session_state.agent.clear_history()
            st.rerun()

        # Agent status
        if st.session_state.agent:
            st.success(f"✅ Agent Active: {st.session_state.agent_model}")
        else:
            st.warning("⚠️ Agent not initialized")

    # Display chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat input
    if prompt := st.chat_input("Ask about vulnerabilities, dependencies, CVEs, or anything..."):
        # Check if agent is initialized
        if not st.session_state.agent:
            with st.chat_message("assistant"):
                st.error("⚠️ Please initialize the agent first using the sidebar button!")
        else:
            # Add user message to history
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            # Generate assistant response using real LLM
            with st.chat_message("assistant"):
                with st.spinner("🤔 Agent is thinking..."):
                    try:
                        # Call agent.chat() - fully synchronous!
                        response = st.session_state.agent.chat(prompt)
                        st.markdown(response)
                        # Add assistant response to history
                        st.session_state.messages.append({"role": "assistant", "content": response})
                    except Exception as e:
                        error_msg = f"❌ **Error:** {str(e)}\n\nTry reinitializing the agent."
                        st.markdown(error_msg)
                        st.session_state.messages.append({"role": "assistant", "content": error_msg})

# Footer
st.markdown("---")
st.markdown(PROJECT_TITLE)