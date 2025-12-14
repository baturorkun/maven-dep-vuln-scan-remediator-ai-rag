# Maven Dependency Scan & Remediate & AI RAG Supported

An AI-powered security analysis system for analyzing OWASP Dependency Check reports using Neo4j graph database, MCP (Model Context Protocol) tools, and LLM agents.

## 🎯 Overview

This project provides a comprehensive solution for:
- 🔍 Scanning Java projects for dependency vulnerabilities using OWASP Dependency Check
- 📊 Importing vulnerability data into Neo4j graph database
- 🤖 AI-powered analysis using LLM agents with MCP tools
- 📈 Interactive dashboard for visualization and analysis
- 🔗 Automated remediation suggestions based on available safe versions

## 🏗️ Architecture

```
┌─────────────────────┐
│  Java Project       │
│  (Maven/Gradle)     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ OWASP Dependency    │
│ Check Scanner       │
│ (Container)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Import Script       │
│ (import_odc_to_     │
│  neo4j.py)          │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐         ┌─────────────────┐
│     Neo4j Graph     │◄────────┤   MCP Tools     │
│     Database        │         │   (server.py)   │
└──────────┬──────────┘         └────────┬────────┘
           │                             │
           ▼                             ▼
┌─────────────────────┐         ┌─────────────────┐
│  Streamlit          │         │   LLM Agent     │
│  Dashboard          │         │   (agent.py)    │
└─────────────────────┘         └─────────────────┘
```

## 👤 User Flow

### Option 1: Web Dashboard (Recommended for most users)

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. USER OPENS BROWSER                                            │
│    → streamlit run dashboard.py                                  │
│    → Opens http://localhost:8501                                 │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. USER SEES DASHBOARD TABS                                      │
│    [Overview] [Risk Analysis] [Dependency Graph] [CVE] [AI Chat] │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                ┌───────────┴──────────┬────────────┬──────────────┐
                ▼                      ▼            ▼              ▼
    ┌───────────────────┐  ┌──────────────────┐  ┌────────┐  ┌─────────┐
    │ Overview Tab      │  │ Risk Analysis    │  │ Graph  │  │ AI Chat │
    │                   │  │                  │  │        │  │         │
    │ • Total CVEs      │  │ • Top 10 Risky   │  │ Visual │  │ Natural │
    │ • Severity Chart  │  │   Dependencies   │  │ Graph  │  │ Language│
    │ • Module Summary  │  │ • Risk Scores    │  │        │  │ Queries │
    └───────────────────┘  └──────────────────┘  └────────┘  └─────────┘
                                                                    │
                                                                    ▼
                                                    ┌────────────────────────┐
                                                    │ USER ASKS QUESTIONS:   │
                                                    │                        │
                                                    │ "What are the top 10   │
                                                    │  riskiest deps?"       │
                                                    │                        │
                                                    │ "Show me all CRITICAL  │
                                                    │  CVEs in log4j"        │
                                                    │                        │
                                                    │ "What's the safe       │
                                                    │  version for X?"       │
                                                    └───────────┬────────────┘
                                                                │
                                                                ▼
                                        ┌───────────────────────────────────┐
                                        │ 3. AI AGENT PROCESSES QUERY       │
                                        │    (Behind the scenes)            │
                                        │                                   │
                                        │    THOUGHT: "I need to query Neo4j│
                                        │             for dependencies..."  │
                                        │                                   │
                                        │    ACTION: Calls MCP Tool         │
                                        │            read_neo4j_query()     │
                                        └───────────────┬───────────────────┘
                                                        │
                                                        ▼
                                        ┌───────────────────────────────────┐
                                        │ 4. MCP TOOLS EXECUTE              │
                                        │    → Query Neo4j Graph DB         │
                                        │    → Fetch CVE data from NVD      │
                                        │    → Generate visualizations      │
                                        │    → Calculate risk scores        │
                                        └───────────────┬───────────────────┘
                                                        │
                                                        ▼
                                        ┌───────────────────────────────────┐
                                        │ 5. USER RECEIVES ANSWER           │
                                        │                                   │
                                        │    "Found 5 dependencies with     │
                                        │     CRITICAL vulnerabilities:     │
                                        │                                   │
                                        │     1. log4j-core 2.14.1          │
                                        │        → CVE-2021-44228 (10.0)    │
                                        │        → Recommended: 2.17.1      │
                                        │                                   │
                                        │     2. jackson-databind 2.9.8     │
                                        │        → CVE-2020-36518 (9.8)     │
                                        │        → Recommended: 2.12.6.1"   │
                                        └───────────────────────────────────┘
```

### Option 2: Command-Line Agent (For power users)

```
┌──────────────────────────────────────────────────────────────────┐
│ USER RUNS: python agent.py                                       │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ INTERACTIVE CHAT SESSION STARTS                                  │
│                                                                   │
│ You: What are the top 10 riskiest dependencies?                  │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ AGENT SHOWS REASONING (ReAct Pattern)                            │
│                                                                   │
│ 💭 THOUGHT: I should use the analyze_risk_statistics tool...     │
│                                                                   │
│ 🔧 ACTION: analyze_risk_statistics()                             │
│                                                                   │
│ 📊 OBSERVATION: Retrieved risk data with 47 total deps...        │
│                                                                   │
│ 💭 THOUGHT: Now I can answer with the top 10 by risk score...    │
│                                                                   │
│ 🤖 ANSWER: Here are the top 10 riskiest dependencies:            │
│    1. log4j-core 2.14.1 (Risk: 95/100) - 3 CRITICAL CVEs         │
│    2. jackson-databind 2.9.8 (Risk: 87/100) - 2 HIGH CVEs        │
│    ...                                                            │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ You: What's the recommended upgrade for log4j-core?              │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ 💭 THOUGHT: I need to query Neo4j for RECOMMENDED_VERSION...     │
│                                                                   │
│ 🔧 ACTION: read_neo4j_query(                                     │
│      "MATCH (d:Dependency {artifactId: 'log4j-core'})            │
│       -[:RECOMMENDED_VERSION]->(v:ArtifactVersion)               │
│       RETURN v.version")                                         │
│                                                                   │
│ 📊 OBSERVATION: Found version 2.17.1                             │
│                                                                   │
│ 🤖 ANSWER: Recommended version for log4j-core: 2.17.1            │
│    This version has no known CVEs and is safe to upgrade to.     │
└──────────────────────────────────────────────────────────────────┘
```

### Complete Query Journey (Behind the Scenes)

```
USER QUESTION                    AI AGENT                  MCP TOOLS              NEO4J DATABASE
     │                              │                          │                         │
     │ "Show CVEs in module1"       │                          │                         │
     ├─────────────────────────────>│                          │                         │
     │                              │                          │                         │
     │                              │ 💭 Parse question        │                         │
     │                              │ 💭 Identify: Need Neo4j  │                         │
     │                              │                          │                         │
     │                              │ read_neo4j_query()       │                         │
     │                              ├─────────────────────────>│                         │
     │                              │                          │                         │
     │                              │                          │ MATCH (m:Module         │
     │                              │                          │  {name:'module1'})      │
     │                              │                          │ -[:USES_DEPENDENCY]->   │
     │                              │                          │  (d)-[:HAS_VULN]->(v)   │
     │                              │                          ├────────────────────────>│
     │                              │                          │                         │
     │                              │                          │    Execute Cypher       │
     │                              │                          │    Return Results       │
     │                              │                          │<────────────────────────┤
     │                              │                          │                         │
     │                              │ 📊 Results: 12 CVEs      │                         │
     │                              │<─────────────────────────┤                         │
     │                              │                          │                         │
     │                              │ 💭 Format answer         │                         │
     │                              │ 💭 Add recommendations   │                         │
     │                              │                          │                         │
     │ 🤖 "Found 12 CVEs:"          │                          │                         │
     │    "1. CVE-2021-44228..."    │                          │                         │
     │    "2. CVE-2020-36518..."    │                          │                         │
     │<─────────────────────────────┤                          │                         │
     │                              │                          │                         │
```

## 📁 Project Structure

```
dependency-remediate-ai-rag/
├── version-scanner-odc/        # OWASP Dependency Check scanner
│   ├── Dockerfile-odc          # Scanner container definition
│   ├── version-scanner-odc.py  # Main scanner script
│   ├── remediation.py          # Version remediation logic
│   ├── get-odc-data.sh         # Initialize ODC database
│   ├── build.sh                # Build container
│   └── java-project/           # Sample multi-module Java project
│
├── rag_graphdb/                # Neo4j import & tools
│   ├── import_odc_to_neo4j.py  # Import ODC reports to Neo4j
│   ├── verify_neo4j.py         # Verify Neo4j connection
│   ├── test_tools.py           # Test MCP tools
│   ├── requirements.txt        # Python dependencies
│   └── .docs/                  # Documentation
│       ├── plan1.md            # Neo4j schema design
│       └── README.md           # Implementation guide
│
├── mcp_agent/                  # MCP Server & LLM Agent
│   ├── server.py               # MCP tool server (FastMCP)
│   ├── agent.py                # LLM agent with MCP client
│   ├── tools.py                # Tool implementations
│   ├── dashboard.py            # Streamlit web UI
│   ├── streamlit_agent.py      # Streamlit chat interface
│   ├── prompt.neo4j.md         # Neo4j schema guide for LLM
│   └── requirements.txt        # Python dependencies
│
└── README.md                   # This file
```

## 🚀 Quick Start

### Prerequisites

- Docker (for OWASP Dependency Check scanner)
- Python 3.9+
- Neo4j 5.0+ (running locally or remote)
- LLM API (OpenAI, Ollama, or any OpenAI-compatible endpoint)

### 1. Setup Neo4j

```bash
# Using Docker
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password \
  neo4j:latest

# Or use Neo4j Desktop, AuraDB, etc.
```

### 2. Setup Environment Variables

```bash
# Neo4j Configuration
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your_password"

# LLM Configuration (for agent.py)
export LLM_BASE_URL="http://localhost:11434/v1"  # Ollama
export LLM_MODEL="qwen3:8b"
# export LLM_API_KEY="sk-xxx"  # Only if using OpenAI or similar
```

### 3. Install Python Dependencies

```bash
# Install dependencies for rag_graphdb
cd rag_graphdb
pip install -r requirements.txt

# Install dependencies for mcp_agent
cd ../mcp_agent
pip install -r requirements.txt
```

### 4. Build Scanner Container

```bash
cd version-scanner-odc

# Initialize OWASP Dependency Check database
./get-odc-data.sh

# Build container (macOS ARM64)
./build.sh osx

# Or for Linux AMD64
# ./build.sh linux
```

### 5. Scan a Java Project

```bash
cd version-scanner-odc

# Scan the sample project
docker run --rm \
  -v "$(pwd):/app" \
  -v "$(pwd)/version-scanner-odc.py:/scanner/version-scanner-odc.py" \
  -v "$(pwd)/remediation.py:/scanner/remediation.py" \
  version-scanner-odc:odc-arm64 \
  --target-dir /app/java-project \
  --remediation \
  --transitive

# This generates:
# - dependency-check-report.json (per module)
# - dependency-graph.graphml (dependency tree)
# - remediation.json (version upgrade suggestions)
```

### 6. Import Data to Neo4j

```bash
cd rag_graphdb

# Import all ODC reports from the scanned project
python import_odc_to_neo4j.py \
  --target-dir ../version-scanner-odc/java-project \
  --project MY_PROJECT

# Verify import
python verify_neo4j.py
```

### 7. Test MCP Tools

```bash
cd rag_graphdb

# Test all tools
python test_tools.py
```

### 8. Run LLM Agent (Interactive Chat)

```bash
cd mcp_agent

# Start the agent
python agent.py

# Ask questions like:
# - "What are the top 10 riskiest dependencies?"
# - "Which dependencies have CRITICAL vulnerabilities?"
# - "What is the recommended version for log4j-core?"
```

### 9. Run Dashboard (Web UI)

```bash
cd mcp_agent

# Start Streamlit dashboard
streamlit run dashboard.py

# Open browser at http://localhost:8501
```

## 🔧 Neo4j Graph Schema

The system implements a comprehensive graph schema based on Plan1.md (Method 2):

### Node Types

- **Project**: Software project
- **Module**: Project modules (in multi-module projects)
- **Dependency**: Library dependencies (identified by SHA256)
- **Vulnerability**: Known CVEs
- **ArtifactVersion**: Specific versions of artifacts

### Relationships

```cypher
(Project)-[:HAS_MODULE]->(Module)
(Module)-[:USES_DEPENDENCY]->(Dependency)
(Dependency)-[:HAS_VULNERABILITY]->(Vulnerability)
(Dependency)-[:CURRENT_VERSION {project, module}]->(ArtifactVersion)
(Dependency)-[:RECOMMENDED_VERSION {project, module}]->(ArtifactVersion)
(Dependency)-[:AVAILABLE_VERSION {project, module}]->(ArtifactVersion)
(ArtifactVersion)-[:UPGRADES_TO]->(ArtifactVersion)
(Dependency)-[:DEPENDS_ON]->(Dependency)
```

### Key Properties

**Dependency:**
- `sha256`: Unique identifier
- `groupId`, `artifactId`, `detectedVersion`: Maven coordinates
- `isDirectDependency`: Boolean (from GraphML analysis)
- `hasRemediation`: Boolean (safe upgrade available)
- `usedByProjects[]`: Array of project codes
- `usedByModules[]`: Array of module names

**ArtifactVersion:**
- `version`: Version string (e.g., "2.17.0")
- `majorVersion`, `minorVersion`, `patchVersion`: Parsed integers
- `hasCVE`: Boolean
- `cveCount`: Number of CVEs
- `highSeverityCVECount`: Number of HIGH/CRITICAL CVEs

**Vulnerability:**
- `name`: CVE identifier
- `severity`: CRITICAL, HIGH, MEDIUM, LOW
- `cvssScore`: CVSS score (float)
- `description`: Vulnerability description

## 🛠️ MCP Tools

The system provides the following MCP tools:

### 1. `analyze_risk_statistics()`
Returns comprehensive risk analysis including:
- Project and module overview
- Vulnerability counts and severity distribution
- Top 10 riskiest dependencies with risk scores
- CVSS statistics

### 2. `read_neo4j_query(query: str)`
Execute Cypher queries on Neo4j database with auto-correction for common mistakes.

### 3. `visualize_dependency_graph(limit: int, output_file: str)`
Generate visual dependency graph showing dependencies and their vulnerabilities.

### 4. `enrich_cve_data(cve_id: str)`
Fetch detailed CVE information from NVD API.

### 5. Utility tools
- `get_current_time(timezone: str)`
- `calculate(expression: str)`
- `get_weather(city: str)` (mock data)

## 📊 Example Queries

### Find direct dependencies with remediations

```cypher
MATCH (d:Dependency {isDirectDependency: true, hasRemediation: true})
  -[:RECOMMENDED_VERSION]->(rec:ArtifactVersion)
RETURN d.groupId, d.artifactId, d.detectedVersion, 
       rec.version AS remediationVersion
```

### Get all CVEs for a specific dependency

```cypher
MATCH (d:Dependency {artifactId: "log4j-core"})
  -[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN v.name, v.severity, v.cvssScore
ORDER BY v.cvssScore DESC
```

### Find upgrade path

```cypher
MATCH path = (cv:ArtifactVersion {version: "2.14.1"})
  -[:UPGRADES_TO*]->(rv:ArtifactVersion {version: "2.17.0"})
RETURN path
```

## 🤖 LLM Agent Features

The LLM agent (`agent.py`) implements:

- **ReAct Pattern**: Shows reasoning (THOUGHT → ACTION → OBSERVATION)
- **Auto-correction**: Fixes common Cypher syntax errors (e.g., GROUP BY)
- **Error Prevention**: Prevents hallucination with strong warnings
- **Schema-aware**: Loaded with Neo4j schema guide (`prompt.neo4j.md`)
- **Tool Chaining**: Can call multiple tools to answer complex questions

## 📈 Dashboard Features

The Streamlit dashboard (`dashboard.py`) provides:

- **Overview Tab**: Vulnerability counts and severity distribution
- **Risk Analysis Tab**: Complete risk statistics and top risky dependencies
- **Dependency Graph Tab**: Visual graph generation
- **CVE Lookup Tab**: Detailed CVE information from NVD
- **AI Chat Tab**: Interactive chat with LLM agent

## 🧪 Testing

```bash
# Test Neo4j connection
cd rag_graphdb
python verify_neo4j.py

# Test all MCP tools
python test_tools.py

# Test specific query
python -c "
import sys
sys.path.insert(0, '../mcp_agent')
from tools import read_neo4j_query
print(read_neo4j_query('MATCH (v:Vulnerability) RETURN count(v)'))
"
```

## 📚 Documentation

- `rag_graphdb/.docs/plan1.md`: Neo4j schema design and rationale
- `rag_graphdb/.docs/README.md`: Implementation guide
- `mcp_agent/prompt.neo4j.md`: Neo4j schema guide for LLM
- `version-scanner-odc/README.md`: Scanner usage guide

## 🔐 Security Notes

- Store Neo4j credentials securely (use `.env` files)
- Don't commit API keys to version control
- Review remediation suggestions before applying
- Test upgrades in a staging environment first

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

See LICENSE file for details.

## 🙏 Acknowledgments

- OWASP Dependency Check project
- Neo4j graph database
- FastMCP framework
- Streamlit framework
- Model Context Protocol (MCP) specification

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation in `.docs/` folders
- Review example queries in `prompt.neo4j.md`

---

**Note**: This is an active development project. Features and APIs may change.

