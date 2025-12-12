# Getting Started with Dependency Remediate AI RAG

This guide will walk you through setting up and using the Dependency Remediate AI RAG system for the first time.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [First Scan](#first-scan)
5. [Import Data](#import-data)
6. [Query the Database](#query-the-database)
7. [Use the AI Agent](#use-the-ai-agent)
8. [Use the Dashboard](#use-the-dashboard)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

Before you begin, ensure you have:

- **Python 3.9+** installed
- **Docker** or **Podman** installed (for the scanner)
- **Neo4j 5.0+** running (local or remote)
- **LLM API access** (Ollama, OpenAI, or any OpenAI-compatible endpoint)
- **Git** for cloning the repository

### Starting Neo4j

If you don't have Neo4j running, the easiest way is with Docker:

```bash
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password \
  neo4j:latest
```

Access the Neo4j Browser at: http://localhost:7474

### Setting up Ollama (Optional, for local LLM)

If you want to use a local LLM:

```bash
# Install Ollama (macOS)
brew install ollama

# Or download from https://ollama.ai

# Start Ollama
ollama serve

# Pull a model (in another terminal)
ollama pull qwen3:8b
```

## Installation

### Automated Setup (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd dependency-remediate-ai-rag

# Run the setup script
./setup.sh
```

The setup script will:
- Create virtual environments
- Install all dependencies
- Create a `.env` file
- Optionally initialize the OWASP database
- Optionally build the scanner container

### Manual Setup

If you prefer manual setup:

```bash
# 1. Create .env file
cp .env.example .env

# 2. Edit .env with your settings
vim .env

# 3. Install rag_graphdb dependencies
cd rag_graphdb
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate

# 4. Install mcp_agent dependencies
cd ../mcp_agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate

# 5. Initialize OWASP database
cd ../version-scanner-odc
./get-odc-data.sh

# 6. Build scanner container (macOS)
./build.sh osx
# Or for Linux: ./build.sh linux
```

## Configuration

Edit the `.env` file to configure your environment:

```bash
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password

# LLM Configuration
LLM_BASE_URL=http://localhost:11434/v1  # Ollama
LLM_MODEL=qwen3:8b
# LLM_API_KEY=  # Not needed for Ollama
```

### Verify Neo4j Connection

```bash
cd rag_graphdb
source venv/bin/activate

# Load environment variables
export $(cat ../.env | grep -v '^#' | xargs)

# Test connection
python verify_neo4j.py
```

You should see output showing node and relationship counts.

## First Scan

Let's scan the sample Java project:

```bash
cd version-scanner-odc

# Scan the project
docker run --rm \
  -v "$(pwd):/app" \
  -v "$(pwd)/version-scanner-odc.py:/scanner/version-scanner-odc.py" \
  -v "$(pwd)/remediation.py:/scanner/remediation.py" \
  version-scanner-odc:odc-arm64 \
  --target-dir /app/java-project \
  --remediation \
  --transitive

# For Linux, use: version-scanner-odc:odc-amd64
```

This will:
- Scan all modules in the java-project
- Generate dependency-check-report.json files
- Create dependency-graph.graphml files
- Generate remediation.json with upgrade suggestions

The scan takes a few minutes on first run (downloading vulnerability database).

### Understanding the Output

After scanning, you'll find in each module's `target/` directory:

```
target/
├── dependency-check-report/
│   ├── dependency-check-report.json  # Main vulnerability report
│   ├── dependency-check-report.html  # HTML report
│   └── dependency-check-report.xml   # XML report
├── dependency-graph.graphml          # Dependency tree
├── remediation.json                  # Version upgrade suggestions
└── transitive/                       # Transitive dependency data
    └── *.json
```

## Import Data

Now let's import the scan results into Neo4j:

```bash
cd ../rag_graphdb
source venv/bin/activate

# Load environment variables
export $(cat ../.env | grep -v '^#' | xargs)

# Import data
python import_odc_to_neo4j.py \
  --target-dir ../version-scanner-odc/java-project \
  --project MY_PROJECT
```

The import process will:
- Create Project and Module nodes
- Import all dependencies
- Link dependencies to vulnerabilities
- Create ArtifactVersion nodes for remediation
- Build DEPENDS_ON relationships from GraphML
- Create UPGRADES_TO paths between versions

### Verify the Import

```bash
python verify_neo4j.py
```

You should see counts like:
```
Project: 1
Module: 3
Dependency: 41
Vulnerability: 148
ArtifactVersion: 592
...
```

## Query the Database

### Using Neo4j Browser

Open http://localhost:7474 and try these queries:

```cypher
// See the schema
CALL db.schema.visualization()

// Count vulnerabilities by severity
MATCH (v:Vulnerability)
RETURN v.severity, count(*) as count
ORDER BY count DESC

// Find dependencies with CRITICAL vulnerabilities
MATCH (d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability {severity: 'CRITICAL'})
RETURN d.groupId, d.artifactId, d.detectedVersion, 
       count(v) as criticalCount
ORDER BY criticalCount DESC
```

### Using the Tools

```bash
# Test all tools
python test_tools.py

# Or test specific queries
python -c "
import sys
sys.path.insert(0, '../mcp_agent')
from tools import read_neo4j_query
print(read_neo4j_query('MATCH (v:Vulnerability) RETURN count(v)'))
"
```

### Example Queries

**Get project overview:**
```bash
python -c "
import sys
sys.path.insert(0, '../mcp_agent')
from tools import analyze_risk_statistics
import json
result = json.loads(analyze_risk_statistics())
print(json.dumps(result, indent=2))
"
```

**Find direct dependencies with remediations:**
```cypher
MATCH (d:Dependency {isDirectDependency: true, hasRemediation: true})
  -[:RECOMMENDED_VERSION]->(rec:ArtifactVersion)
RETURN d.groupId + ':' + d.artifactId as dependency,
       d.detectedVersion as current,
       rec.version as recommended
ORDER BY d.groupId, d.artifactId
```

## Use the AI Agent

The AI agent provides an interactive chat interface with access to all tools:

```bash
cd ../mcp_agent
source venv/bin/activate

# Load environment variables
export $(cat ../.env | grep -v '^#' | xargs)

# Start the agent
python agent.py
```

### Example Conversations

```
You: What are the top 10 riskiest dependencies?

Agent: 
THOUGHT: I need to get risk statistics from the database
ACTION: Calling analyze_risk_statistics()
OBSERVATION: ...
THOUGHT: The data shows...
ANSWER: Here are the top 10 riskiest dependencies:
1. jackson-databind (Risk Score: 245)
   - 15 vulnerabilities (8 CRITICAL, 7 HIGH)
   ...
```

```
You: Which direct dependencies have available fixes?

Agent:
THOUGHT: I need to query for direct dependencies with remediation
ACTION: Calling read_neo4j_query with Cypher query
OBSERVATION: Found 5 dependencies with fixes
THOUGHT: Let me format this clearly
ANSWER: The following direct dependencies have safe upgrades available:
1. log4j-core: 2.14.1 → 2.17.0
2. spring-webmvc: 5.2.8.RELEASE → 5.3.27
...
```

### Agent Commands

- `clear` - Clear conversation history
- `quit` - Exit the agent

## Use the Dashboard

For a visual interface, use the Streamlit dashboard:

```bash
cd mcp_agent
source venv/bin/activate

# Load environment variables
export $(cat ../.env | grep -v '^#' | xargs)

# Start dashboard
streamlit run dashboard.py
```

Open http://localhost:8501

### Dashboard Features

- **Overview Tab**: Vulnerability statistics and severity distribution
- **Risk Analysis Tab**: Comprehensive risk metrics and top risky dependencies
- **Dependency Graph Tab**: Visual graph of dependencies and vulnerabilities
- **CVE Lookup Tab**: Detailed CVE information from NVD
- **AI Chat Tab**: Interactive chat with LLM agent

## Troubleshooting

### Neo4j Connection Failed

```bash
# Check if Neo4j is running
docker ps | grep neo4j

# Check logs
docker logs neo4j

# Test connection
python verify_neo4j.py
```

### Scanner Container Not Found

```bash
# Rebuild the container
cd version-scanner-odc
./build.sh osx  # or linux
```

### Import Script Errors

```bash
# Check if ODC reports exist
ls -la java-project/module1/target/dependency-check-report/

# Run import with verbose output
python import_odc_to_neo4j.py \
  --target-dir ../version-scanner-odc/java-project \
  --project MY_PROJECT 2>&1 | tee import.log
```

### LLM Agent Not Working

```bash
# Check environment variables
echo $LLM_BASE_URL
echo $LLM_MODEL

# For Ollama, check if it's running
curl http://localhost:11434/api/tags

# Test tool calls directly
python test_tools.py
```

### Tools Import Error

If you get import errors in `test_tools.py`:

```bash
# Make sure you're in the right directory
cd rag_graphdb

# Check if mcp_agent is accessible
ls -la ../mcp_agent/tools.py

# Run with explicit path
python test_tools.py
```

## Next Steps

Now that everything is set up:

1. **Scan your own projects**: Replace `java-project` with your project path
2. **Explore queries**: Check `mcp_agent/prompt.neo4j.md` for query examples
3. **Customize tools**: Add your own tools in `mcp_agent/tools.py`
4. **Integrate with CI/CD**: Automate scans and imports
5. **Create reports**: Use the dashboard or agent to generate security reports

## Additional Resources

- [README.md](README.md) - Full project documentation
- [rag_graphdb/.docs/plan1.md](rag_graphdb/.docs/plan1.md) - Neo4j schema design
- [mcp_agent/prompt.neo4j.md](mcp_agent/prompt.neo4j.md) - Query guide for LLM
- [version-scanner-odc/README.md](version-scanner-odc/README.md) - Scanner details

## Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Review error messages carefully
3. Check Neo4j Browser for data issues
4. Test tools individually with `test_tools.py`
5. Open an issue on GitHub with:
   - Error messages
   - Steps to reproduce
   - Your environment (OS, Python version, etc.)

Happy analyzing! 🚀

