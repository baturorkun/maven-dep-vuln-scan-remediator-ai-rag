# Quick Reference Guide

## Common Commands Cheat Sheet

### Setup & Installation

```bash
# Run automated setup
./setup.sh

# Manual Neo4j setup (Docker)
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password neo4j:latest

# Manual Ollama setup
brew install ollama
ollama serve
ollama pull qwen3:8b
```

### Scanning Projects

```bash
cd version-scanner-odc

# Initialize OWASP database (first time only)
./get-odc-data.sh

# Build scanner container
./build.sh osx  # or: ./build.sh linux

# Scan a project (macOS)
docker run --rm \
  -v "$(pwd):/app" \
  -v "$(pwd)/version-scanner-odc.py:/scanner/version-scanner-odc.py" \
  -v "$(pwd)/remediation.py:/scanner/remediation.py" \
  version-scanner-odc:odc-arm64 \
  --target-dir /app/java-project \
  --remediation \
  --transitive

# Scan a project (Linux)
docker run --rm \
  -v "$(pwd):/app" \
  -v "$(pwd)/version-scanner-odc.py:/scanner/version-scanner-odc.py" \
  -v "$(pwd)/remediation.py:/scanner/remediation.py" \
  version-scanner-odc:odc-amd64 \
  --target-dir /app/java-project \
  --remediation \
  --transitive
```

### Neo4j Operations

```bash
cd rag_graphdb
source venv/bin/activate

# Set environment variables
export $(cat ../.env | grep -v '^#' | xargs)

# Verify Neo4j connection
python verify_neo4j.py

# Import scan results
python import_odc_to_neo4j.py \
  --target-dir ../version-scanner-odc/java-project \
  --project MY_PROJECT

# Import with custom Neo4j settings
python import_odc_to_neo4j.py \
  --target-dir /path/to/project \
  --project PROJECT_CODE \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password mypassword
```

### Testing

```bash
cd rag_graphdb
source venv/bin/activate

# Test all tools
python test_tools.py

# Test specific tool
python -c "
import sys
sys.path.insert(0, '../mcp_agent')
from tools import analyze_risk_statistics
print(analyze_risk_statistics())
"
```

### AI Agent

```bash
cd mcp_agent
source venv/bin/activate

# Set environment variables
export $(cat ../.env | grep -v '^#' | xargs)

# Start interactive agent
python agent.py

# Example questions:
# - What are the top 10 riskiest dependencies?
# - Which dependencies have CRITICAL vulnerabilities?
# - Show me direct dependencies with available fixes
# - What is the upgrade path for log4j-core?
```

### Dashboard

```bash
cd mcp_agent
source venv/bin/activate

# Set environment variables
export $(cat ../.env | grep -v '^#' | xargs)

# Start dashboard
streamlit run dashboard.py

# Open browser at: http://localhost:8501
```

## Useful Neo4j Queries

### In Neo4j Browser (http://localhost:7474)

```cypher
// Show schema
CALL db.schema.visualization()

// Count all nodes by type
MATCH (n)
RETURN labels(n)[0] as NodeType, count(*) as Count
ORDER BY Count DESC

// Count all relationships by type
MATCH ()-[r]->()
RETURN type(r) as RelType, count(*) as Count
ORDER BY Count DESC

// Find CRITICAL vulnerabilities
MATCH (d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability {severity: 'CRITICAL'})
RETURN d.groupId, d.artifactId, v.name, v.cvssScore
ORDER BY v.cvssScore DESC

// Find direct dependencies with remediations
MATCH (d:Dependency {isDirectDependency: true, hasRemediation: true})
  -[:RECOMMENDED_VERSION]->(rec:ArtifactVersion)
RETURN d.groupId + ':' + d.artifactId as dependency,
       d.detectedVersion as current,
       rec.version as recommended

// Get project overview
MATCH (p:Project)-[:HAS_MODULE]->(m:Module)-[:USES_DEPENDENCY]->(d:Dependency)
OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN p.name as project,
       m.name as module,
       count(DISTINCT d) as dependencies,
       count(DISTINCT v) as vulnerabilities

// Find upgrade path for a dependency
MATCH path = (cv:ArtifactVersion {version: '2.14.1'})
  -[:UPGRADES_TO*]->(rv:ArtifactVersion)
WHERE cv.aid = 'log4j-core'
RETURN path
LIMIT 1

// Top 10 dependencies by vulnerability count
MATCH (d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH d, count(v) as vulnCount
RETURN d.groupId + ':' + d.artifactId as dependency,
       d.detectedVersion,
       vulnCount
ORDER BY vulnCount DESC
LIMIT 10

// Dependencies without any vulnerabilities
MATCH (d:Dependency)
WHERE NOT (d)-[:HAS_VULNERABILITY]->()
RETURN d.groupId + ':' + d.artifactId as dependency,
       d.detectedVersion,
       d.isDirectDependency
ORDER BY d.groupId, d.artifactId

// Severity distribution
MATCH (v:Vulnerability)
RETURN v.severity, count(*) as count
ORDER BY count DESC

// Average CVSS score by severity
MATCH (v:Vulnerability)
WHERE v.cvssScore IS NOT NULL
RETURN v.severity,
       avg(v.cvssScore) as avgScore,
       max(v.cvssScore) as maxScore,
       count(*) as count
ORDER BY avgScore DESC
```

## Environment Variables

```bash
# Required for Neo4j
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your_password"

# Required for LLM Agent
export LLM_BASE_URL="http://localhost:11434/v1"  # or your endpoint
export LLM_MODEL="qwen3:8b"                      # or your model
export LLM_API_KEY="sk-xxx"                      # optional

# Quick way to load from .env
export $(cat .env | grep -v '^#' | xargs)
```

## Troubleshooting Commands

```bash
# Check Neo4j connection
curl http://localhost:7474

# Check if Neo4j accepts connections
nc -zv localhost 7687

# Check Ollama
curl http://localhost:11434/api/tags

# List Docker containers
docker ps -a

# Check Neo4j logs
docker logs neo4j

# Restart Neo4j
docker restart neo4j

# Check Python version
python3 --version

# Check if virtual environment is activated
which python  # Should show path with 'venv'

# List installed packages
pip list

# Test import
python -c "from neo4j import GraphDatabase; print('OK')"
```

## File Locations

```
# ODC Reports (after scan)
version-scanner-odc/java-project/module1/target/
  ├── dependency-check-report/dependency-check-report.json
  ├── dependency-graph.graphml
  └── remediation.json

# Configuration
.env                           # Your settings (create from .env.example)
.env.example                   # Template

# Documentation
README.md                      # Main documentation
GETTING_STARTED.md            # Step-by-step guide
IMPLEMENTATION_STATUS.md       # Project status
QUICK_REFERENCE.md            # This file

# Main Scripts
rag_graphdb/import_odc_to_neo4j.py    # Import to Neo4j
rag_graphdb/verify_neo4j.py           # Test connection
rag_graphdb/test_tools.py             # Test MCP tools
mcp_agent/agent.py                    # LLM agent
mcp_agent/server.py                   # MCP server
mcp_agent/dashboard.py                # Web UI
version-scanner-odc/version-scanner-odc.py  # Scanner
```

## Quick Workflow

```bash
# 1. Setup (once)
./setup.sh

# 2. Configure
cp .env.example .env
vim .env  # Edit your settings

# 3. Scan
cd version-scanner-odc
docker run --rm -v "$(pwd):/app" version-scanner-odc:odc-arm64 \
  --target-dir /app/your-project --remediation --transitive

# 4. Import
cd ../rag_graphdb
source venv/bin/activate
export $(cat ../.env | grep -v '^#' | xargs)
python import_odc_to_neo4j.py --target-dir ../version-scanner-odc/your-project --project YOUR_PROJECT

# 5. Analyze
python test_tools.py  # Test
cd ../mcp_agent
python agent.py       # Chat
# OR
streamlit run dashboard.py  # Dashboard
```

## Common Agent Questions

```
What are the top 10 riskiest dependencies?
Which dependencies have CRITICAL vulnerabilities?
Show me all direct dependencies with available fixes
What is the recommended version for jackson-databind?
How many vulnerabilities does log4j-core have?
Which modules use spring-webmvc?
What's the upgrade path from version X to version Y?
List all dependencies without any vulnerabilities
Show me the severity distribution of vulnerabilities
Which dependencies are used across multiple modules?
```

## Keyboard Shortcuts

### Agent
- `Ctrl+C` - Interrupt current operation
- `clear` - Clear conversation history
- `quit` - Exit agent

### Dashboard
- `Ctrl+C` - Stop server
- `R` - Refresh page (in browser)

### Terminal
- `Ctrl+Z` then `bg` - Background process
- `fg` - Bring to foreground
- `jobs` - List background jobs

---

**Need help?** Check GETTING_STARTED.md or open an issue on GitHub.

