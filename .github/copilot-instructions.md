# Project Instructions for GitHub Copilot

## Project Overview
This project is a DevSecOps platform for analyzing OWASP Dependency-Check reports
and storing them in Neo4j for graph-based vulnerability analysis for LLM agent tools.

## Tech Stack
- Mac OS X
- Python 3.13
- Neo4j 5.x (Community Edition, running via Podman)
- Streamlit (for dashboard)
- Podman (Docker alternative)
- OWASP Dependency-Check

## IMPORTANT: Python Virtual Environments
**Always use venv when running Python commands!** Each directory has its own venv:

```bash
# For data-ingestion scripts:
cd data-ingestion
./venv/bin/python3 script.py

# For llm-agent scripts:
cd llm-agent
./venv/bin/python3 script.py

# Or activate venv first:
source venv/bin/activate
python3 script.py
```

**DO NOT use system Python directly!** The required packages (neo4j, streamlit, etc.) are only installed in the venvs.

## Project Structure
```
├── data-ingestion/          # Neo4j import scripts
│   ├── import_odc_to_neo4j.py  # Main importer
│   └── requirements.txt
├── llm-agent/               # LLM Agent with MCP tools
│   ├── tools.py             # Tool implementations (Neo4j queries)
│   ├── server.py            # MCP server
│   ├── agent.py             # Agent logic
│   └── streamlit_agent.py   # Streamlit UI
├── version-scanner-odc/     # OWASP DC scanner Docker image
│   ├── java-project/        # Sample Maven project with 3 modules
│   │   ├── module1/, module2/, module3/
│   │   └── pom.xml
│   └── Dockerfile-odc
```

## Neo4j Configuration
- **URI**: bolt://localhost:7687
- **User**: neo4j
- **Password**: password (development only)
- **Environment Variables**:
  ```bash
  export NEO4J_URI=bolt://localhost:7687
  export NEO4J_USER=neo4j
  export NEO4J_PASSWORD=password
  ```

## Neo4j Graph Schema
```
(Project) -[:HAS_MODULE]-> (Module) -[:USES_DEPENDENCY]-> (Dependency)
(Dependency) -[:HAS_VULNERABILITY]-> (Vulnerability)
(Dependency) -[:DEPENDS_ON]-> (Dependency)  # Transitive dependencies
(Dependency) -[:CURRENT_VERSION]-> (ArtifactVersion)
(Dependency) -[:RECOMMENDED_VERSION]-> (ArtifactVersion)
(ArtifactVersion) -[:UPGRADES_TO]-> (ArtifactVersion)
```

### Key Node Properties
- **Dependency**: sha256, groupId, artifactId, detectedVersion, isDirectDependency, hasRemediation
- **Vulnerability**: name, severity, cvssScore, description
- **ArtifactVersion**: version, majorVersion, minorVersion, patchVersion, hasCVE

## Coding Rules
- Prefer clear, readable code over clever tricks
- Always add type hints in Python
- Do not hardcode credentials
- Use environment variables for configuration
- Use `json.dumps()` with `default=str` for Neo4j datetime serialization

## Security
- Assume air-gapped / offline environments
- Avoid external network calls unless explicitly stated
- NVD API calls are optional (enrich_cve_data tool)

## Output Expectations
- Provide production-ready code
- Include brief comments for complex logic
- Return JSON from all tool functions

## Testing

### Important Directories
There are 3 main directories, but 2 are most important:
1. **version-scanner-odc/** - OWASP Dependency Check scanner (Docker/Podman)
2. **data-ingestion/** - Neo4j import scripts (Docker/Podman)
3. **llm-agent/** - LLM Agent with MCP tools (local Python)

### First-Time Setup: Build Docker Images
Before running, build the container images:

```bash
# 1. Build version-scanner image (Mac/ARM64)
cd version-scanner-odc
./build.sh osx   # Creates: version-scanner:odc-arm64

# 2. Build data-ingestion image
cd data-ingestion
./build.sh       # Creates: data-ingestion
```

### Start Neo4j (required for all tests)
```bash
# Using Podman
podman run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5-community
```

---

### 1. Run OWASP Dependency Check Scanner
**Directory:** `version-scanner-odc/`

```bash
cd version-scanner-odc
./run.sh
```

**What run.sh does:**
```bash
podman run --rm \
  -v "$(pwd)":/app \
  -v "$(pwd)/.m2:/root/.m2" \
  -e ALLOW_MAJOR_UPGRADE=true \
  version-scanner:odc-arm64 \
  --target-dir /app/java-project --remediation --transitive
```

**Outputs:**
- `java-project/module*/target/dependency-check-report/` - ODC JSON/HTML reports
- `java-project/module*/target/dependency-graph.graphml` - Dependency tree
- `java-project/module*/target/remediation.json` - Version remediation suggestions

---

### 2. Import Data to Neo4j
**Directory:** `data-ingestion/`

```bash
cd data-ingestion
./run.sh
```

**What run.sh does:**
```bash
podman run \
  -v "$(pwd)/../version-scanner-odc":/app \
  data-ingestion \
  --target-dir /app/java-project --project "myproject"
```

**Expected output:**
```
✓ Created/updated Project: myproject
✓ Created X DEPENDS_ON relationships
✓ Import Complete
```

**Alternative (local Python, no Docker):**
```bash
cd data-ingestion
python3 import_odc_to_neo4j.py \
  --target-dir ../version-scanner-odc/java-project \
  --project java-project
```

---

### 3. Run LLM Agent Dashboard
**Directory:** `llm-agent/`

```bash
cd llm-agent
./run.sh
```

**What run.sh does:**
```bash
source .env
streamlit run dashboard.py
```

**Requires `.env` file with:**
```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
# OLLAMA_HOST=http://localhost:11434  # if using Ollama
```

---

### Test LLM Tools (without Streamlit)
```bash
cd llm-agent
./venv/bin/python3 -c "from tools import list_projects; print(list_projects())"
./venv/bin/python3 -c "from tools import diagnose_graph_relationships; print(diagnose_graph_relationships())"
./venv/bin/python3 -c "from tools import get_dependency_tree; print(get_dependency_tree('java-project'))"
```

### Verify Neo4j Data (Cypher Queries)
```cypher
// Count all nodes and relationships
MATCH (n) RETURN labels(n)[0] as label, count(n) as count

// Check DEPENDS_ON relationships
MATCH ()-[r:DEPENDS_ON]->() RETURN count(r)

// Sample transitive tree
MATCH path = (d:Dependency)-[:DEPENDS_ON*1..3]->(child)
WHERE d.artifactId = 'jackson-databind'
RETURN path LIMIT 10

// Projects with vulnerabilities
MATCH (p:Project)-[:HAS_MODULE]->(m:Module)-[:USES_DEPENDENCY]->(d:Dependency)-[:HAS_VULNERABILITY]->(v)
RETURN p.name, count(DISTINCT v) as vulns
ORDER BY vulns DESC
```

## Common Issues & Solutions

### ModuleNotFoundError: No module named 'neo4j'
**You're using system Python instead of venv!** Use:
```bash
cd data-ingestion
./venv/bin/python3 script.py
# NOT: python3 script.py
```

### Terminal Output Empty
If terminal commands return empty output, create a script file and run it:
```bash
python3 script.py > output.txt 2>&1 && cat output.txt
```

### DEPENDS_ON Relationships Missing
Re-run import with GraphML files present:
```bash
cd data-ingestion
python3 import_odc_to_neo4j.py --target-dir ../version-scanner-odc/java-project --project java-project
```
Expected output should show: `✓ Created X DEPENDS_ON relationships`

### Neo4j Connection Failed
Check if Neo4j is running:
```bash
podman ps | grep neo4j
# or
docker ps | grep neo4j
```

## LLM Agent Tools (tools.py)

| Tool | Description |
|------|-------------|
| `list_projects()` | List all projects with vulnerability summary |
| `analyze_risk_statistics()` | Comprehensive risk analysis |
| `get_dependency_tree(name)` | Get dependency tree for project/module/artifact |
| `diagnose_graph_relationships()` | Debug database structure |
| `read_neo4j_query(cypher)` | Run custom Cypher query |
| `visualize_dependency_graph()` | Generate PNG visualization |
| `enrich_cve_data(cve_id)` | Fetch CVE details from NVD (requires internet) |

### Viewing Generated PNG Files

When `visualize_dependency_graph()` is called, it creates a PNG file (default: `dependency_graph.png`).

**Option 1: Streamlit Dashboard (Recommended)**
```bash
cd llm-agent
./run.sh
```
Go to "🌐 Dependency Graph" tab → Click "Generate Graph" → View & Download

**Option 2: Open directly on Mac**
```bash
open llm-agent/dependency_graph.png
```

**Option 3: Manual generation and view**
```bash
cd llm-agent
./venv/bin/python3 -c "from tools import visualize_dependency_graph; print(visualize_dependency_graph())"
open dependency_graph.png
```

The PNG file is saved in the `llm-agent/` directory.

## Current Database State (After Import)

After running `import_odc_to_neo4j.py`, the database should contain:

### Expected Node/Relationship Counts
| Type | Expected Count |
|------|----------------|
| Project | 1 (java-project) |
| Module | 3 (module1, module2, module3) |
| Dependency | ~40-50 |
| Vulnerability | ~20-30 |
| DEPENDS_ON relationships | ~50 |
| HAS_VULNERABILITY relationships | ~30 |

### Sample Data Structure
```
java-project
├── module1
│   ├── log4j-core:2.14.1 (CRITICAL vulns)
│   ├── log4j-api:2.14.1
│   ├── jackson-databind:2.9.8 (HIGH vulns)
│   │   └── jackson-annotations:2.9.0 (transitive)
│   └── jackson-core:2.9.8
├── module2
│   ├── spring-core:5.0.0
│   │   └── spring-jcl (transitive)
│   ├── spring-web:5.0.0
│   ├── commons-beanutils:1.9.4
│   └── commons-collections:3.2.1 (CRITICAL vulns)
└── module3
    ├── struts2-core:2.3.20 (CRITICAL vulns, many transitives)
    ├── mysql-connector-java:5.1.40
    ├── httpclient:4.5.12
    └── log4j-api:2.14.1
```

## File Locations Reference

| Purpose | File Path |
|---------|-----------|
| Main importer | `data-ingestion/import_odc_to_neo4j.py` |
| LLM tools | `llm-agent/tools.py` |
| MCP server | `llm-agent/server.py` |
| Streamlit UI | `llm-agent/streamlit_agent.py` |
| Sample Java project | `version-scanner-odc/java-project/` |
| ODC reports | `version-scanner-odc/java-project/module*/target/dependency-check-report/` |
| GraphML files | `version-scanner-odc/java-project/module*/target/dependency-graph.graphml` |
| Remediation files | `version-scanner-odc/java-project/module*/target/remediation.json` |

## Quick Validation Commands

After making changes, run these to validate:

```bash
# 1. Check Python syntax
cd data-ingestion
./venv/bin/python3 -m py_compile import_odc_to_neo4j.py

# 2. Test basic import
cd llm-agent
./venv/bin/python3 -c "from tools import *; print('OK')"

# 3. Test Neo4j connection (requires running Neo4j)
cd data-ingestion
./venv/bin/python3 -c "
from neo4j import GraphDatabase
driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'password'))
driver.verify_connectivity()
print('Neo4j connection OK')
driver.close()
"

# 4. Run full Neo4j model test
cd data-ingestion
./venv/bin/python3 test_neo4j_model.py
```
