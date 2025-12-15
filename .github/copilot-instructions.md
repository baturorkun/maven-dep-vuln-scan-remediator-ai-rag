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

## CVE Lookup Configuration
- **CVE_LOOKUP_ONLINE**: Controls whether to use NVD API as fallback when CVE is not found in local H2 database
  - `false` (default): Offline only - returns error if CVE not in local database (for air-gapped environments)
  - `true`: Falls back to NVD API (https://services.nvd.nist.gov) when CVE not found locally
  ```bash
  export CVE_LOOKUP_ONLINE=false  # Default: offline only
  export CVE_LOOKUP_ONLINE=true   # Enable NVD API fallback
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
- **CVE Lookup**: Uses OWASP Dependency Check's offline H2 database (NVD mirror)
  - Database location: `version-scanner-odc/odc-data/odc.mv.db`
  - Database credentials: `sa` / `password`
  - No internet required for CVE enrichment
  - H2 JDBC driver used via JayDeBeApi

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
./venv/bin/python3 -c "from tools import get_remediation_suggestions; print(get_remediation_suggestions('java-project'))"
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

### LLM Not Using Remediation Tool
If LLM doesn't use `get_remediation_suggestions` for remediation queries:
1. Check that tool is registered in `server.py` (should be there)
2. Restart the MCP server or Streamlit dashboard
3. Try specific queries like: "Give me remediation suggestions for java-project"
4. Verify Neo4j has remediation data: 
   ```cypher
   MATCH (d:Dependency)-[:RECOMMENDED_VERSION]->(v) RETURN count(d)
   ```

## LLM Agent Tools (tools.py)

**All tools below are registered in MCP server (`server.py`) and available to LLM agents.**

| Tool | Description |
|------|-------------|
| `list_projects()` | List all projects with vulnerability summary |
| `analyze_risk_statistics()` | Comprehensive risk analysis |
| `get_dependency_tree(name)` | Get dependency tree for project/module/artifact |
| `get_remediation_suggestions(project_name)` | **Get upgrade recommendations for vulnerable dependencies** - Returns current version, recommended version, CVE count, severity, and upgrade path |
| `diagnose_graph_relationships()` | Debug database structure |
| `read_neo4j_query(cypher)` | Run custom Cypher query |
| `visualize_dependency_graph(limit, output_file, artifact_name)` | Generate PNG visualization. If artifact_name provided, creates transitive tree for that artifact |
| `enrich_cve_data(cve_id)` | Fetch CVE details from NVD (requires internet) |

### Remediation Suggestions

**LLM Queries that trigger this tool:**
- "Give me remediation suggestions"
- "What are the recommended version upgrades?"
- "Show me upgrade recommendations"
- "How can I fix these vulnerabilities?"
- "Give me remediation for java-project"

**Usage:**
```python
# Get remediation suggestions for all projects
get_remediation_suggestions()

# Get remediation suggestions for specific project
get_remediation_suggestions('java-project')
```

**Example Response:**
```json
{
  "success": true,
  "project": "java-project",
  "remediation_count": 14,
  "suggestions": [
    {
      "artifact": "com.fasterxml.jackson.core:jackson-databind",
      "current_version": "2.9.8",
      "recommended_version": "2.16.0",
      "vulnerability_count": 54,
      "highest_severity": "CRITICAL",
      "upgrade_path": []
    },
    {
      "artifact": "org.apache.logging.log4j:log4j-core",
      "current_version": "2.14.1",
      "recommended_version": "2.17.1",
      "vulnerability_count": 4,
      "highest_severity": "CRITICAL",
      "upgrade_path": ["2.15.0", "2.16.0", "2.17.0"]
    }
  ]
}
```

The tool:
- ✅ Retrieves recommendations from Neo4j (RECOMMENDED_VERSION relationship)
- ✅ Shows current version and recommended safe version
- ✅ Includes CVE count and highest severity
- ✅ Provides upgrade path when available (via UPGRADES_TO relationships)
- ✅ Sorted by vulnerability count (most critical first)

### Viewing Generated PNG Files

When `visualize_dependency_graph()` is called, it creates a PNG file (default: `dependency_graph.png`).

**Two modes:**
1. **Vulnerability Graph** (default): Top vulnerable dependencies
2. **Transitive Tree** (with artifact_name): Dependency tree for specific artifact

**Option 1: Streamlit Dashboard (Recommended)**
```bash
cd llm-agent
./run.sh
```
Go to "🌐 Dependency Graph" tab:
- **Left panel**: 
  - Click "Generate Graph" to create `dependency_graph.png`
  - Browse all saved PNG graphs (auto-refreshed on every tab switch)
  - Click on any graph to view it
  - Shows: filename, date, time (HH:MM format)
  - Selected graph is marked with ✅
- **Right panel**: 
  - View selected graph (full size)
  - File metadata (size, creation time)
  - Download button available

**Option 2: Open directly on Mac**
```bash
open llm-agent/dependency_graph.png
```

**Option 3: Generate transitive tree for specific artifact**
```bash
cd llm-agent
./venv/bin/python3 -c "from tools import visualize_dependency_graph; visualize_dependency_graph(artifact_name='jackson-databind', output_file='jackson_tree.png')"
open jackson_tree.png
```

**Examples:**
```python
# Vulnerability graph (default)
visualize_dependency_graph(limit=20)

# Transitive tree for jackson-databind (Neo4j Browser style)
visualize_dependency_graph(artifact_name='jackson-databind', output_file='jackson_tree.png')

# Transitive tree for log4j
visualize_dependency_graph(artifact_name='log4j', output_file='log4j_tree.png')
```

**Graph Features:**
- **Professional light theme** - White background with black text for better readability
- **CVE Information** - Each node shows CVE count (e.g., "jackson-databind\n(54 CVEs)")
- **Larger canvas** - 24x18 inches for better detail visibility
- **Bigger nodes** - 4500 size units with no borders for maximum text clarity
- **Font size 16** - Large, bold black labels for maximum readability
- **High DPI** - 200 DPI output for crisp, clear images
- **Bootstrap-inspired color palette** (professional and accessible):
  - 🔴 #DC3545 - CRITICAL (Bootstrap Danger Red)
  - 🟠 #FD7E14 - HIGH (Bootstrap Orange)
  - 🟡 #FFC107 - MEDIUM (Bootstrap Warning Yellow)
  - 🟢 #28A745 - LOW (Bootstrap Success Green)
  - 🔵 #17A2B8 - No Vulnerabilities (Bootstrap Info Blue)
- **Clean design** - White background, no borders, professional appearance
- **Thicker edges** - 3px gray edges with curved style
- **Complete legend** - Shows all severity levels and DEPENDS_ON relationship

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
