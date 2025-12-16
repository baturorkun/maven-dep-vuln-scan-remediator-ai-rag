# LLM Prompt Guide for Neo4j Schema

This document is the primary source of truth for generating Cypher queries. You MUST adhere to the rules and patterns described here.

## 1. CRITICAL QUERYING RULES

Your primary directive is to generate accurate Cypher queries based on the user's request and the schema described below. You MUST follow these rules without exception.

### RULE #1: Identifying "Root" or "Direct" Dependencies
This is the most important rule.

- **IF** the user asks for "root dependencies", "direct dependencies", or "pom dependencies",
- **THEN** you **MUST** filter the `Dependency` node by its property: `{isDirectDependency: true}`.

**This is the ONLY correct way.**

- **DO NOT** try to guess or infer a root dependency by checking for the absence of a `:DEPENDS_ON` relationship. This is **STRICTLY FORBIDDEN** as it produces incorrect results.

### RULE #2: Identifying Dependencies With or Without a Remediation

- **To find dependencies with a remediation:** You **MUST** use the filter `{hasRemediation: true}`.
- **To find dependencies without a remediation:** You **MUST** use the filter `{hasRemediation: false}`.

---

## 2. NEO4J SCHEMA REFERENCE

### Node Labels & Key Properties

-   `Project`: Represents a top-level project (e.g., a multi-module Maven project).
    -   `name`: (string) The project name/identifier.
    -   `updated`: (datetime) Last update timestamp.
-   `Module`: Represents a module within a project.
    -   `id`: (string) Unique identifier in format "projectName:moduleName".
    -   `name`: (string) The module name.
    -   `project`: (string) The parent project name.
-   `Dependency`: Represents a library.
    -   `groupId`: (string) The Maven groupId.
    -   `artifactId`: (string) The Maven artifactId.
    -   `detectedVersion`: (string) The current version in use.
    -   `isDirectDependency`: (boolean) **SEE RULE #1**. `true` if it's a root dependency.
    -   `hasRemediation`: (boolean) **SEE RULE #2**. `true` if a safe upgrade version is available.
    -   `isPhantomDependency`: (boolean) `true` for BOM/starter packages that don't produce jar files (e.g., spring-boot-starter-web). These are declared in pom.xml but have no vulnerabilities tracked.
    -   `usedByProjects`: (list) Array of project names using this dependency.
    -   `usedByModules`: (list) Array of module names using this dependency.
-   `ArtifactVersion`: Represents a specific version of a library.
    -   `version`: (string) The version number (e.g., "2.17.1").
    -   `majorVersion`: (integer) Major version number.
    -   `minorVersion`: (integer) Minor version number.
    -   `patchVersion`: (integer) Patch version number.
    -   `hasCVE`: (boolean) `true` if this version has known vulnerabilities.
    -   `cveCount`: (integer) Count of known vulnerabilities for this version.
-   `Vulnerability`: A known CVE.
    -   `name`: (string) CVE identifier (e.g., "CVE-2024-1234").
    -   `severity`: (string) e.g., "CRITICAL", "HIGH", "MEDIUM", "LOW".
    -   `cvssScore`: (float) CVSS score.

### Relationship Types

-   `(Project)-[:HAS_MODULE]->(Module)`: A project contains modules.
-   `(Module)-[:USES_DEPENDENCY]->(Dependency)`
-   `(Dependency)-[:HAS_VULNERABILITY]->(Vulnerability)`
-   `(Dependency)-[:DEPENDS_ON]->(Dependency)`: Transitive dependency relationship.
-   `(Dependency)-[:RECOMMENDED_VERSION]->(ArtifactVersion)`: **IMPORTANT!** This links a dependency to the `ArtifactVersion` node that holds the recommended version string.
-   `(Dependency)-[:CURRENT_VERSION]->(ArtifactVersion)`

---

## 3. COMMON QUERY PATTERNS & EXAMPLES

### Pattern 0: Listing All Projects and Modules

**User Question:** "What are my projects?", "List projects", "Show me all projects", "What projects do I have?"
**Correct Cypher Query:**
```cypher
// List all projects with their modules
MATCH (p:Project)
OPTIONAL MATCH (p)-[:HAS_MODULE]->(m:Module)
RETURN p.name AS project, collect(m.name) AS modules
ORDER BY p.name
```

**User Question:** "What modules are in project X?"
**Correct Cypher Query:**
```cypher
MATCH (p:Project {name: 'X'})-[:HAS_MODULE]->(m:Module)
RETURN m.name AS module, m.id AS moduleId
```

**User Question:** "Which project has the most vulnerabilities?"
**Correct Cypher Query:**
```cypher
// Count vulnerabilities per project by traversing Project -> Module -> Dependency -> Vulnerability
MATCH (p:Project)-[:HAS_MODULE]->(m:Module)-[:USES_DEPENDENCY]->(d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN p.name AS project, 
       count(DISTINCT v) AS vulnerabilityCount,
       count(DISTINCT d) AS affectedDependencies
ORDER BY vulnerabilityCount DESC
```

**User Question:** "Which project has the most remediations available?" or "Show remediation status per project"
**Correct Cypher Query:**
```cypher
// Count remediations per project
MATCH (p:Project)-[:HAS_MODULE]->(m:Module)-[:USES_DEPENDENCY]->(d:Dependency)
WHERE d.hasRemediation = true
OPTIONAL MATCH (d)-[:RECOMMENDED_VERSION]->(rec:ArtifactVersion)
RETURN p.name AS project,
       count(DISTINCT d) AS dependenciesWithRemediation,
       collect(DISTINCT {artifact: d.groupId + ':' + d.artifactId, from: d.detectedVersion, to: rec.version})[0..5] AS sampleRemediations
ORDER BY dependenciesWithRemediation DESC
```

**User Question:** "Show me a summary of vulnerabilities and remediations for each project"
**Correct Cypher Query:**
```cypher
// Full project vulnerability and remediation summary
// NOTE: remediationCoverage = % of vulnerable dependencies that have a remediation
MATCH (p:Project)-[:HAS_MODULE]->(m:Module)-[:USES_DEPENDENCY]->(d:Dependency)
OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH p, d, count(v) as vulnCountPerDep
WITH p,
     count(DISTINCT d) AS totalDeps,
     count(DISTINCT CASE WHEN vulnCountPerDep > 0 THEN d END) AS depsWithVulnerabilities,
     count(DISTINCT CASE WHEN vulnCountPerDep > 0 AND d.hasRemediation = true THEN d END) AS depsWithRemediations
RETURN p.name AS project,
       totalDeps AS totalDependencies,
       depsWithVulnerabilities AS vulnerableDependencies,
       depsWithRemediations AS remediationsAvailable,
       round(depsWithRemediations * 100.0 / CASE WHEN depsWithVulnerabilities = 0 THEN 1 ELSE depsWithVulnerabilities END, 1) AS remediationCoveragePercent
ORDER BY depsWithVulnerabilities DESC
```

### Pattern 1: Finding Root Dependencies

**User Question:** "What are the root dependencies in each module?"
**Correct Cypher Query:**
```cypher
// To find "root" dependencies, the filter {isDirectDependency: true} is MANDATORY.
MATCH (m:Module)-[:USES_DEPENDENCY]->(d:Dependency {isDirectDependency: true})
RETURN m.name AS module, d.artifactId, d.detectedVersion
```

### Pattern 2: Listing Direct Dependencies with Safety Status

**User Question:** "Show me all direct dependencies" or "What are my root dependencies?" or "Show safe versions of direct dependencies"

**Tool to Use:** `list_direct_dependencies(project_name="myproject")`

This tool shows ALL direct dependencies (both safe and vulnerable) with their:
- Current version
- Vulnerability count
- Safety status (SAFE/VULNERABLE)
- Recommended version (if vulnerable and remediation available)

**NOTE:** This is different from `get_remediation_suggestions()` which only shows vulnerable dependencies with remediations.

### Pattern 3: Finding Dependencies with a Remediation AND Showing the Recommended Version

**User Question:** "Which root dependencies have a remediation, and what is the recommended version?"

**Correct Cypher Query:**
```cypher
// IMPORTANT: To get the remediation version string, you MUST follow the [:RECOMMENDED_VERSION] relationship.
// The version number is on the connected ArtifactVersion node.
MATCH (d:Dependency {isDirectDependency: true, hasRemediation: true})-[:RECOMMENDED_VERSION]->(rec:ArtifactVersion)
RETURN d.groupId, d.artifactId, d.detectedVersion, rec.version AS remediationVersion
```

### Pattern 4: Listing All Remediations

**User Question:** "List our remediations" or "Show me all remediations" or "What remediations are available?"

**Correct Cypher Query:**
```cypher
// To list all remediations, find dependencies with hasRemediation:true
// and follow the [:RECOMMENDED_VERSION] relationship to get the version string
MATCH (d:Dependency {hasRemediation: true})-[:RECOMMENDED_VERSION]->(rec:ArtifactVersion)
RETURN d.groupId, d.artifactId, d.detectedVersion AS currentVersion, rec.version AS remediationVersion
ORDER BY d.groupId, d.artifactId
```

### Pattern 5: Finding Dependencies Without a Remediation

**User Question:** "Which dependencies have no fix available?"
**Correct Cypher Query:**
```cypher
MATCH (d:Dependency {hasRemediation: false})
RETURN d.groupId, d.artifactId, d.detectedVersion
```

### Pattern 6: Querying Phantom/Starter Dependencies and Their Transitive Dependencies

**User Question:** "List sub dependencies of spring-boot-starter-web" or "What are the transitive dependencies of [starter-name]?"
**Correct Cypher Query:**
```cypher
// Phantom dependencies (like spring-boot-starter-web) are BOM/starter packages
// They link to their transitive dependencies via DEPENDS_ON
MATCH (starter:Dependency {isPhantomDependency: true})
WHERE starter.artifactId CONTAINS 'spring-boot-starter-web'
OPTIONAL MATCH (starter)-[:DEPENDS_ON]->(transitive:Dependency)
RETURN starter.artifactId AS starter,
       starter.detectedVersion AS version,
       collect(transitive.groupId + ':' + transitive.artifactId) AS transitiveDependencies
```

**User Question:** "Show all phantom/starter dependencies"
**Correct Cypher Query:**
```cypher
// List all BOM/starter packages that don't produce jar files
MATCH (d:Dependency {isPhantomDependency: true})
OPTIONAL MATCH (d)-[:DEPENDS_ON]->(t:Dependency)
RETURN d.groupId + ':' + d.artifactId AS phantom,
       d.detectedVersion AS version,
       count(t) AS linkedDependencies
ORDER BY linkedDependencies DESC
```

**User Question:** "Which starter brings in vulnerable dependencies?"
**Correct Cypher Query:**
```cypher
// Find phantom starters that have vulnerable transitive dependencies
MATCH (starter:Dependency {isPhantomDependency: true})-[:DEPENDS_ON]->(d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN starter.artifactId AS starter,
       d.groupId + ':' + d.artifactId AS vulnerableDependency,
       count(v) AS vulnerabilityCount,
       collect(DISTINCT v.severity) AS severities
ORDER BY vulnerabilityCount DESC
```

### Pattern 7: Transitive Dependency Tree Queries (CRITICAL FOR TREE EXTRACTION)

**User Question:** "Show me the dependency tree of jackson-databind" or "What are the transitive dependencies of X?"
**Correct Cypher Query:**
```cypher
// Get full transitive dependency tree for a specific artifact
// Uses variable-length path pattern [:DEPENDS_ON*1..5] for depth control
MATCH path = (root:Dependency)-[:DEPENDS_ON*1..5]->(child:Dependency)
WHERE root.artifactId CONTAINS 'jackson-databind'
WITH root, child, length(path) AS depth,
     [node IN nodes(path) | node.groupId + ':' + node.artifactId + ':' + COALESCE(node.detectedVersion, 'unknown')] AS fullPath
RETURN root.groupId + ':' + root.artifactId AS rootDependency,
       child.groupId + ':' + child.artifactId AS transitiveDependency,
       child.detectedVersion AS version,
       depth,
       fullPath
ORDER BY depth, transitiveDependency
```

**User Question:** "Show me all direct dependencies and their transitive tree"
**Correct Cypher Query:**
```cypher
// Get dependency tree starting from direct dependencies
MATCH (direct:Dependency {isDirectDependency: true})
OPTIONAL MATCH path = (direct)-[:DEPENDS_ON*1..4]->(transitive:Dependency)
WITH direct, 
     collect(DISTINCT {
       artifact: transitive.groupId + ':' + transitive.artifactId,
       version: transitive.detectedVersion,
       depth: length(path)
     }) AS transitives
RETURN direct.groupId + ':' + direct.artifactId AS directDependency,
       direct.detectedVersion AS version,
       size(transitives) AS transitiveCount,
       transitives[0..10] AS sampleTransitives
ORDER BY transitiveCount DESC
```

**User Question:** "Which dependencies depend on log4j?" or "What uses X?" (Reverse tree)
**Correct Cypher Query:**
```cypher
// Find all dependencies that DEPEND ON a specific library (reverse lookup)
MATCH path = (parent:Dependency)-[:DEPENDS_ON*1..5]->(target:Dependency)
WHERE target.artifactId CONTAINS 'log4j' OR target.groupId CONTAINS 'log4j'
WITH parent, target, length(path) AS depth,
     [node IN nodes(path) | node.groupId + ':' + node.artifactId] AS dependencyChain
RETURN parent.groupId + ':' + parent.artifactId AS dependsOnTarget,
       parent.isDirectDependency AS isDirect,
       target.groupId + ':' + target.artifactId AS targetLibrary,
       depth,
       dependencyChain
ORDER BY depth, dependsOnTarget
```

**User Question:** "Show full dependency tree with vulnerabilities"
**Correct Cypher Query:**
```cypher
// Get dependency tree with vulnerability information at each level
MATCH (direct:Dependency {isDirectDependency: true})
OPTIONAL MATCH path = (direct)-[:DEPENDS_ON*0..4]->(dep:Dependency)
OPTIONAL MATCH (dep)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH direct, dep, length(path) AS depth, collect(DISTINCT v.name) AS cves, collect(DISTINCT v.severity) AS severities
WHERE dep IS NOT NULL
RETURN direct.groupId + ':' + direct.artifactId AS rootDependency,
       dep.groupId + ':' + dep.artifactId AS dependency,
       dep.detectedVersion AS version,
       depth,
       size(cves) AS cveCount,
       cves[0..3] AS sampleCVEs,
       severities
ORDER BY direct.artifactId, depth
```

**User Question:** "What is the maximum depth of transitive dependencies?"
**Correct Cypher Query:**
```cypher
// Analyze transitive dependency depth statistics
MATCH path = (direct:Dependency {isDirectDependency: true})-[:DEPENDS_ON*]->(trans:Dependency)
WITH direct, max(length(path)) AS maxDepth, count(DISTINCT trans) AS transitiveCount
RETURN direct.groupId + ':' + direct.artifactId AS directDependency,
       maxDepth,
       transitiveCount
ORDER BY maxDepth DESC, transitiveCount DESC
LIMIT 20
```

**User Question:** "List all DEPENDS_ON relationships" or "Show transitive edges"
**Correct Cypher Query:**
```cypher
// Get all DEPENDS_ON relationships (edges)
MATCH (parent:Dependency)-[:DEPENDS_ON]->(child:Dependency)
RETURN parent.groupId + ':' + parent.artifactId AS parent,
       parent.detectedVersion AS parentVersion,
       child.groupId + ':' + child.artifactId AS child,
       child.detectedVersion AS childVersion
ORDER BY parent, child
LIMIT 100
```

### Pattern 8: Debugging DEPENDS_ON Relationships

**User Question:** "Are there any DEPENDS_ON relationships?" or "Check transitive data"
**Correct Cypher Query:**
```cypher
// Check if DEPENDS_ON relationships exist and count them
MATCH ()-[r:DEPENDS_ON]->()
RETURN count(r) AS totalDependsOnRelationships
```

**User Question:** "Show sample transitive dependency chains"
**Correct Cypher Query:**
```cypher
// Sample some DEPENDS_ON chains for debugging
MATCH (a:Dependency)-[r:DEPENDS_ON]->(b:Dependency)
RETURN a.groupId + ':' + a.artifactId AS from,
       a.detectedVersion AS fromVersion,
       b.groupId + ':' + b.artifactId AS to,
       b.detectedVersion AS toVersion
LIMIT 20
```

