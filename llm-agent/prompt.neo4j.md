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

### Pattern 2: Finding Dependencies with a Remediation AND Showing the Recommended Version

**User Question:** "Which root dependencies have a remediation, and what is the recommended version?"

**Correct Cypher Query:**
```cypher
// IMPORTANT: To get the remediation version string, you MUST follow the [:RECOMMENDED_VERSION] relationship.
// The version number is on the connected ArtifactVersion node.
MATCH (d:Dependency {isDirectDependency: true, hasRemediation: true})-[:RECOMMENDED_VERSION]->(rec:ArtifactVersion)
RETURN d.groupId, d.artifactId, d.detectedVersion, rec.version AS remediationVersion
```

### Pattern 3: Listing All Remediations

**User Question:** "List our remediations" or "Show me all remediations" or "What remediations are available?"

**Correct Cypher Query:**
```cypher
// To list all remediations, find dependencies with hasRemediation:true
// and follow the [:RECOMMENDED_VERSION] relationship to get the version string
MATCH (d:Dependency {hasRemediation: true})-[:RECOMMENDED_VERSION]->(rec:ArtifactVersion)
RETURN d.groupId, d.artifactId, d.detectedVersion AS currentVersion, rec.version AS remediationVersion
ORDER BY d.groupId, d.artifactId
```

### Pattern 4: Finding Dependencies Without a Remediation

**User Question:** "Which dependencies have no fix available?"
**Correct Cypher Query:**
```cypher
MATCH (d:Dependency {hasRemediation: false})
RETURN d.groupId, d.artifactId, d.detectedVersion
```

### Pattern 5: Querying Phantom/Starter Dependencies and Their Transitive Dependencies

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

