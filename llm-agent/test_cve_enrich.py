#!/usr/bin/env python3
"""
Quick test to find actual date column names in H2 database.
"""
import sys
sys.path.insert(0, '/Users/batur/Documents/Projects/github/maven-dep-vuln-scan-remediator-ai-rag/llm-agent')

from tools import enrich_cve_data
import json

print("Testing CVE enrichment with CVE-2021-44228 (Log4Shell)")
print("=" * 70)

result = enrich_cve_data("CVE-2021-44228")
data = json.loads(result)

if data.get("success"):
    print("✅ SUCCESS")
    print(f"\nCVE ID: {data.get('cve_id')}")
    print(f"Published: {data.get('published')}")
    print(f"Last Modified: {data.get('last_modified')}")
    print(f"Source: {data.get('source')}")
    print(f"\nDescription: {data.get('description', 'N/A')[:100]}...")

    if data.get('cvss_v3'):
        print(f"\nCVSS v3 Score: {data['cvss_v3']['score']}")
        print(f"CVSS v3 Severity: {data['cvss_v3']['severity']}")
    else:
        print("\n⚠️  CVSS v3: Not available")

    if data.get('cvss_v2'):
        print(f"\nCVSS v2 Score: {data['cvss_v2']['score']}")
    else:
        print("\n⚠️  CVSS v2: Not available")

    print(f"\nCWEs: {data.get('cwes', [])}")
    print(f"References: {len(data.get('references', []))} found")
else:
    print(f"❌ FAILED: {data.get('error')}")

