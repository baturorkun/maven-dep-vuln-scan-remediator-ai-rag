#!/usr/bin/env python3
"""
Check H2 database schema to find correct column names for VULNERABILITY table.
"""

import glob
import jaydebeapi
import os

def check_schema():
    # Try multiple possible database locations
    possible_db_paths = [
        "/odc-data/odc",
        "../version-scanner-odc/odc-data/odc",
        "/usr/share/dependency-check/data/odc",
    ]

    db_path = None
    for path in possible_db_paths:
        if os.path.exists(f"{path}.mv.db"):
            db_path = path
            break

    if not db_path:
        print("ERROR: H2 database not found!")
        return

    print(f"Using database: {db_path}.mv.db")

    # Find H2 driver
    h2_jar_paths = [
        "/opt/dependency-check/lib/h2-*.jar",
        "/usr/share/java/h2.jar",
        "../version-scanner-odc/h2-*.jar",
    ]

    h2_jar = None
    for pattern in h2_jar_paths:
        matches = glob.glob(pattern)
        if matches:
            h2_jar = matches[0]
            break

    if not h2_jar:
        print("ERROR: H2 jar not found!")
        return

    print(f"Using H2 driver: {h2_jar}\n")

    # Connect to database
    conn = jaydebeapi.connect(
        "org.h2.Driver",
        f"jdbc:h2:{db_path}",
        ["sa", "password"],
        h2_jar
    )

    cursor = conn.cursor()

    # Get VULNERABILITY table structure
    print("=== VULNERABILITY Table Columns ===")
    cursor.execute("""
        SELECT COLUMN_NAME, TYPE_NAME, COLUMN_SIZE, NULLABLE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = 'VULNERABILITY'
        ORDER BY ORDINAL_POSITION
    """)

    print(f"{'Column Name':<40} {'Type':<20} {'Nullable':<10}")
    print("-" * 70)

    columns = []
    for row in cursor.fetchall():
        col_name, type_name, size, nullable = row
        columns.append(col_name)
        nullable_str = "YES" if nullable else "NO"
        print(f"{col_name:<40} {type_name:<20} {nullable_str:<10}")

    print(f"\nTotal columns: {len(columns)}")

    # Check if we have sample data
    print("\n=== Sample CVE Entry (CVE-2021-44228 - Log4Shell) ===")
    cursor.execute("""
        SELECT * FROM VULNERABILITY WHERE CVE = 'CVE-2021-44228' LIMIT 1
    """)

    row = cursor.fetchone()
    if row:
        print("\nColumn values:")
        for i, col_name in enumerate(columns):
            value = row[i] if i < len(row) else "N/A"
            if value and len(str(value)) > 100:
                value = str(value)[:97] + "..."
            print(f"  {col_name}: {value}")
    else:
        print("CVE-2021-44228 not found in database")

    # Check CWE_ENTRY table
    print("\n=== CWE_ENTRY Table Columns ===")
    cursor.execute("""
        SELECT COLUMN_NAME, TYPE_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = 'CWE_ENTRY'
        ORDER BY ORDINAL_POSITION
    """)

    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    # Check REFERENCE table
    print("\n=== REFERENCE Table Columns ===")
    cursor.execute("""
        SELECT COLUMN_NAME, TYPE_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = 'REFERENCE'
        ORDER BY ORDINAL_POSITION
    """)

    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    conn.close()

if __name__ == '__main__':
    print("H2 Database Schema Checker")
    print("=" * 70)
    check_schema()

