#!/usr/bin/env python3
"""
Direct H2 database inspection to find actual column names.
"""
import jaydebeapi
import glob
import os

# Find H2 jar
h2_jar = None
jar_locations = [
    '../version-scanner-odc/odc-data/h2*.jar',
    '/opt/dependency-check/lib/h2-*.jar',
]

for pattern in jar_locations:
    matches = glob.glob(pattern)
    if matches:
        h2_jar = matches[0]
        break

if not h2_jar:
    print("ERROR: H2 jar not found!")
    exit(1)

print(f"Using H2 jar: {h2_jar}\n")

# Connect to database
db_path = '../version-scanner-odc/odc-data/odc'
if not os.path.exists(f"{db_path}.mv.db"):
    print(f"ERROR: Database not found at {db_path}.mv.db")
    exit(1)

print(f"Connecting to: {db_path}.mv.db\n")

conn = jaydebeapi.connect(
    "org.h2.Driver",
    f"jdbc:h2:{db_path}",
    ["sa", "password"],
    h2_jar
)

cursor = conn.cursor()

# Get all columns in VULNERABILITY table
print("=" * 80)
print("VULNERABILITY Table - All Columns")
print("=" * 80)

cursor.execute("""
    SELECT COLUMN_NAME, TYPE_NAME, CHARACTER_MAXIMUM_LENGTH
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_NAME = 'VULNERABILITY'
    ORDER BY ORDINAL_POSITION
""")

columns = []
for row in cursor.fetchall():
    col_name = row[0]
    data_type = row[1]
    max_len = row[2] if row[2] else ""
    columns.append(col_name)
    print(f"  {col_name:40} {data_type:20} {max_len}")

print(f"\nTotal columns: {len(columns)}")

# Find date/time related columns
print("\n" + "=" * 80)
print("Date/Time Related Columns")
print("=" * 80)

date_keywords = ['DATE', 'TIME', 'PUBLISH', 'MODIF', 'CREATE', 'UPDATE']
date_cols = [c for c in columns if any(kw in c.upper() for kw in date_keywords)]

if date_cols:
    for col in date_cols:
        print(f"  ✓ {col}")
else:
    print("  ⚠️  No date/time columns found!")

# Query a sample CVE to see actual data
print("\n" + "=" * 80)
print("Sample CVE Data: CVE-2021-44228 (Log4Shell)")
print("=" * 80)

# First check if CVE exists
cursor.execute("SELECT COUNT(*) FROM VULNERABILITY WHERE CVE = 'CVE-2021-44228'")
count = cursor.fetchone()[0]

if count > 0:
    # Build query with only existing columns
    select_cols = ['CVE', 'DESCRIPTION']
    if date_cols:
        select_cols.extend(date_cols)

    query = f"SELECT {', '.join(select_cols)} FROM VULNERABILITY WHERE CVE = 'CVE-2021-44228'"
    cursor.execute(query)

    row = cursor.fetchone()
    if row:
        print(f"\nCVE: {row[0]}")
        print(f"Description: {row[1][:100] if row[1] else 'N/A'}...")

        if date_cols:
            print("\nDate values:")
            for i, col in enumerate(date_cols):
                value = row[i + 2] if i + 2 < len(row) else None
                print(f"  {col}: {value}")
else:
    print("\n⚠️  CVE-2021-44228 not found in database")
    print("Trying first available CVE...")

    cursor.execute("SELECT CVE FROM VULNERABILITY LIMIT 1")
    first_cve_row = cursor.fetchone()
    if first_cve_row:
        first_cve = first_cve_row[0]
        print(f"Found: {first_cve}")

        select_cols = ['CVE', 'DESCRIPTION']
        if date_cols:
            select_cols.extend(date_cols)

        query = f"SELECT {', '.join(select_cols)} FROM VULNERABILITY WHERE CVE = '{first_cve}'"
        cursor.execute(query)

        row = cursor.fetchone()
        if row:
            print(f"\nCVE: {row[0]}")
            if date_cols:
                print("\nDate values:")
                for i, col in enumerate(date_cols):
                    value = row[i + 2] if i + 2 < len(row) else None
                    print(f"  {col}: {value}")

conn.close()

print("\n" + "=" * 80)
print("Inspection Complete")
print("=" * 80)

