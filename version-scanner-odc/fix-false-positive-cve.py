#!/usr/bin/env python3
"""
Fix false positive CVE-2023-44794 in OWASP Dependency Check database.
This CVE is for Dromara SaToken, not Spring Boot.
"""

import glob
import jaydebeapi
import os

def fix_database():
    odc_data_dir = os.getenv('DEPENDENCY_CHECK_DATA', '/usr/share/dependency-check/data')
    db_path = os.path.join(odc_data_dir, 'odc')

    # Find H2 driver
    h2_jar_candidates = glob.glob('/usr/share/dependency-check/lib/h2-*.jar')
    if not h2_jar_candidates:
        h2_jar_candidates = glob.glob('./h2-*.jar')

    if not h2_jar_candidates:
        print("ERROR: H2 driver not found!")
        return

    h2_jar = h2_jar_candidates[0]
    print(f"Using H2 driver: {h2_jar}")

    # Connect to database
    conn = jaydebeapi.connect(
        "org.h2.Driver",
        f"jdbc:h2:file:{db_path}",
        ["sa", "password"],
        h2_jar
    )

    cursor = conn.cursor()

    # First, check what we're about to delete
    print("\n=== Checking false positive entries ===")
    cursor.execute("""
        SELECT
            v.CVE,
            v.DESCRIPTION,
            c.VENDOR,
            c.PRODUCT,
            s.VERSIONSTARTINCLUDING,
            s.VERSIONENDINCLUDING
        FROM SOFTWARE s
        JOIN CPEENTRY c ON s.CPEENTRYID = c.ID
        JOIN VULNERABILITY v ON s.CVEID = v.ID
        WHERE v.CVE = 'CVE-2023-44794'
          AND c.PRODUCT = 'spring_boot'
    """)

    results = cursor.fetchall()
    if not results:
        print("No false positive entries found.")
        conn.close()
        return

    print(f"Found {len(results)} false positive entries:")
    for row in results:
        print(f"  CVE: {row[0]}")
        print(f"  Description: {row[1][:80]}...")
        print(f"  Vendor: {row[2]}, Product: {row[3]}")
        print(f"  Range: {row[4] or 'null'} - {row[5] or 'null (infinity)'}")
        print()

    # Delete the false positive entries
    print("=== Deleting false positive entries ===")
    cursor.execute("""
        DELETE FROM SOFTWARE
        WHERE CVEID IN (
            SELECT ID FROM VULNERABILITY WHERE CVE = 'CVE-2023-44794'
        )
        AND CPEENTRYID IN (
            SELECT ID FROM CPEENTRY WHERE PRODUCT = 'spring_boot'
        )
    """)

    deleted_count = cursor.rowcount
    conn.commit()

    print(f"✅ Successfully deleted {deleted_count} false positive entries!")

    # Verify deletion
    cursor.execute("""
        SELECT COUNT(*)
        FROM SOFTWARE s
        JOIN CPEENTRY c ON s.CPEENTRYID = c.ID
        WHERE c.PRODUCT = 'spring_boot'
    """)

    remaining = cursor.fetchone()[0]
    print(f"ℹ️  Remaining Spring Boot entries in database: {remaining}")

    conn.close()

if __name__ == '__main__':
    print("OWASP Dependency Check Database False Positive Fix")
    print("=" * 60)
    fix_database()
    print("\nDone! You can now re-run remediation scan.")