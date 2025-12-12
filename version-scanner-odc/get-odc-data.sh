#!/bin/bash

# Download the OWASP Dependency-Check database
# Creates a database compatible with v12.1.0

if [ $NVD_API_KEY == "" ];
    echo "❌ ERROR: NVD_API_KEY is not set!"
    exit
fi

echo "🔄 Downloading Dependency-Check database (v12.1.0)..."
echo "📁 Directory: $(pwd)/odc-data"
echo ""

# Clean up the old database
rm -rf $(pwd)/odc-data
mkdir -p $(pwd)/odc-data
touch $(pwd)/odc-data/dummy.txt

# Update using the H2 database
# Username and password are explicitly specified
podman run --rm \
    -v $(pwd)/odc-data:/usr/share/dependency-check/data:z \
    owasp/dependency-check:12.1.0 \
    --nvdApiKey $NVD_API_KEY \
    --dbUser sa \
    --dbPassword password \
    --scan "/usr/share/dependency-check/data/dummy.txt" \
    --format "HTML" \
    --out "/usr/share/dependency-check/data/dummy-report"

# Check the command's success status
if [ $? -eq 0 ]; then
    # Clean up dummy files
    rm -f $(pwd)/odc-data/dummy.txt
    rm -rf $(pwd)/odc-data/dummy-report

    echo ""
    echo "✅ Database downloaded successfully!"
    echo "🔑 Username: sa"
    echo "🔑 Password: password"
    echo "📊 Size: $(du -sh $(pwd)/odc-data | cut -f1)"
else
    echo "❌ ERROR: An issue occurred while creating the database."
fi
