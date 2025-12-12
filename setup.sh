#!/bin/bash
#
# Setup script for Dependency Remediate AI RAG
# This script helps you set up the development environment
#

set -e

echo "=========================================="
echo "Dependency Remediate AI RAG - Setup"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Python is installed
echo "Checking prerequisites..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 is not installed. Please install Python 3.9 or higher.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python 3 found: $(python3 --version)${NC}"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}⚠ Docker is not installed. You'll need it to run the OWASP scanner.${NC}"
else
    echo -e "${GREEN}✓ Docker found: $(docker --version)${NC}"
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo ""
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file${NC}"
    echo -e "${YELLOW}⚠ Please edit .env and configure your Neo4j and LLM settings${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

# Install rag_graphdb dependencies
echo ""
echo "Installing rag_graphdb dependencies..."
cd rag_graphdb
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
cd ..
echo -e "${GREEN}✓ rag_graphdb dependencies installed${NC}"

# Install mcp_agent dependencies
echo ""
echo "Installing mcp_agent dependencies..."
cd mcp_agent
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
cd ..
echo -e "${GREEN}✓ mcp_agent dependencies installed${NC}"

# Initialize OWASP Dependency Check database (if Docker is available)
if command -v docker &> /dev/null; then
    echo ""
    read -p "Do you want to initialize the OWASP Dependency Check database? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Initializing OWASP Dependency Check database..."
        cd version-scanner-odc
        ./get-odc-data.sh
        echo -e "${GREEN}✓ OWASP Dependency Check database initialized${NC}"

        echo ""
        read -p "Do you want to build the scanner container? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Detect platform
            if [[ "$OSTYPE" == "darwin"* ]]; then
                ./build.sh osx
            else
                ./build.sh linux
            fi
            echo -e "${GREEN}✓ Scanner container built${NC}"
        fi
        cd ..
    fi
fi

# Check Neo4j connection
echo ""
echo "Checking Neo4j connection..."
read -p "Is Neo4j running? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd rag_graphdb
    source venv/bin/activate

    # Source .env if it exists
    if [ -f ../.env ]; then
        export $(cat ../.env | grep -v '^#' | xargs)
    fi

    if python verify_neo4j.py 2>/dev/null; then
        echo -e "${GREEN}✓ Neo4j connection successful${NC}"
    else
        echo -e "${RED}✗ Failed to connect to Neo4j${NC}"
        echo -e "${YELLOW}  Please check your Neo4j settings in .env${NC}"
    fi
    deactivate
    cd ..
else
    echo -e "${YELLOW}⚠ Please start Neo4j before using the system${NC}"
    echo "  You can use Docker: docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:latest"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Edit .env and configure your settings"
echo "2. Start Neo4j if not already running"
echo "3. Run a scan:"
echo "   cd version-scanner-odc"
echo "   docker run --rm -v \$(pwd):/app version-scanner-odc:odc-arm64 --target-dir /app/java-project --remediation --transitive"
echo "4. Import data to Neo4j:"
echo "   cd rag_graphdb"
echo "   source venv/bin/activate"
echo "   python import_odc_to_neo4j.py --target-dir ../version-scanner-odc/java-project --project MY_PROJECT"
echo "5. Test tools:"
echo "   python test_tools.py"
echo "6. Run the agent:"
echo "   cd ../mcp_agent"
echo "   source venv/bin/activate"
echo "   python agent.py"
echo "7. Or run the dashboard:"
echo "   streamlit run dashboard.py"
echo ""
echo -e "${GREEN}Enjoy using Dependency Remediate AI RAG!${NC}"

