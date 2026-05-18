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

# Check if Podman is installed (preferred), fall back to Docker
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
    echo -e "${GREEN}✓ Podman found: $(podman --version)${NC}"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
    echo -e "${GREEN}✓ Docker found: $(docker --version)${NC}"
else
    CONTAINER_CMD=""
    echo -e "${YELLOW}⚠ Neither Podman nor Docker is installed. You'll need one to run the OWASP scanner.${NC}"
fi

# Create llm-agent/.env file if it doesn't exist
if [ ! -f llm-agent/.env ]; then
    echo ""
    echo "Creating llm-agent/.env file from llm-agent/.env.example..."
    cp llm-agent/.env.example llm-agent/.env
    echo -e "${GREEN}✓ Created llm-agent/.env file${NC}"
    echo -e "${YELLOW}⚠ Please edit llm-agent/.env and configure your Neo4j and LLM settings${NC}"
else
    echo -e "${GREEN}✓ llm-agent/.env file already exists${NC}"
fi

# Install data-ingestion dependencies
echo ""
echo "Installing data-ingestion dependencies..."
cd data-ingestion
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
cd ..
echo -e "${GREEN}✓ data-ingestion dependencies installed${NC}"

# Install llm-agent dependencies
echo ""
echo "Installing llm-agent dependencies..."
cd llm-agent
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
cd ..
echo -e "${GREEN}✓ llm-agent dependencies installed${NC}"

# Initialize OWASP Dependency Check database (if container runtime is available)
if [[ -n "$CONTAINER_CMD" ]]; then
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
    cd data-ingestion
    source venv/bin/activate

    # Source llm-agent/.env if it exists
    if [ -f ../llm-agent/.env ]; then
        set -a
        source ../llm-agent/.env
        set +a
    fi

    if python3 verify_neo4j.py 2>/dev/null; then
        echo -e "${GREEN}✓ Neo4j connection successful${NC}"
    else
        echo -e "${RED}✗ Failed to connect to Neo4j${NC}"
        echo -e "${YELLOW}  Please check your Neo4j settings in llm-agent/.env${NC}"
    fi
    deactivate
    cd ..
else
    echo -e "${YELLOW}⚠ Please start Neo4j before using the system${NC}"
    echo "  podman run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:5-community"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Edit llm-agent/.env and configure your settings"
echo "2. Start Neo4j if not already running:"
echo "   podman run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:5-community"
echo "3. Run a scan:"
echo "   cd version-scanner-odc && ./run.sh"
echo "4. Import data to Neo4j:"
echo "   cd data-ingestion && ./run.sh"
echo "5. Run the dashboard:"
echo "   cd llm-agent && ./run.sh"
echo ""
echo -e "${GREEN}Enjoy using Dependency Remediate AI RAG!${NC}"

