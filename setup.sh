#!/bin/bash
#===============================================================================
# ThreatGuard-AI Setup Script
# Automated environment setup for DDoS Detection System
#===============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}       ThreatGuard-AI - DDoS Detection System Setup            ${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

#-------------------------------------------------------------------------------
# Step 1: Check Python Version
#-------------------------------------------------------------------------------
echo -e "${YELLOW}[1/6] Checking Python version...${NC}"

if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
        echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
    else
        echo -e "${RED}✗ Python 3.8+ required, found $PYTHON_VERSION${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ Python3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

#-------------------------------------------------------------------------------
# Step 2: Create Directory Structure
#-------------------------------------------------------------------------------
echo -e "${YELLOW}[2/6] Creating directory structure...${NC}"

directories=(
    "data/processed"
    "data/splits"
    "models"
    "src"
    "templates"
    "logs"
)

for dir in "${directories[@]}"; do
    mkdir -p "$dir"
    echo -e "  ${GREEN}✓${NC} Created $dir/"
done

#-------------------------------------------------------------------------------
# Step 3: Create Virtual Environment
#-------------------------------------------------------------------------------
echo -e "${YELLOW}[3/6] Setting up virtual environment...${NC}"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

# Activate virtual environment
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

#-------------------------------------------------------------------------------
# Step 4: Install Dependencies
#-------------------------------------------------------------------------------
echo -e "${YELLOW}[4/6] Installing Python dependencies...${NC}"

pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

echo -e "${GREEN}✓ All dependencies installed${NC}"

#-------------------------------------------------------------------------------
# Step 5: Verify NFStream Installation
#-------------------------------------------------------------------------------
echo -e "${YELLOW}[5/6] Verifying NFStream installation...${NC}"

if python3 -c "import nfstream; print(f'NFStream version: {nfstream.__version__}')" 2>/dev/null; then
    echo -e "${GREEN}✓ NFStream verified${NC}"
else
    echo -e "${RED}✗ NFStream installation failed${NC}"
    echo -e "${YELLOW}Try: sudo apt-get install libpcap-dev${NC}"
    exit 1
fi

#-------------------------------------------------------------------------------
# Step 6: Check Network Interfaces
#-------------------------------------------------------------------------------
echo -e "${YELLOW}[6/6] Checking network interfaces...${NC}"
echo ""
echo -e "${BLUE}Available network interfaces:${NC}"
ip -br addr | grep -v "^lo" | while read line; do
    echo -e "  ${GREEN}→${NC} $line"
done

#-------------------------------------------------------------------------------
# Setup Complete
#-------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}           ✓ Setup Complete!                                   ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Activate environment: ${YELLOW}source venv/bin/activate${NC}"
echo -e "  2. Extract features:     ${YELLOW}python src/extract_features.py${NC}"
echo -e "  3. Train model:          ${YELLOW}python src/train_model.py${NC}"
echo -e "  4. Run live detection:   ${YELLOW}sudo venv/bin/python src/capture_live.py${NC}"
echo -e "  5. Start dashboard:      ${YELLOW}sudo venv/bin/python src/backend.py${NC}"
echo ""
echo -e "${BLUE}Dataset location:${NC} data/PCAP-03-11/"
echo -e "${BLUE}Model output:${NC} models/"
echo ""
