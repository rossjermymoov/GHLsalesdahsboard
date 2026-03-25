#!/bin/bash
cd "$(dirname "$0")"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo ""
    echo "  Node.js is not installed."
    echo ""
    echo "  Installing now via Homebrew..."
    echo ""

    if ! command -v brew &> /dev/null; then
        echo "  Installing Homebrew first..."
        echo ""
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        if [ -f /opt/homebrew/bin/brew ]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
    fi

    brew install node
    echo ""
    echo "  Node.js installed!"
    echo ""
fi

# Load .env file if it exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Prompt for credentials if not set
if [ -z "$GHL_API_KEY" ]; then
    echo ""
    echo "  First-time setup — enter your GHL credentials."
    echo "  These will be saved to a .env file so you only do this once."
    echo ""
    read -p "  GHL API Key: " GHL_API_KEY
    read -p "  GHL Location ID: " GHL_LOCATION_ID
    read -p "  Admin Secret (pick a password): " ADMIN_SECRET
    echo ""

    cat > .env <<EOF
GHL_API_KEY=$GHL_API_KEY
GHL_LOCATION_ID=$GHL_LOCATION_ID
ADMIN_SECRET=$ADMIN_SECRET
PORT=3456
EOF

    echo "  Saved to .env file."
    export GHL_API_KEY GHL_LOCATION_ID ADMIN_SECRET
fi

echo ""
echo "  Starting GHL Sales Dashboard..."
echo ""

# Open browser after a short delay
(sleep 2 && open "http://localhost:${PORT:-3456}") &

# Start the server
node server.js
