#!/bin/bash

# Ensure we are NOT running as root (the script itself)
if [ "$EUID" -eq 0 ]; then
  echo "❌ Error: Please DO NOT run this script as root (sudo)."
  echo "   Run it as a normal user. It will ask for sudo password ONLY for the backend."
  echo "Usage: ./run.sh"
  exit
fi

echo "🚀 Starting Network Analyzer..."

# 1. Kill any existing backend instances
echo "🧹 Cleaning up old processes..."
sudo pkill -f "python3 server.py"

# 2. Start Backend as Root (Prompt for password)
echo "🔒 Starting Backend Service (Requires Sudo for Sniffing)..."
sudo python3 server.py > backend.log 2>&1 &
BACKEND_PID=$!

# Give it a moment to start
sleep 2

# Check if backend is running
if ps -p $BACKEND_PID > /dev/null
then
   echo "✅ Backend started (PID: $BACKEND_PID)"
else
   echo "❌ Backend failed to start. Check backend.log"
   cat backend.log
   exit 1
fi

# 3. Start Frontend as User
echo "💻 Starting Frontend..."
cd network-analyzer
export SKIP_PY_BACKEND=true
npm run dev:electron

# 4. Cleanup on exit
echo "🛑 Stopping Backend..."
sudo kill $BACKEND_PID
