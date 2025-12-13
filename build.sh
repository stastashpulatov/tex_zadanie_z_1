#!/bin/bash

echo "🔨 Building Network Analyzer Frontend..."

cd /home/kratos/Документы/zadaniya/tex_zadanie_z_1/network-analyzer

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Build the production bundle
echo "⚙️  Compiling TypeScript and building Vite bundle..."
npm run build

if [ $? -eq 0 ]; then
    echo "✅ Build completed successfully!"
    echo "   Production files are in: network-analyzer/dist/"
    echo ""
    echo "You can now run the application with:"
    echo "  ./run.sh"
    echo "or test autostart with:"
    echo "  ./start_frontend.sh"
else
    echo "❌ Build failed. Please check the errors above."
    exit 1
fi
