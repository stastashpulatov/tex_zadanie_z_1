#!/bin/bash

# 1. Install Systemd Service (Backend)
echo "Installing Backend Service..."
sudo cp /home/kratos/Документы/zadaniya/tex_zadanie_z_1/network-analyzer-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable network-analyzer-backend.service
sudo systemctl start network-analyzer-backend.service
echo "Backend service started and enabled."

# 2. Install Autostart Entry (Frontend)
echo "Installing Frontend Autostart..."
mkdir -p /home/kratos/.config/autostart
cp /home/kratos/Документы/zadaniya/tex_zadanie_z_1/network-analyzer.desktop /home/kratos/.config/autostart/
chmod +x /home/kratos/.config/autostart/network-analyzer.desktop
echo "Frontend autostart configured."

echo "✅ Setup Complete! The application will start automatically on boot."
