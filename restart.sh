#!/bin/bash

echo "Stopping existing Root CA application..."
sudo pkill -f "python3 app.py" || echo "No existing process found"

echo "Waiting for process to stop..."
sleep 2

echo "Starting Root CA application..."
cd /home/compiler/cursorai/rootca
sudo python3 app.py &
echo "Application started in background"
echo "Check logs at: /var/log/rootca/app.log"
echo "Access the application at: http://localhost:5000"
