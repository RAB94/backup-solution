#!/bin/bash
echo "🚀 Starting VM Backup Solution..."

# Pull latest images
docker-compose pull

# Build and start services
docker-compose up --build -d

echo "⏳ Waiting for services to start..."
sleep 10

# Check service health
echo "🔍 Checking service status..."
docker-compose ps

echo ""
echo "✅ VM Backup Solution is starting up!"
echo ""
echo "🌐 Access URLs:"
echo "   Frontend:  http://localhost:3000"
echo "   API:       http://localhost:8000"
echo "   API Docs:  http://localhost:8000/docs"
echo "   Grafana:   http://localhost:3001 (admin/admin123)"
echo "   MinIO:     http://localhost:9001 (minioadmin/minioadmin123)"
echo ""
