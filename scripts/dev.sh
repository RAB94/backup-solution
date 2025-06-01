#!/bin/bash
echo "🔧 Starting VM Backup Solution in Development Mode..."

# Start only required services for development
docker-compose up -d postgres redis minio

echo "⏳ Waiting for database to be ready..."
sleep 5

echo "🐍 To start backend in development mode:"
echo "   cd backend"
echo "   source venv/bin/activate"
echo "   uvicorn main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "⚛️ To start frontend in development mode:"
echo "   cd frontend"
echo "   npm start"
echo ""
