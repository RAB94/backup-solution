# VM Backup Solution 🛡️

Enterprise-grade virtual machine backup and recovery solution supporting VMware vSphere, Proxmox VE, XCP-NG, and Ubuntu machines.

## Quick Start 🚀

### Prerequisites
- Docker & Docker Compose
- 4GB+ RAM
- 10GB+ free disk space

### Installation
```bash
# Start all services
./scripts/start.sh

# Access the application
open http://localhost:3000
```

### Default Access
- **Frontend**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **Monitoring**: http://localhost:3001 (admin/admin123)
- **Storage**: http://localhost:9001 (minioadmin/minioadmin123)

## Features ✨

- **Multi-Platform Support**: VMware, Proxmox, XCP-NG, Ubuntu
- **Authentication**: JWT-based with role management
- **Ubuntu Machine Backup**: SSH-based laptop/server backup
- **Network Discovery**: Automatic Ubuntu machine detection
- **Futuristic Interface**: Cyberpunk-inspired functional UI
- **Enterprise Security**: Encryption and anti-ransomware
- **Monitoring**: Prometheus + Grafana integration

## Development 🛠️

```bash
# Start in development mode
./scripts/dev.sh

# Backend development
cd backend
source venv/bin/activate
uvicorn main:app --reload

# Frontend development
cd frontend
npm start
```

## Support 📞

Check the docs/ directory for detailed documentation.
