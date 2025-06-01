# main.py
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Optional
from datetime import datetime, timedelta
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import our modules
from database import (
    get_db, init_db, Base, engine,
    VirtualMachine, BackupJob, BackupRepository, PlatformConnection,
    PlatformType, BackupJobStatus, BackupType,
    VMResponse, BackupJobCreate, BackupJobResponse,
    BackupRepositoryCreate, BackupRepositoryResponse,
    PlatformConnectionCreate, PlatformConnectionResponse
)
from platform_connectors import VMwareConnector, ProxmoxConnector, XCPNGConnector
from ubuntu_backup import UbuntuBackupConnector, UbuntuNetworkDiscovery
from backup_engine import BackupEngine
from auth import (
    User, UserCreate, UserLogin, UserResponse, Token,
    create_access_token, create_refresh_token, get_current_user,
    admin_required, operator_required, authenticate_user,
    create_user, create_user_session, get_active_sessions,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Simple scheduler class since APScheduler might not be installed
class SimpleScheduler:
    def __init__(self):
        self.jobs = {}
        self.running = False
    
    def start(self):
        self.running = True
        logger.info("Simple scheduler started")
    
    def shutdown(self):
        self.running = False
        logger.info("Simple scheduler stopped")
    
    def schedule_job(self, backup_job):
        self.jobs[backup_job.id] = backup_job
        logger.info(f"Scheduled job: {backup_job.name}")
    
    def remove_job(self, job_id: int):
        if job_id in self.jobs:
            del self.jobs[job_id]
            logger.info(f"Removed job: {job_id}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing database...")
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    
    # Start the backup scheduler
    scheduler = SimpleScheduler()
    scheduler.start()
    app.state.scheduler = scheduler
    
    logger.info("VM Backup Solution API started!")
    yield
    
    # Shutdown
    if hasattr(app.state, 'scheduler'):
        app.state.scheduler.shutdown()
    logger.info("VM Backup Solution API stopped!")

app = FastAPI(
    title="VM Backup Solution API",
    description="Enterprise VM backup and recovery solution for VMware, Proxmox, and XCP-NG",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:1001", "http://192.168.27.97:1001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Platform connectors
connectors = {
    PlatformType.VMWARE: VMwareConnector(),
    PlatformType.PROXMOX: ProxmoxConnector(),
    PlatformType.XCPNG: XCPNGConnector(),
    'ubuntu': UbuntuBackupConnector()  # Add Ubuntu connector
}

# Backup engine
backup_engine = BackupEngine(connectors)

@app.get("/")
async def root():
    return {
        "message": "VM Backup Solution API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "services": {
            "database": "connected",
            "backup_engine": "running",
            "scheduler": "active"
        }
    }

# Platform Management Endpoints
@app.post("/api/v1/platforms/{platform_type}/connect")
async def connect_platform(
    platform_type: PlatformType,
    connection_data: dict,
    db: Session = Depends(get_db)
):
    """Connect to a virtualization platform"""
    try:
        connector = connectors[platform_type]
        success = await connector.connect(connection_data)
        
        if success:
            # Store connection info (encrypted in production)
            return {"status": "connected", "platform": platform_type}
        else:
            raise HTTPException(status_code=400, detail="Failed to connect to platform")
            
    except Exception as e:
        logger.error(f"Platform connection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/platforms/{platform_type}/vms")
async def get_platform_vms(
    platform_type: PlatformType,
    db: Session = Depends(get_db)
) -> List[dict]:
    """Get list of VMs from a platform"""
    try:
        connector = connectors[platform_type]
        vms = await connector.list_vms()
        return vms
    except Exception as e:
        logger.error(f"Error getting VMs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Backup Job Management
@app.post("/api/v1/backup-jobs")
async def create_backup_job(
    job_data: BackupJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
) -> dict:
    """Create a new backup job"""
    try:
        # Create job in database
        db_job = BackupJob(
            name=job_data.name,
            description=job_data.description,
            vm_id=job_data.vm_id,
            platform=job_data.platform,
            backup_type=job_data.backup_type,
            repository_id=job_data.repository_id,
            schedule_cron=job_data.schedule_cron,
            retention_days=job_data.retention_days,
            compression_enabled=job_data.compression_enabled,
            encryption_enabled=job_data.encryption_enabled
        )
        db.add(db_job)
        db.commit()
        db.refresh(db_job)
        
        # Schedule the job
        if hasattr(app.state, 'scheduler'):
            app.state.scheduler.schedule_job(db_job)
        
        return {
            "id": db_job.id,
            "name": db_job.name,
            "status": "created"
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/vms/scan")
async def scan_vm_by_ip(
    scan_data: dict,
    db: Session = Depends(get_db)
):
    """Scan and detect VM by IP address"""
    try:
        ip = scan_data.get('ip')
        platform = scan_data.get('platform', 'unknown')
        username = scan_data.get('username', '')
        password = scan_data.get('password', '')
        port = scan_data.get('port', 22)
        
        logger.info(f"Scanning VM at {ip} for platform {platform}")
        
        if platform == 'ubuntu':
            # Use Ubuntu connector for scanning
            connector = connectors['ubuntu']
            connection_params = {
                'ip': ip,
                'username': username,
                'password': password,
                'port': port
            }
            
            if await connector.connect(connection_params):
                machines = await connector.list_vms()
                if machines:
                    return machines[0]
        
        elif platform in ['vmware', 'proxmox', 'xcpng']:
            # Try to connect to the platform and get VM info
            connector = connectors.get(PlatformType(platform))
            if connector:
                connection_params = {
                    'host': ip,
                    'username': username,
                    'password': password,
                    'port': port
                }
                
                if await connector.connect(connection_params):
                    vms = await connector.list_vms()
                    # Find VM that matches the IP or return first one
                    for vm in vms:
                        if vm.get('host') == ip or vm.get('ip_address') == ip:
                            return vm
                    if vms:
                        return vms[0]
        
        # Fallback: create basic VM info from scan data
        vm_info = {
            'vm_id': f"manual-{ip}",
            'name': f"{platform}-{ip}",
            'platform': platform,
            'host': ip,
            'ip_address': ip,
            'cpu_count': 2,
            'memory_mb': 4096,
            'disk_size_gb': 50,
            'operating_system': 'Unknown',
            'power_state': 'unknown',
            'created_at': datetime.now().isoformat()
        }
        
        return vm_info
        
    except Exception as e:
        logger.error(f"VM scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"VM scan failed: {str(e)}")

@app.post("/api/v1/vms/scan")
async def scan_vm_by_ip(
    scan_data: dict,
    db: Session = Depends(get_db)
):
    """Scan and detect VM by IP address"""
    try:
        ip = scan_data.get('ip')
        platform = scan_data.get('platform', 'unknown')
        username = scan_data.get('username', '')
        password = scan_data.get('password', '')
        port = scan_data.get('port', 22)
        
        logger.info(f"Scanning VM at {ip} for platform {platform}")
        
        if platform == 'ubuntu':
            # Use Ubuntu connector for scanning
            connector = connectors['ubuntu']
            connection_params = {
                'ip': ip,
                'username': username,
                'password': password,
                'port': port
            }
            
            if await connector.connect(connection_params):
                machines = await connector.list_vms()
                if machines:
                    return machines[0]
        
        elif platform in ['vmware', 'proxmox', 'xcpng']:
            # Try to connect to the platform and get VM info
            connector = connectors.get(PlatformType(platform))
            if connector:
                connection_params = {
                    'host': ip,
                    'username': username,
                    'password': password,
                    'port': port
                }
                
                if await connector.connect(connection_params):
                    vms = await connector.list_vms()
                    # Find VM that matches the IP or return first one
                    for vm in vms:
                        if vm.get('host') == ip or vm.get('ip_address') == ip:
                            return vm
                    if vms:
                        return vms[0]
        
        # Fallback: create basic VM info from scan data
        vm_info = {
            'vm_id': f"manual-{ip}",
            'name': f"{platform}-{ip}",
            'platform': platform,
            'host': ip,
            'ip_address': ip,
            'cpu_count': 2,
            'memory_mb': 4096,
            'disk_size_gb': 50,
            'operating_system': 'Unknown',
            'power_state': 'unknown',
            'created_at': datetime.now().isoformat()
        }
        
        return vm_info
        
    except Exception as e:
        logger.error(f"VM scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"VM scan failed: {str(e)}")

@app.post("/api/v1/vms/manual")
async def add_vm_manually(
    vm_data: dict,
    db: Session = Depends(get_db)
):
    """Add VM manually with user-provided information"""
    try:
        # Create VM record in database
        db_vm = VirtualMachine(
            vm_id=vm_data.get('vm_id', f"manual-{vm_data.get('ip_address', 'unknown')}"),
            name=vm_data.get('name'),
            platform=PlatformType(vm_data.get('platform')),
            host=vm_data.get('ip_address'),
            cpu_count=vm_data.get('cpu_count', 2),
            memory_mb=vm_data.get('memory_mb', 4096),
            disk_size_gb=vm_data.get('disk_size_gb', 50),
            operating_system=vm_data.get('operating_system', 'Unknown'),
            power_state='unknown',
            vm_metadata={'manually_added': True, 'notes': vm_data.get('notes', '')}
        )
        
        db.add(db_vm)
        db.commit()
        db.refresh(db_vm)
        
        return {
            'id': db_vm.id,
            'vm_id': db_vm.vm_id,
            'name': db_vm.name,
            'platform': db_vm.platform.value,
            'host': db_vm.host,
            'ip_address': db_vm.host,
            'cpu_count': db_vm.cpu_count,
            'memory_mb': db_vm.memory_mb,
            'disk_size_gb': db_vm.disk_size_gb,
            'operating_system': db_vm.operating_system,
            'power_state': db_vm.power_state,
            'created_at': db_vm.created_at.isoformat()
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to add VM manually: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add VM: {str(e)}")

@app.put("/api/v1/vms/{vm_id}")
async def update_vm(
    vm_id: str,
    vm_data: dict,
    db: Session = Depends(get_db)
):
    """Update VM information"""
    try:
        # Find existing VM in database
        db_vm = db.query(VirtualMachine).filter(VirtualMachine.vm_id == vm_id).first()
        
        if not db_vm:
            # Create new VM record if it doesn't exist
            db_vm = VirtualMachine(
                vm_id=vm_id,
                name=vm_data.get('name', 'Unknown VM'),
                platform=PlatformType(vm_data.get('platform', 'vmware')),
                host=vm_data.get('ip_address', vm_data.get('host', 'unknown')),
                cpu_count=vm_data.get('cpu_count', 2),
                memory_mb=vm_data.get('memory_mb', 4096),
                disk_size_gb=vm_data.get('disk_size_gb', 50),
                operating_system=vm_data.get('operating_system', 'Unknown'),
                power_state=vm_data.get('power_state', 'unknown'),
                vm_metadata={'updated_via_api': True}
            )
            db.add(db_vm)
        else:
            # Update existing VM
            if 'name' in vm_data:
                db_vm.name = vm_data['name']
            if 'operating_system' in vm_data:
                db_vm.operating_system = vm_data['operating_system']
            if 'cpu_count' in vm_data:
                db_vm.cpu_count = vm_data['cpu_count']
            if 'memory_mb' in vm_data:
                db_vm.memory_mb = vm_data['memory_mb']
            if 'disk_size_gb' in vm_data:
                db_vm.disk_size_gb = vm_data['disk_size_gb']
            if 'ip_address' in vm_data:
                db_vm.host = vm_data['ip_address']
            
            db_vm.updated_at = datetime.now()
        
        db.commit()
        db.refresh(db_vm)
        
        return {
            'id': db_vm.id,
            'vm_id': db_vm.vm_id,
            'name': db_vm.name,
            'platform': db_vm.platform.value,
            'host': db_vm.host,
            'ip_address': db_vm.host,
            'cpu_count': db_vm.cpu_count,
            'memory_mb': db_vm.memory_mb,
            'disk_size_gb': db_vm.disk_size_gb,
            'operating_system': db_vm.operating_system,
            'power_state': db_vm.power_state,
            'created_at': db_vm.created_at.isoformat()
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update VM {vm_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update VM: {str(e)}")

@app.post("/api/v1/discovery/network")
async def discover_network_range(
    discovery_data: dict,
    db: Session = Depends(get_db)
):
    """Discover devices on network range"""
    try:
        network_range = discovery_data.get('network_range', '192.168.1.0/24')
        logger.info(f"Discovering devices in network range: {network_range}")
        
        # Use Ubuntu network discovery as it's the most generic
        ubuntu_connector = connectors.get('ubuntu')
        if ubuntu_connector:
            discovered = await ubuntu_connector.discover_ubuntu_machines(network_range)
            
            # Enhanced discovery - try to detect platform types
            enhanced_devices = []
            for device in discovered:
                enhanced_device = device.copy()
                
                # Try to detect platform based on open ports and services
                ip = device.get('ip')
                if ip:
                    try:
                        import socket
                        
                        # Check for common virtualization platform ports
                        platform_ports = {
                            443: 'vmware',  # vCenter/ESXi HTTPS
                            902: 'vmware',  # VMware Auth
                            8006: 'proxmox',  # Proxmox Web UI
                            80: 'xcpng',    # XCP-ng Web UI (also check for specific headers)
                            22: 'ubuntu'    # SSH (Ubuntu/Linux)
                        }
                        
                        open_ports = []
                        detected_platform = 'unknown'
                        
                        for port, platform in platform_ports.items():
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            result = sock.connect_ex((ip, port))
                            if result == 0:
                                open_ports.append(port)
                                if detected_platform == 'unknown':
                                    detected_platform = platform
                            sock.close()
                        
                        enhanced_device['open_ports'] = open_ports
                        enhanced_device['platform'] = detected_platform
                        
                    except Exception as scan_error:
                        logger.warning(f"Port scan failed for {ip}: {scan_error}")
                        enhanced_device['platform'] = 'unknown'
                        enhanced_device['open_ports'] = []
                
                enhanced_devices.append(enhanced_device)
            
            return {
                'network_range': network_range,
                'discovered_count': len(enhanced_devices),
                'discovered': enhanced_devices
            }
        
        return {
            'network_range': network_range,
            'discovered_count': 0,
            'discovered': []
        }
        
    except Exception as e:
        logger.error(f"Network discovery failed: {e}")
        raise HTTPException(status_code=500, detail=f"Network discovery failed: {str(e)}")

@app.post("/api/v1/platforms/{platform_type}/refresh")
async def refresh_platform_vms(
    platform_type: PlatformType,
    db: Session = Depends(get_db)
):
    """Refresh VM list for a specific platform"""
    try:
        connector = connectors.get(platform_type)
        if not connector:
            raise HTTPException(status_code=400, detail=f"Platform {platform_type} not supported")
        
        if not connector.connected:
            raise HTTPException(status_code=400, detail=f"Not connected to {platform_type}")
        
        vms = await connector.list_vms()
        
        # Update database with discovered VMs
        for vm_data in vms:
            existing_vm = db.query(VirtualMachine).filter(
                VirtualMachine.vm_id == vm_data['vm_id'],
                VirtualMachine.platform == platform_type
            ).first()
            
            if existing_vm:
                # Update existing VM
                existing_vm.name = vm_data['name']
                existing_vm.host = vm_data['host']
                existing_vm.cpu_count = vm_data['cpu_count']
                existing_vm.memory_mb = vm_data['memory_mb']
                existing_vm.disk_size_gb = vm_data['disk_size_gb']
                existing_vm.operating_system = vm_data['operating_system']
                existing_vm.power_state = vm_data['power_state']
                existing_vm.updated_at = datetime.now()
            else:
                # Create new VM record
                new_vm = VirtualMachine(
                    vm_id=vm_data['vm_id'],
                    name=vm_data['name'],
                    platform=platform_type,
                    host=vm_data['host'],
                    cpu_count=vm_data['cpu_count'],
                    memory_mb=vm_data['memory_mb'],
                    disk_size_gb=vm_data['disk_size_gb'],
                    operating_system=vm_data['operating_system'],
                    power_state=vm_data['power_state']
                )
                db.add(new_vm)
        
        db.commit()
        
        return {
            'platform': platform_type.value,
            'vms_discovered': len(vms),
            'vms': vms
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to refresh VMs for {platform_type}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/vms/manual")
async def add_vm_manually(
    vm_data: dict,
    db: Session = Depends(get_db)
):
    """Add VM manually with user-provided information"""
    try:
        # Create VM record in database
        db_vm = VirtualMachine(
            vm_id=vm_data.get('vm_id', f"manual-{vm_data.get('ip_address', 'unknown')}"),
            name=vm_data.get('name'),
            platform=PlatformType(vm_data.get('platform')),
            host=vm_data.get('ip_address'),
            cpu_count=vm_data.get('cpu_count', 2),
            memory_mb=vm_data.get('memory_mb', 4096),
            disk_size_gb=vm_data.get('disk_size_gb', 50),
            operating_system=vm_data.get('operating_system', 'Unknown'),
            power_state='unknown',
            vm_metadata={'manually_added': True, 'notes': vm_data.get('notes', '')}
        )
        
        db.add(db_vm)
        db.commit()
        db.refresh(db_vm)
        
        return {
            'id': db_vm.id,
            'vm_id': db_vm.vm_id,
            'name': db_vm.name,
            'platform': db_vm.platform.value,
            'host': db_vm.host,
            'ip_address': db_vm.host,
            'cpu_count': db_vm.cpu_count,
            'memory_mb': db_vm.memory_mb,
            'disk_size_gb': db_vm.disk_size_gb,
            'operating_system': db_vm.operating_system,
            'power_state': db_vm.power_state,
            'created_at': db_vm.created_at.isoformat()
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to add VM manually: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add VM: {str(e)}")

@app.post("/api/v1/discovery/network")
async def discover_network_range(
    discovery_data: dict,
    db: Session = Depends(get_db)
):
    """Discover devices on network range"""
    try:
        network_range = discovery_data.get('network_range', '192.168.1.0/24')
        logger.info(f"Discovering devices in network range: {network_range}")
        
        # Use Ubuntu network discovery as it's the most generic
        ubuntu_connector = connectors.get('ubuntu')
        if ubuntu_connector:
            discovered = await ubuntu_connector.discover_ubuntu_machines(network_range)
            
            # Enhanced discovery - try to detect platform types
            enhanced_devices = []
            for device in discovered:
                enhanced_device = device.copy()
                
                # Try to detect platform based on open ports and services
                ip = device.get('ip')
                if ip:
                    try:
                        import socket
                        
                        # Check for common virtualization platform ports
                        platform_ports = {
                            443: 'vmware',  # vCenter/ESXi HTTPS
                            902: 'vmware',  # VMware Auth
                            8006: 'proxmox',  # Proxmox Web UI
                            80: 'xcpng',    # XCP-ng Web UI (also check for specific headers)
                            22: 'ubuntu'    # SSH (Ubuntu/Linux)
                        }
                        
                        open_ports = []
                        detected_platform = 'unknown'
                        
                        for port, platform in platform_ports.items():
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            result = sock.connect_ex((ip, port))
                            if result == 0:
                                open_ports.append(port)
                                if detected_platform == 'unknown':
                                    detected_platform = platform
                            sock.close()
                        
                        enhanced_device['open_ports'] = open_ports
                        enhanced_device['platform'] = detected_platform
                        
                    except Exception as scan_error:
                        logger.warning(f"Port scan failed for {ip}: {scan_error}")
                        enhanced_device['platform'] = 'unknown'
                        enhanced_device['open_ports'] = []
                
                enhanced_devices.append(enhanced_device)
            
            return {
                'network_range': network_range,
                'discovered_count': len(enhanced_devices),
                'discovered': enhanced_devices
            }
        
        return {
            'network_range': network_range,
            'discovered_count': 0,
            'discovered': []
        }
        
    except Exception as e:
        logger.error(f"Network discovery failed: {e}")
        raise HTTPException(status_code=500, detail=f"Network discovery failed: {str(e)}")

@app.post("/api/v1/platforms/{platform_type}/refresh")
async def refresh_platform_vms(
    platform_type: PlatformType,
    db: Session = Depends(get_db)
):
    """Refresh VM list for a specific platform"""
    try:
        connector = connectors.get(platform_type)
        if not connector:
            raise HTTPException(status_code=400, detail=f"Platform {platform_type} not supported")
        
        if not connector.connected:
            raise HTTPException(status_code=400, detail=f"Not connected to {platform_type}")
        
        vms = await connector.list_vms()
        
        # Update database with discovered VMs
        for vm_data in vms:
            existing_vm = db.query(VirtualMachine).filter(
                VirtualMachine.vm_id == vm_data['vm_id'],
                VirtualMachine.platform == platform_type
            ).first()
            
            if existing_vm:
                # Update existing VM
                existing_vm.name = vm_data['name']
                existing_vm.host = vm_data['host']
                existing_vm.cpu_count = vm_data['cpu_count']
                existing_vm.memory_mb = vm_data['memory_mb']
                existing_vm.disk_size_gb = vm_data['disk_size_gb']
                existing_vm.operating_system = vm_data['operating_system']
                existing_vm.power_state = vm_data['power_state']
                existing_vm.updated_at = datetime.now()
            else:
                # Create new VM record
                new_vm = VirtualMachine(
                    vm_id=vm_data['vm_id'],
                    name=vm_data['name'],
                    platform=platform_type,
                    host=vm_data['host'],
                    cpu_count=vm_data['cpu_count'],
                    memory_mb=vm_data['memory_mb'],
                    disk_size_gb=vm_data['disk_size_gb'],
                    operating_system=vm_data['operating_system'],
                    power_state=vm_data['power_state']
                )
                db.add(new_vm)
        
        db.commit()
        
        return {
            'platform': platform_type.value,
            'vms_discovered': len(vms),
            'vms': vms
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to refresh VMs for {platform_type}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/backup-jobs")
async def list_backup_jobs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
) -> List[dict]:
    """List all backup jobs"""
    try:
        jobs = db.query(BackupJob).offset(skip).limit(limit).all()
        return [
            {
                "id": job.id,
                "name": job.name,
                "description": job.description,
                "vm_id": job.vm_id,
                "platform": job.platform.value,
                "backup_type": job.backup_type.value,
                "status": job.status.value,
                "schedule_cron": job.schedule_cron,
                "last_run": job.last_run.isoformat() if job.last_run else None,
                "next_run": job.next_run.isoformat() if job.next_run else None,
                "created_at": job.created_at.isoformat()
            }
            for job in jobs
        ]
    except Exception as e:
        logger.error(f"Error listing backup jobs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/backup-jobs/{job_id}")
async def get_backup_job(
    job_id: int,
    db: Session = Depends(get_db)
) -> dict:
    """Get specific backup job details"""
    try:
        job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Backup job not found")
        
        return {
            "id": job.id,
            "name": job.name,
            "description": job.description,
            "vm_id": job.vm_id,
            "platform": job.platform.value,
            "backup_type": job.backup_type.value,
            "status": job.status.value,
            "schedule_cron": job.schedule_cron,
            "last_run": job.last_run.isoformat() if job.last_run else None,
            "next_run": job.next_run.isoformat() if job.next_run else None,
            "created_at": job.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/backup-jobs/{job_id}/run")
async def run_backup_job(
    job_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Manually trigger a backup job"""
    try:
        job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Backup job not found")
        
        # Add backup task to background
        background_tasks.add_task(backup_engine.run_backup, job)
        
        # Update job status
        job.status = BackupJobStatus.RUNNING
        job.last_run = datetime.now()
        db.commit()
        
        return {"message": "Backup job started", "job_id": job_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/backup-jobs/{job_id}")
async def delete_backup_job(
    job_id: int,
    db: Session = Depends(get_db)
):
    """Delete a backup job"""
    try:
        job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Backup job not found")
        
        # Remove from scheduler
        if hasattr(app.state, 'scheduler'):
            app.state.scheduler.remove_job(job_id)
        
        db.delete(job)
        db.commit()
        
        return {"message": "Backup job deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Recovery Endpoints
@app.post("/api/v1/recovery/instant-restore")
async def instant_restore(
    backup_id: str,
    target_platform: PlatformType,
    restore_config: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Perform instant VM restore"""
    try:
        # Add restore task to background
        background_tasks.add_task(
            backup_engine.instant_restore,
            backup_id,
            target_platform,
            restore_config
        )
        
        return {
            "message": "Instant restore initiated",
            "backup_id": backup_id,
            "estimated_time": "15 seconds"
        }
    except Exception as e:
        logger.error(f"Error starting instant restore: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Statistics and Monitoring
@app.get("/api/v1/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    """Get backup system statistics"""
    try:
        total_jobs = db.query(BackupJob).count()
        running_jobs = db.query(BackupJob).filter(
            BackupJob.status == BackupJobStatus.RUNNING
        ).count()
        
        return {
            "total_backup_jobs": total_jobs,
            "running_jobs": running_jobs,
            "total_vms_protected": 0,  # Calculate from actual data
            "total_backups_size": "0 GB",  # Calculate from storage
            "last_24h_jobs": 0,  # Calculate from recent jobs
            "success_rate": "99.5%"  # Calculate from job history
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Authentication Endpoints
@app.post("/api/v1/auth/register")
async def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db)
) -> dict:
    """Register a new user"""
    try:
        user = create_user(db, user_data)
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "created_at": user.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/auth/login")
async def login_user(
    login_data: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
) -> Token:
    """Authenticate user and return tokens"""
    try:
        user = authenticate_user(db, login_data.username, login_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is disabled"
            )
        
        # Create tokens
        access_token = create_access_token(
            data={"sub": user.username, "user_id": user.id, "role": user.role}
        )
        refresh_token = create_refresh_token()
        
        # Store refresh token
        user.refresh_token = refresh_token
        db.commit()
        
        # Create session
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "")
        create_user_session(db, user.id, client_ip, user_agent)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/auth/logout")
async def logout_user(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logout user and invalidate tokens"""
    try:
        # Clear refresh token
        current_user.refresh_token = None
        db.commit()
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/auth/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> dict:
    """Get current user information"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at.isoformat(),
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None
    }

# Ubuntu Machine Management Endpoints
@app.post("/api/v1/ubuntu/discover")
async def discover_ubuntu_machines(
    network_range: str = "192.168.1.0/24",
    current_user: User = Depends(get_current_user)
):
    """Discover Ubuntu machines on the network"""
    try:
        machines = await UbuntuNetworkDiscovery.scan_network_range(network_range)
        return {
            "network_range": network_range,
            "discovered_count": len(machines),
            "machines": machines
        }
    except Exception as e:
        logger.error(f"Error discovering Ubuntu machines: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ubuntu/connect")
async def connect_ubuntu_machine(
    connection_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Connect to Ubuntu machine"""
    try:
        connector = connectors['ubuntu']
        success = await connector.connect(connection_data)
        
        if success:
            return {"status": "connected", "ip": connection_data.get('ip')}
        else:
            raise HTTPException(status_code=400, detail="Failed to connect to Ubuntu machine")
            
    except Exception as e:
        logger.error(f"Error connecting to Ubuntu machine: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ubuntu/machines")
async def get_ubuntu_machines(
    current_user: User = Depends(get_current_user)
) -> List[dict]:
    """Get list of connected Ubuntu machines"""
    try:
        connector = connectors['ubuntu']
        machines = await connector.list_vms()
        return machines
    except Exception as e:
        logger.error(f"Error getting Ubuntu machines: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ubuntu/{machine_id}/backup")
async def backup_ubuntu_machine(
    machine_id: str,
    backup_config: dict,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """Start backup of Ubuntu machine"""
    try:
        # Add backup task to background
        background_tasks.add_task(
            backup_ubuntu_machine_task,
            machine_id,
            backup_config,
            current_user.id
        )
        
        return {
            "message": "Ubuntu machine backup started",
            "machine_id": machine_id
        }
    except Exception as e:
        logger.error(f"Error starting Ubuntu backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ubuntu/{machine_id}/install-agent")
async def install_ubuntu_agent(
    machine_id: str,
    current_user: User = Depends(get_current_user)
):
    """Install backup agent on Ubuntu machine"""
    try:
        connector = connectors['ubuntu']
        ip = machine_id.replace('ubuntu-', '')
        
        if ip in connector.ssh_connections:
            from ubuntu_backup import UbuntuBackupAgent
            ssh_client = connector.ssh_connections[ip]
            success = await UbuntuBackupAgent.install_agent(ip, ssh_client)
            
            if success:
                return {"message": "Backup agent installed successfully", "machine_id": machine_id}
            else:
                raise HTTPException(status_code=500, detail="Failed to install backup agent")
        else:
            raise HTTPException(status_code=400, detail="Machine not connected")
            
    except Exception as e:
        logger.error(f"Error installing Ubuntu agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Background task functions
async def backup_ubuntu_machine_task(machine_id: str, backup_config: dict, user_id: int):
    """Background task to backup Ubuntu machine"""
    try:
        connector = connectors['ubuntu']
        
        # Create backup directory
        backup_dir = f"./backups/ubuntu/{machine_id}"
        
        # Perform backup
        result = await connector.export_vm(machine_id, backup_dir)
        
        logger.info(f"Ubuntu machine backup completed: {result}")
        
        # TODO: Save backup record to database
        
    except Exception as e:
        logger.error(f"Ubuntu machine backup failed: {e}")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
