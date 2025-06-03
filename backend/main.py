# main.py - Fixed version with proper backup listing and status updates

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio
import logging
import json
from cryptography.fernet import Fernet
import base64
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import our modules
from database import (
    get_db, init_db, Base, engine,
    VirtualMachine, BackupJob, BackupRepository, PlatformConnection, BackupRecord,
    PlatformType, BackupJobStatus, BackupType,
    VMResponse, BackupJobCreate, BackupJobResponse,
    BackupRepositoryCreate, BackupRepositoryResponse,
    PlatformConnectionCreate, PlatformConnectionResponse
)
from platform_connectors import VMwareConnector, ProxmoxConnector, XCPNGConnector
from ubuntu_backup import UbuntuBackupConnector, UbuntuNetworkDiscovery
from backup_engine import BackupEngine
from storage_manager import StorageManager, LocalStorageBackend, NFSStorageBackend, ISCSIStorageBackend
from auth import (
    User, UserCreate, UserLogin, UserResponse, Token,
    create_access_token, create_refresh_token, get_current_user,
    admin_required, operator_required, authenticate_user,
    create_user, create_user_session, get_active_sessions,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Encryption for storing sensitive connection data (keeping existing implementation)
class ConnectionEncryption:
    def __init__(self):
        self.key = os.getenv('ENCRYPTION_KEY', 'your-encryption-key-here-change-in-production')
        if len(self.key) < 32:
            self.key = base64.urlsafe_b64encode(b'dev-key-32-chars-long-change-me!').decode()[:32]
        self.cipher = Fernet(base64.urlsafe_b64encode(self.key.encode()[:32]))
    
    def encrypt(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        return self.cipher.decrypt(encrypted_data.encode()).decode()

encryption = ConnectionEncryption()

# Platform Connection Manager (keeping existing implementation)
class PlatformConnectionManager:
    def __init__(self, connectors: Dict[PlatformType, Any]):
        self.connectors = connectors
        self.active_connections = {}
    
    async def save_connection(self, db: Session, platform: str, connection_data: Dict[str, Any]) -> PlatformConnection:
        """Save platform connection to database"""
        try:
            encrypted_password = encryption.encrypt(connection_data.get('password', ''))
            encrypted_ssh_key = encryption.encrypt(connection_data.get('ssh_key_path', ''))
            
            existing = db.query(PlatformConnection).filter(
                PlatformConnection.platform == PlatformType(platform),
                PlatformConnection.host == connection_data['host']
            ).first()
            
            if existing:
                existing.username = connection_data['username']
                existing.password_encrypted = encrypted_password
                existing.port = connection_data['port']
                existing.ssl_enabled = connection_data.get('ssl_enabled', True)
                existing.is_active = True
                existing.last_connected = datetime.now()
                existing.connection_settings = {
                    'use_key': connection_data.get('use_key', False),
                    'ssh_key_path_encrypted': encrypted_ssh_key
                }
                db.commit()
                db.refresh(existing)
                return existing
            else:
                new_connection = PlatformConnection(
                    name=f"{platform}-{connection_data['host']}",
                    platform=PlatformType(platform),
                    host=connection_data['host'],
                    port=connection_data['port'],
                    username=connection_data['username'],
                    password_encrypted=encrypted_password,
                    ssl_enabled=connection_data.get('ssl_enabled', True),
                    is_active=True,
                    last_connected=datetime.now(),
                    connection_settings={
                        'use_key': connection_data.get('use_key', False),
                        'ssh_key_path_encrypted': encrypted_ssh_key
                    }
                )
                db.add(new_connection)
                db.commit()
                db.refresh(new_connection)
                return new_connection
                
        except Exception as e:
            logger.error(f"Failed to save connection: {e}")
            raise
    
    async def restore_connections(self, db: Session) -> Dict[str, bool]:
        """Restore all active platform connections from database"""
        restored = {'vmware': False, 'proxmox': False, 'xcpng': False, 'ubuntu': False}
        
        try:
            active_connections = db.query(PlatformConnection).filter(
                PlatformConnection.is_active == True
            ).all()
            
            logger.info(f"Found {len(active_connections)} stored connections to restore")
            
            for conn in active_connections:
                try:
                    platform = conn.platform.value
                    logger.info(f"Restoring connection to {platform} ({conn.host})")
                    
                    password = encryption.decrypt(conn.password_encrypted) if conn.password_encrypted else ''
                    ssh_key_path = ''
                    use_key = False
                    
                    if conn.connection_settings:
                        use_key = conn.connection_settings.get('use_key', False)
                        encrypted_ssh_key = conn.connection_settings.get('ssh_key_path_encrypted', '')
                        if encrypted_ssh_key:
                            ssh_key_path = encryption.decrypt(encrypted_ssh_key)
                    
                    connection_data = {
                        'host': conn.host,
                        'username': conn.username,
                        'password': password,
                        'port': conn.port,
                        'use_key': use_key,
                        'ssh_key_path': ssh_key_path
                    }
                    
                    if platform == 'ubuntu':
                        connector = self.connectors['ubuntu']
                    else:
                        connector = self.connectors[PlatformType(platform)]
                    
                    success = await connector.connect(connection_data)
                    if success:
                        restored[platform] = True
                        self.active_connections[platform] = conn
                        conn.last_connected = datetime.now()
                        logger.info(f"✅ Successfully restored {platform} connection")
                        
                        try:
                            await self._discover_and_save_vms(db, platform, connector)
                        except Exception as vm_error:
                            logger.warning(f"Failed to discover VMs for {platform}: {vm_error}")
                    else:
                        logger.warning(f"❌ Failed to restore {platform} connection")
                        conn.is_active = False
                        
                except Exception as e:
                    logger.error(f"Error restoring {conn.platform.value} connection: {e}")
                    conn.is_active = False
            
            db.commit()
            return restored
            
        except Exception as e:
            logger.error(f"Error restoring connections: {e}")
            return restored
    
    async def _discover_and_save_vms(self, db: Session, platform: str, connector):
        """Discover VMs from platform and save to database"""
        try:
            logger.info(f"Discovering VMs from {platform}...")
            vms = await connector.list_vms()
            
            for vm_data in vms:
                existing_vm = db.query(VirtualMachine).filter(
                    VirtualMachine.vm_id == vm_data['vm_id'],
                    VirtualMachine.platform == PlatformType(platform)
                ).first()
                
                if existing_vm:
                    existing_vm.name = vm_data['name']
                    existing_vm.host = vm_data['host']
                    existing_vm.cpu_count = vm_data['cpu_count']
                    existing_vm.memory_mb = vm_data['memory_mb']
                    existing_vm.disk_size_gb = vm_data['disk_size_gb']
                    existing_vm.operating_system = vm_data['operating_system']
                    existing_vm.power_state = vm_data['power_state']
                    existing_vm.updated_at = datetime.now()
                else:
                    new_vm = VirtualMachine(
                        vm_id=vm_data['vm_id'],
                        name=vm_data['name'],
                        platform=PlatformType(platform),
                        host=vm_data['host'],
                        cpu_count=vm_data['cpu_count'],
                        memory_mb=vm_data['memory_mb'],
                        disk_size_gb=vm_data['disk_size_gb'],
                        operating_system=vm_data['operating_system'],
                        power_state=vm_data['power_state']
                    )
                    db.add(new_vm)
            
            db.commit()
            logger.info(f"Successfully saved {len(vms)} VMs from {platform}")
            
        except Exception as e:
            logger.error(f"Failed to discover/save VMs for {platform}: {e}")

# Enhanced Backup Job Scheduler with proper status updates
class BackupJobScheduler:
    def __init__(self, backup_engine: BackupEngine):
        self.backup_engine = backup_engine
        self.scheduled_jobs = {}
        self.running = False
        
    def start(self):
        self.running = True
        logger.info("Backup job scheduler started")
        
    def stop(self):
        self.running = False
        logger.info("Backup job scheduler stopped")
        
    def schedule_job(self, backup_job):
        self.scheduled_jobs[backup_job.id] = backup_job
        logger.info(f"Scheduled backup job: {backup_job.name} (ID: {backup_job.id})")
        
    def remove_job(self, job_id: int):
        if job_id in self.scheduled_jobs:
            del self.scheduled_jobs[job_id]
            logger.info(f"Removed scheduled job: {job_id}")
            
    async def run_job(self, job_id: int) -> Dict[str, Any]:
        if job_id not in self.scheduled_jobs:
            raise Exception(f"Job {job_id} not found in scheduler")
            
        backup_job = self.scheduled_jobs[job_id]
        return await self.backup_engine.run_backup(backup_job)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing VM Backup Solution...")
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    
    # Initialize platform connectors
    connectors = {
        PlatformType.VMWARE: VMwareConnector(),
        PlatformType.PROXMOX: ProxmoxConnector(),
        PlatformType.XCPNG: XCPNGConnector(),
        'ubuntu': UbuntuBackupConnector()
    }
    
    # Initialize connection manager
    connection_manager = PlatformConnectionManager(connectors)
    app.state.connectors = connectors
    app.state.connection_manager = connection_manager
    
    # Initialize storage manager with default backends
    storage_manager = StorageManager()
    
    # Create default local storage backend
    default_local_config = {
        'name': 'Default Local Storage',
        'storage_type': 'local',
        'path': '/app/backups',
        'capacity_gb': 1000
    }
    default_backend = LocalStorageBackend(default_local_config)
    storage_manager.register_backend('default_local', default_backend)
    
    # Connect storage backends
    await storage_manager.connect_all()
    app.state.storage_manager = storage_manager
    
    # Initialize production backup engine
    backup_engine = BackupEngine(connectors, storage_manager)
    app.state.backup_engine = backup_engine
    
    # Initialize backup job scheduler
    scheduler = BackupJobScheduler(backup_engine)
    scheduler.start()
    app.state.scheduler = scheduler
    
    # Restore platform connections from database
    logger.info("Restoring platform connections from database...")
    db = next(get_db())
    try:
        restored = await connection_manager.restore_connections(db)
        connected_count = sum(restored.values())
        logger.info(f"✅ Restored {connected_count} platform connections: {restored}")
        app.state.platform_status = restored
    except Exception as e:
        logger.error(f"Failed to restore connections: {e}")
        app.state.platform_status = {'vmware': False, 'proxmox': False, 'xcpng': False, 'ubuntu': False}
    finally:
        db.close()
    
    logger.info("🚀 VM Backup Solution API started successfully!")
    yield
    
    # Shutdown
    if hasattr(app.state, 'scheduler'):
        app.state.scheduler.stop()
    
    if hasattr(app.state, 'storage_manager'):
        await app.state.storage_manager.disconnect_all()
        
    logger.info("VM Backup Solution API stopped!")

app = FastAPI(
    title="VM Backup Solution API",
    description="Production-grade VM backup and recovery solution for VMware, Proxmox, XCP-NG, and Ubuntu",
    version="2.0.0",
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

@app.get("/")
async def root():
    return {
        "message": "VM Backup Solution API - Production Ready",
        "version": "2.0.0",
        "status": "running",
        "features": [
            "Multi-platform VM backup (VMware, Proxmox, XCP-NG, Ubuntu)",
            "Multiple storage backends (Local, NFS, iSCSI)",
            "Full/Incremental/Differential backups",
            "Instant VM restore",
            "File-level restore",
            "Backup encryption and compression",
            "Real-time job monitoring"
        ]
    }

@app.get("/api/v1/health")
async def health_check():
    """Enhanced health check with actual status reporting"""
    platform_status = getattr(app.state, 'platform_status', {})
    
    # Test storage manager health
    storage_health = {"status": "unknown", "message": "Storage manager not initialized"}
    storage_stats = {"total_backends": 0, "connected_backends": 0, "total_capacity_gb": 0, "total_available_gb": 0}
    
    if hasattr(app.state, 'storage_manager'):
        try:
            storage_stats = await app.state.storage_manager.get_storage_statistics()
            if storage_stats["connected_backends"] > 0:
                storage_health = {"status": "healthy", "message": f"{storage_stats['connected_backends']} backends connected"}
            else:
                storage_health = {"status": "error", "message": "No storage backends connected"}
        except Exception as e:
            storage_health = {"status": "error", "message": f"Storage error: {e}"}
    
    # Test database health
    db_health = {"status": "unknown", "message": "Database not tested"}
    try:
        db = next(get_db())
        user_count = db.query(User).count()
        db.close()
        db_health = {"status": "healthy", "message": f"Database connected ({user_count} users)"}
    except Exception as e:
        db_health = {"status": "error", "message": f"Database error: {e}"}
    
    # Test backup engine health
    engine_health = {"status": "unknown", "message": "Backup engine not tested"}
    if hasattr(app.state, 'backup_engine'):
        try:
            active_jobs = app.state.backup_engine.get_all_active_jobs()
            engine_health = {"status": "healthy", "message": f"Engine running ({len(active_jobs)} active jobs)"}
        except Exception as e:
            engine_health = {"status": "error", "message": f"Engine error: {e}"}
    
    # Test scheduler health
    scheduler_health = {"status": "unknown", "message": "Scheduler not tested"}
    if hasattr(app.state, 'scheduler') and app.state.scheduler.running:
        scheduled_count = len(app.state.scheduler.scheduled_jobs)
        scheduler_health = {"status": "healthy", "message": f"Scheduler active ({scheduled_count} jobs)"}
    else:
        scheduler_health = {"status": "error", "message": "Scheduler not running"}
    
    return {
        "status": "healthy" if all(h.get("status") == "healthy" for h in [storage_health, db_health, engine_health, scheduler_health]) else "warning",
        "timestamp": datetime.now(),
        "services": {
            "database": db_health,
            "backup_engine": engine_health,
            "scheduler": scheduler_health,
            "storage_manager": storage_health
        },
        "platform_connections": platform_status,
        "storage_backends": {
            "total": storage_stats["total_backends"],
            "connected": storage_stats["connected_backends"],
            "total_capacity_gb": storage_stats["total_capacity_gb"],
            "available_gb": storage_stats["total_available_gb"]
        }
    }

# Platform Management Endpoints
@app.get("/api/v1/platforms/status")
async def get_platform_status():
    """Get current platform connection status with actual connectivity"""
    status = getattr(app.state, 'platform_status', {
        'vmware': False, 'proxmox': False, 'xcpng': False, 'ubuntu': False
    })
    
    # Test actual connectivity for each platform
    actual_status = {}
    connectors = getattr(app.state, 'connectors', {})
    
    for platform in ['vmware', 'proxmox', 'xcpng', 'ubuntu']:
        try:
            if platform == 'ubuntu':
                connector = connectors.get('ubuntu')
            else:
                connector = connectors.get(PlatformType(platform))
            
            if connector and hasattr(connector, 'connected'):
                actual_status[platform] = connector.connected
            else:
                actual_status[platform] = False
        except Exception:
            actual_status[platform] = False
    
    # Update app state with actual status
    app.state.platform_status = actual_status
    
    return actual_status

@app.post("/api/v1/platforms/{platform_type}/connect")
async def connect_platform(
    platform_type: PlatformType,
    connection_data: dict,
    db: Session = Depends(get_db)
):
    """Connect to a virtualization platform with automatic VM discovery"""
    try:
        logger.info(f"Attempting to connect to {platform_type} at {connection_data.get('host')}")
        
        connectors = app.state.connectors
        connection_manager = app.state.connection_manager
        
        if platform_type.value == 'ubuntu':
            connector = connectors['ubuntu']
        else:
            connector = connectors[platform_type]
        
        # Attempt connection
        success = await connector.connect(connection_data)
        
        if success:
            # Save connection to database
            saved_connection = await connection_manager.save_connection(
                db, platform_type.value, connection_data
            )
            
            # Update platform status in app state
            if not hasattr(app.state, 'platform_status'):
                app.state.platform_status = {'vmware': False, 'proxmox': False, 'xcpng': False, 'ubuntu': False}
            
            app.state.platform_status[platform_type.value] = True
            
            # AUTOMATICALLY DISCOVER AND SAVE VMs
            try:
                logger.info(f"Discovering VMs from {platform_type}...")
                vms = await connector.list_vms()
                
                vm_count = 0
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
                    vm_count += 1
                
                db.commit()
                logger.info(f"Successfully discovered and saved {vm_count} VMs from {platform_type}")
                
            except Exception as vm_error:
                logger.warning(f"VM discovery failed for {platform_type}: {vm_error}")
            
            logger.info(f"Successfully connected and saved {platform_type}")
            return {
                "status": "connected", 
                "platform": platform_type,
                "message": f"Successfully connected to {platform_type.value.upper()}",
                "connection_id": saved_connection.id,
                "vms_discovered": vm_count if 'vm_count' in locals() else 0
            }
        else:
            error_msg = f"Failed to connect to {platform_type.value.upper()}: Connection test failed"
            logger.error(error_msg)
            raise HTTPException(status_code=400, detail=error_msg)
            
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Failed to connect to {platform_type.value.upper()}: {str(e)}"
        logger.error(f"Platform connection error: {e}")
        raise HTTPException(status_code=500, detail=error_msg)

# VM Management Endpoints
@app.get("/api/v1/vms")
async def get_all_vms(db: Session = Depends(get_db)) -> List[dict]:
    """Get all VMs from database"""
    try:
        vms = db.query(VirtualMachine).all()
        return [
            {
                "id": vm.id,
                "vm_id": vm.vm_id,
                "name": vm.name,
                "platform": vm.platform.value,
                "host": vm.host,
                "ip_address": vm.host,
                "cpu_count": vm.cpu_count,
                "memory_mb": vm.memory_mb,
                "disk_size_gb": vm.disk_size_gb,
                "operating_system": vm.operating_system,
                "power_state": vm.power_state,
                "created_at": vm.created_at.isoformat()
            }
            for vm in vms
        ]
    except Exception as e:
        logger.error(f"Error getting all VMs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Enhanced Backup Jobs Management with proper status updates
@app.post("/api/v1/backup-jobs")
async def create_backup_job(
    job_data: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
) -> dict:
    """Create a new backup job with enhanced validation"""
    try:
        # Validate VM exists
        vm = db.query(VirtualMachine).filter(
            VirtualMachine.vm_id == job_data['vm_id']
        ).first()
        
        if not vm:
            raise HTTPException(status_code=404, detail=f"VM {job_data['vm_id']} not found")
        
        # Ensure default repository exists
        default_repo = db.query(BackupRepository).filter(
            BackupRepository.id == 1
        ).first()
        
        if not default_repo:
            # Create default repository
            default_repo = BackupRepository(
                id=1,
                name="Default Local Storage",
                storage_type="local",
                connection_string="/app/backups",
                capacity_gb=1000,
                encryption_enabled=True,
                settings={"compression": True}
            )
            db.add(default_repo)
            db.commit()
            db.refresh(default_repo)
        
        # Create job in database
        db_job = BackupJob(
            name=job_data['name'],
            description=job_data.get('description', ''),
            vm_id=job_data['vm_id'],
            platform=PlatformType(job_data['platform']),
            backup_type=BackupType(job_data['backup_type']),
            repository_id=job_data.get('repository_id', 1),
            schedule_cron=job_data['schedule_cron'],
            retention_days=job_data.get('retention_days', 30),
            compression_enabled=job_data.get('compression_enabled', True),
            encryption_enabled=job_data.get('encryption_enabled', True)
        )
        db.add(db_job)
        db.commit()
        db.refresh(db_job)
        
        # Schedule the job in the scheduler
        if hasattr(app.state, 'scheduler'):
            app.state.scheduler.schedule_job(db_job)
        
        logger.info(f"Created backup job: {db_job.name} for VM {vm.name}")
        
        return {
            "id": db_job.id,
            "name": db_job.name,
            "status": "created",
            "vm_id": db_job.vm_id,
            "vm_name": vm.name,
            "platform": db_job.platform.value,
            "backup_type": db_job.backup_type.value,
            "schedule_cron": db_job.schedule_cron,
            "compression_enabled": db_job.compression_enabled,
            "encryption_enabled": db_job.encryption_enabled,
            "retention_days": db_job.retention_days
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/backup-jobs")
async def list_backup_jobs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
) -> List[dict]:
    """List all backup jobs with enhanced information and real-time status"""
    try:
        jobs = db.query(BackupJob).offset(skip).limit(limit).all()
        result = []
        
        for job in jobs:
            # Get VM name
            vm = db.query(VirtualMachine).filter(
                VirtualMachine.vm_id == job.vm_id
            ).first()
            
            # Get job status from backup engine
            job_status = None
            current_engine_status = "idle"
            if hasattr(app.state, 'backup_engine'):
                job_status = app.state.backup_engine.get_job_status(job.id)
                if job_status:
                    current_engine_status = job_status.get("status", "idle")
            
            # Use engine status if available, otherwise database status
            display_status = current_engine_status if job_status else job.status.value
            
            result.append({
                "id": job.id,
                "name": job.name,
                "description": job.description,
                "vm_id": job.vm_id,
                "vm_name": vm.name if vm else job.vm_id,
                "platform": job.platform.value,
                "backup_type": job.backup_type.value,
                "status": display_status,
                "schedule_cron": job.schedule_cron,
                "retention_days": job.retention_days,
                "compression_enabled": job.compression_enabled,
                "encryption_enabled": job.encryption_enabled,
                "last_run": job.last_run.isoformat() if job.last_run else None,
                "next_run": job.next_run.isoformat() if job.next_run else None,
                "created_at": job.created_at.isoformat(),
                "current_status": job_status
            })
        
        return result
    except Exception as e:
        logger.error(f"Error listing backup jobs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/backup-jobs/{job_id}/run")
async def run_backup_job(
    job_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Manually trigger a backup job with real backup execution and proper status updates"""
    try:
        job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Backup job not found")
        
        # Check if job is already running
        if hasattr(app.state, 'backup_engine'):
            current_status = app.state.backup_engine.get_job_status(job_id)
            if current_status and current_status.get("status") == "running":
                raise HTTPException(status_code=409, detail="Backup job is already running")
        
        # Update job status to running
        job.status = BackupJobStatus.RUNNING
        job.last_run = datetime.now()
        db.commit()
        
        # Run backup in background using the scheduler
        background_tasks.add_task(execute_backup_job, job_id)
        
        logger.info(f"Started backup job: {job.name}")
        return {
            "message": "Backup job started successfully",
            "job_id": job_id,
            "job_name": job.name,
            "started_at": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/backup-jobs/{job_id}/status")
async def get_backup_job_status(job_id: int, db: Session = Depends(get_db)):
    """Get real-time status of a backup job"""
    try:
        # First check engine status
        if hasattr(app.state, 'backup_engine'):
            status = app.state.backup_engine.get_job_status(job_id)
            if status:
                return status
        
        # Fallback to database status
        job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Backup job not found")
        
        return {
            "job_id": job_id,
            "status": job.status.value,
            "last_run": job.last_run.isoformat() if job.last_run else None,
            "progress": 0,
            "current_operation": "Idle"
        }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job status: {e}")
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
        
        job_name = job.name
        db.delete(job)
        db.commit()
        
        logger.info(f"Deleted backup job: {job_name}")
        return {"message": "Backup job deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def execute_backup_job(job_id: int):
    """Execute backup job using the production backup engine with proper status updates"""
    db = next(get_db())
    try:
        scheduler = app.state.scheduler
        backup_engine = app.state.backup_engine
        
        # Get fresh job object
        job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
        if not job:
            logger.error(f"Job {job_id} not found")
            return
        
        logger.info(f"Executing backup job {job_id}: {job.name}")
        
        # Run the actual backup using the production engine
        result = await scheduler.run_job(job_id)
        
        # Update job status based on result
        if result["status"] == "success":
            job.status = BackupJobStatus.COMPLETED
            logger.info(f"✅ Backup job {job_id} completed successfully")
            logger.info(f"   - Backup ID: {result['backup_id']}")
            logger.info(f"   - Size: {result['size_mb']} MB")
            logger.info(f"   - Storage: {result['storage_backend']}")
        else:
            job.status = BackupJobStatus.FAILED
            logger.error(f"❌ Backup job {job_id} failed: {result.get('error')}")
        
        db.commit()
        
    except Exception as e:
        logger.error(f"Backup job {job_id} failed with exception: {e}")
        
        # Update status to failed
        job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
        if job:
            job.status = BackupJobStatus.FAILED
        db.commit()
    finally:
        db.close()

# Enhanced Storage Backend Endpoints
@app.get("/api/v1/storage/backends")
async def list_storage_backends():
    """List all configured storage backends with detailed health information"""
    try:
        storage_manager = app.state.storage_manager
        backends_info = []
        
        for backend_id, backend in storage_manager.backends.items():
            health = await backend.test_connection()
            backends_info.append({
                "id": backend_id,
                "name": backend.name,
                "storage_type": backend.storage_type,
                "capacity_gb": backend.capacity_gb,
                "is_mounted": backend.is_mounted,
                "mount_point": backend.mount_point,
                "health": health,
                "is_default": backend_id == storage_manager.default_backend,
                "backup_count": len(backend.backup_index)
            })
        
        return backends_info
    except Exception as e:
        logger.error(f"Error listing storage backends: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/storage/backends")
async def create_storage_backend(config: dict):
    """Create a new storage backend with validation"""
    try:
        storage_manager = app.state.storage_manager
        
        # Validate configuration
        required_fields = ['name', 'storage_type']
        for field in required_fields:
            if field not in config:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Generate backend ID
        backend_id = f"{config['storage_type']}_{config['name'].lower().replace(' ', '_')}"
        
        # Check if backend already exists
        if storage_manager.get_backend(backend_id):
            raise HTTPException(status_code=409, detail=f"Storage backend {backend_id} already exists")
        
        # Create backend
        backend = storage_manager.create_backend_from_config(config)
        
        # Register backend
        storage_manager.register_backend(backend_id, backend)
        
        # Connect backend and validate
        success = await backend.connect()
        if not success:
            raise HTTPException(status_code=400, detail="Failed to connect to new storage backend")
        
        logger.info(f"Created and connected storage backend: {config['name']}")
        return {
            "message": "Storage backend created successfully",
            "backend_id": backend_id,
            "name": config['name'],
            "storage_type": config['storage_type']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating storage backend: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/storage/statistics")
async def get_storage_statistics():
    """Get comprehensive storage statistics"""
    try:
        storage_manager = app.state.storage_manager
        stats = await storage_manager.get_storage_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting storage statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Enhanced Backup and Restore Endpoints with proper listing
@app.get("/api/v1/storage/backups")
async def list_all_backups():
    """FIXED: List all backups from all storage backends with proper database integration"""
    try:
        # Get backups from both storage backends AND database
        db = next(get_db())
        try:
            # Get all backup records from database
            db_records = db.query(BackupRecord).filter(
                BackupRecord.status == "completed"
            ).all()
            
            all_backups = []
            
            # Process database records first
            for record in db_records:
                try:
                    # Parse metadata if available
                    vm_name = record.vm_id
                    platform = "unknown"
                    backup_type = "unknown"
                    created_at = record.start_time
                    
                    if record.record_metadata:
                        metadata = record.record_metadata
                        vm_name = metadata.get("vm_name", record.vm_id)
                        platform = metadata.get("platform", "unknown")
                        backup_type = metadata.get("backup_type", "unknown")
                        created_at_str = metadata.get("created_at")
                        if created_at_str:
                            try:
                                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                            except:
                                created_at = record.start_time
                    
                    backup_info = {
                        "backup_id": record.backup_id,
                        "job_id": record.job_id,
                        "vm_id": record.vm_id,
                        "vm_name": vm_name,
                        "platform": platform,
                        "backup_type": backup_type,
                        "size_mb": record.size_mb or 0,
                        "compressed_size_mb": record.compressed_size_mb,
                        "file_path": record.file_path,
                        "checksum": record.checksum,
                        "status": record.status,
                        "created_at": created_at.isoformat() if created_at else None,
                        "storage_backend_id": record.record_metadata.get("storage_backend") if record.record_metadata else "default_local",
                        "compressed": record.record_metadata.get("compressed", False) if record.record_metadata else False,
                        "encrypted": record.record_metadata.get("encrypted", False) if record.record_metadata else False
                    }
                    all_backups.append(backup_info)
                    
                except Exception as e:
                    logger.warning(f"Failed to process backup record {record.backup_id}: {e}")
                    continue
            
            # Also get backups from storage backends (in case of orphaned files)
            if hasattr(app.state, 'storage_manager'):
                try:
                    storage_backups = await app.state.storage_manager.list_all_backups()
                    
                    # Add storage backups that aren't in database
                    db_backup_ids = {backup["backup_id"] for backup in all_backups}
                    
                    for backend_id, backend_backups in storage_backups.items():
                        for storage_backup in backend_backups:
                            backup_id = storage_backup.get("backup_id")
                            if backup_id and backup_id not in db_backup_ids:
                                # This backup is in storage but not in database
                                storage_backup["storage_backend_id"] = backend_id
                                storage_backup["status"] = "orphaned"
                                all_backups.append(storage_backup)
                                
                except Exception as e:
                    logger.warning(f"Failed to get storage backups: {e}")
            
            # Sort by creation date (newest first)
            all_backups.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            
            logger.info(f"Retrieved {len(all_backups)} total backups")
            return all_backups
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error listing all backups: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/restore/instant")
async def instant_restore_vm(
    restore_request: dict,
    background_tasks: BackgroundTasks
):
    """Perform instant VM restore using production engine"""
    try:
        backup_id = restore_request.get('backup_id')
        target_platform = restore_request.get('target_platform')
        restore_config = restore_request.get('restore_config', {})
        
        if not backup_id or not target_platform:
            raise HTTPException(status_code=400, detail="backup_id and target_platform are required")
        
        backup_engine = app.state.backup_engine
        
        # Validate restore request
        try:
            await backup_engine._validate_restore_request(
                backup_id, PlatformType(target_platform), restore_config
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Restore validation failed: {e}")
        
        # Start restore in background
        background_tasks.add_task(
            perform_instant_restore_task, 
            backup_id, 
            target_platform, 
            restore_config
        )
        
        logger.info(f"Started instant restore for backup {backup_id}")
        return {
            "message": "Instant restore started successfully",
            "backup_id": backup_id,
            "target_platform": target_platform,
            "status": "in_progress"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting instant restore: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def perform_instant_restore_task(backup_id: str, target_platform: str, restore_config: dict):
    """Perform the actual instant restore operation"""
    try:
        backup_engine = app.state.backup_engine
        
        result = await backup_engine.instant_restore(
            backup_id, PlatformType(target_platform), restore_config
        )
        
        logger.info(f"✅ Instant restore completed successfully: {result}")
        
    except Exception as e:
        logger.error(f"❌ Instant restore failed: {e}")

@app.post("/api/v1/restore/files")
async def file_restore(
    restore_request: dict,
    background_tasks: BackgroundTasks
):
    """Perform file-level restore using production engine"""
    try:
        backup_id = restore_request.get('backup_id')
        file_paths = restore_request.get('file_paths', [])
        target_path = restore_request.get('target_path')
        
        if not backup_id or not file_paths or not target_path:
            raise HTTPException(status_code=400, detail="backup_id, file_paths, and target_path are required")
        
        backup_engine = app.state.backup_engine
        
        # Start file restore in background
        background_tasks.add_task(
            perform_file_restore_task,
            backup_id,
            file_paths,
            target_path
        )
        
        logger.info(f"Started file restore for backup {backup_id}")
        return {
            "message": "File restore started successfully",
            "backup_id": backup_id,
            "file_count": len(file_paths),
            "target_path": target_path,
            "status": "in_progress"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting file restore: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def perform_file_restore_task(backup_id: str, file_paths: List[str], target_path: str):
    """Perform the actual file restore operation"""
    try:
        backup_engine = app.state.backup_engine
        
        result = await backup_engine.file_restore(backup_id, file_paths, target_path)
        
        logger.info(f"✅ File restore completed successfully: {result}")
        
    except Exception as e:
        logger.error(f"❌ File restore failed: {e}")

# Enhanced Statistics endpoint
@app.get("/api/v1/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    """Get comprehensive backup system statistics with actual data"""
    try:
        # Get VM counts
        total_vms = db.query(VirtualMachine).count()
        
        # Get backup job counts
        total_jobs = db.query(BackupJob).count()
        running_jobs = db.query(BackupJob).filter(
            BackupJob.status == BackupJobStatus.RUNNING
        ).count()
        completed_jobs = db.query(BackupJob).filter(
            BackupJob.status == BackupJobStatus.COMPLETED
        ).count()
        
        # Calculate recent jobs (last 24 hours)
        yesterday = datetime.now() - timedelta(days=1)
        recent_jobs = db.query(BackupJob).filter(
            BackupJob.last_run >= yesterday
        ).count()
        
        # Calculate success rate based on backup records
        total_backup_attempts = db.query(BackupRecord).count()
        successful_backups = db.query(BackupRecord).filter(
            BackupRecord.status == "completed"
        ).count()
        
        if total_backup_attempts > 0:
            success_rate = f"{(successful_backups / total_backup_attempts) * 100:.1f}%"
        else:
            success_rate = "N/A"
        
        # Get platform connection status
        platform_status = getattr(app.state, 'platform_status', {})
        connected_platforms = sum(platform_status.values())
        
        # Calculate storage used from backup records
        backup_records = db.query(BackupRecord).filter(
            BackupRecord.status == "completed"
        ).all()
        total_storage_mb = sum(record.size_mb or 0 for record in backup_records)
        total_storage_gb = total_storage_mb / 1024 if total_storage_mb > 0 else 0
        
        # Get storage statistics
        storage_stats = {"total_backends": 0, "storage_capacity_gb": 0, "storage_available_gb": 0}
        try:
            storage_stats = await app.state.storage_manager.get_storage_statistics()
        except Exception as e:
            logger.warning(f"Failed to get storage statistics: {e}")
        
        return {
            "total_backup_jobs": total_jobs,
            "running_jobs": running_jobs,
            "total_vms_protected": total_vms,
            "connected_platforms": connected_platforms,
            "total_backups_size": f"{total_storage_gb:.1f} GB",
            "last_24h_jobs": recent_jobs,
            "success_rate": success_rate,
            "storage_backends": storage_stats.get("total_backends", 0),
            "storage_capacity_gb": storage_stats.get("total_capacity_gb", 0),
            "storage_available_gb": storage_stats.get("total_available_gb", 0),
            "total_backup_attempts": total_backup_attempts,
            "successful_backups": successful_backups
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Authentication endpoints (keeping existing)
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

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
