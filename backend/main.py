# Updated main.py with automatic VM discovery and better persistence

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
from auth import (
    User, UserCreate, UserLogin, UserResponse, Token,
    create_access_token, create_refresh_token, get_current_user,
    admin_required, operator_required, authenticate_user,
    create_user, create_user_session, get_active_sessions,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Encryption for storing sensitive connection data
class ConnectionEncryption:
    def __init__(self):
        # In production, store this securely (environment variable, vault, etc.)
        self.key = os.getenv('ENCRYPTION_KEY', 'your-encryption-key-here-change-in-production')
        if len(self.key) < 32:
            # Generate a simple key for development
            self.key = base64.urlsafe_b64encode(b'dev-key-32-chars-long-change-me!').decode()[:32]
        self.cipher = Fernet(base64.urlsafe_b64encode(self.key.encode()[:32]))
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()

encryption = ConnectionEncryption()

# Platform Connection Manager
class PlatformConnectionManager:
    def __init__(self, connectors: Dict[PlatformType, Any]):
        self.connectors = connectors
        self.active_connections = {}
    
    async def save_connection(self, db: Session, platform: str, connection_data: Dict[str, Any]) -> PlatformConnection:
        """Save platform connection to database"""
        try:
            # Encrypt sensitive fields
            encrypted_password = encryption.encrypt(connection_data.get('password', ''))
            encrypted_ssh_key = encryption.encrypt(connection_data.get('ssh_key_path', ''))
            
            # Check if connection already exists
            existing = db.query(PlatformConnection).filter(
                PlatformConnection.platform == PlatformType(platform),
                PlatformConnection.host == connection_data['host']
            ).first()
            
            if existing:
                # Update existing connection
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
                # Create new connection
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
                    
                    # Decrypt connection data
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
                    
                    # Attempt to reconnect
                    if platform == 'ubuntu':
                        connector = self.connectors['ubuntu']
                    else:
                        connector = self.connectors[PlatformType(platform)]
                    
                    success = await connector.connect(connection_data)
                    if success:
                        restored[platform] = True
                        self.active_connections[platform] = conn
                        # Update last connected time
                        conn.last_connected = datetime.now()
                        logger.info(f"✅ Successfully restored {platform} connection")
                        
                        # Automatically discover and save VMs after successful connection
                        try:
                            await self._discover_and_save_vms(db, platform, connector)
                        except Exception as vm_error:
                            logger.warning(f"Failed to discover VMs for {platform}: {vm_error}")
                    else:
                        logger.warning(f"❌ Failed to restore {platform} connection")
                        # Mark as inactive but don't delete
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
    
    async def get_stored_connections(self, db: Session) -> List[Dict[str, Any]]:
        """Get all stored connections for display"""
        try:
            connections = db.query(PlatformConnection).all()
            result = []
            
            for conn in connections:
                result.append({
                    'id': conn.id,
                    'name': conn.name,
                    'platform': conn.platform.value,
                    'host': conn.host,
                    'port': conn.port,
                    'username': conn.username,
                    'is_active': conn.is_active,
                    'last_connected': conn.last_connected.isoformat() if conn.last_connected else None,
                    'created_at': conn.created_at.isoformat()
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting stored connections: {e}")
            return []

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
    
    # Initialize storage manager
    storage_manager = StorageManager()
    
    # Initialize default local storage
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
    
    # Initialize backup engine with storage manager
    backup_engine = BackupEngine(connectors, storage_manager)
    app.state.backup_engine = backup_engine
    
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

@app.get("/")
async def root():
    return {
        "message": "VM Backup Solution API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/api/v1/health")
async def health_check():
    platform_status = getattr(app.state, 'platform_status', {})
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "services": {
            "database": "connected",
            "backup_engine": "running",
            "scheduler": "active"
        },
        "platform_connections": platform_status
    }

# Get platform status endpoint
@app.get("/api/v1/platforms/status")
async def get_platform_status():
    """Get current platform connection status"""
    return getattr(app.state, 'platform_status', {
        'vmware': False, 'proxmox': False, 'xcpng': False, 'ubuntu': False
    })

# Get stored connections endpoint
@app.get("/api/v1/platforms/connections")
async def get_stored_connections(db: Session = Depends(get_db)):
    """Get all stored platform connections"""
    connection_manager = app.state.connection_manager
    return await connection_manager.get_stored_connections(db)

# UPDATED: Platform Management with automatic VM discovery
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
                # Still return success for connection, but note VM discovery issue
            
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
        
        # Provide more specific error messages based on common issues
        if "timeout" in str(e).lower():
            error_msg = f"Connection timeout to {platform_type.value.upper()}. Please check the host address and network connectivity."
        elif "authentication" in str(e).lower() or "credential" in str(e).lower():
            error_msg = f"Authentication failed for {platform_type.value.upper()}. Please check your username and password."
        elif "permission" in str(e).lower() or "unauthorized" in str(e).lower():
            error_msg = f"Permission denied for {platform_type.value.upper()}. Please check user permissions."
        elif "not found" in str(e).lower() or "unknown host" in str(e).lower():
            error_msg = f"Host not found for {platform_type.value.upper()}. Please check the host address."
        elif "proxmoxer" in str(e).lower():
            error_msg = f"Proxmox API library not available. Please install proxmoxer: pip install proxmoxer"
        elif "paramiko" in str(e).lower():
            error_msg = f"SSH library not available. Please install paramiko: pip install paramiko"
        
        raise HTTPException(status_code=500, detail=error_msg)

@app.delete("/api/v1/platforms/{platform_type}/disconnect")
async def disconnect_platform(
    platform_type: PlatformType,
    db: Session = Depends(get_db)
):
    """Disconnect from platform and update database"""
    try:
        connectors = app.state.connectors
        
        if platform_type.value == 'ubuntu':
            connector = connectors['ubuntu']
        else:
            connector = connectors[platform_type]
        
        # Disconnect from platform
        await connector.disconnect()
        
        # Mark connections as inactive in database
        connections = db.query(PlatformConnection).filter(
            PlatformConnection.platform == platform_type,
            PlatformConnection.is_active == True
        ).all()
        
        for conn in connections:
            conn.is_active = False
        
        db.commit()
        
        # Update platform status
        if hasattr(app.state, 'platform_status'):
            app.state.platform_status[platform_type.value] = False
        
        logger.info(f"Disconnected from {platform_type}")
        return {"status": "disconnected", "platform": platform_type}
        
    except Exception as e:
        logger.error(f"Failed to disconnect from {platform_type}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# NEW: Get all VMs from database
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
                "ip_address": vm.host,  # Using host as IP for now
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

# UPDATED: Backup Jobs with proper repository handling
@app.post("/api/v1/backup-jobs")
async def create_backup_job(
    job_data: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
) -> dict:
    """Create a new backup job"""
    try:
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
        
        # Schedule the job
        if hasattr(app.state, 'scheduler'):
            app.state.scheduler.schedule_job(db_job)
        
        logger.info(f"Created backup job: {db_job.name}")
        
        return {
            "id": db_job.id,
            "name": db_job.name,
            "status": "created",
            "vm_id": db_job.vm_id,
            "platform": db_job.platform.value,
            "backup_type": db_job.backup_type.value,
            "schedule_cron": db_job.schedule_cron
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
                "retention_days": job.retention_days,
                "compression_enabled": job.compression_enabled,
                "encryption_enabled": job.encryption_enabled,
                "last_run": job.last_run.isoformat() if job.last_run else None,
                "next_run": job.next_run.isoformat() if job.next_run else None,
                "created_at": job.created_at.isoformat()
            }
            for job in jobs
        ]
    except Exception as e:
        logger.error(f"Error listing backup jobs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/backup-jobs/{job_id}/run")
async def run_backup_job(
    job_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Manually trigger a backup job with proper status tracking"""
    try:
        job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Backup job not found")
        
        # Update job status to running
        job.status = BackupJobStatus.RUNNING
        job.last_run = datetime.now()
        db.commit()
        
        # Create backup record
        backup_record = BackupRecord(
            backup_id=f"backup-{job_id}-{int(datetime.now().timestamp())}",
            job_id=job_id,
            vm_id=job.vm_id,
            backup_type=job.backup_type,
            status="running",
            start_time=datetime.now()
        )
        db.add(backup_record)
        db.commit()
        
        # Run backup in background with status updates
        background_tasks.add_task(run_backup_with_status_updates, job, backup_record.id, db)
        
        logger.info(f"Started backup job: {job.name}")
        return {"message": "Backup job started", "job_id": job_id, "backup_record_id": backup_record.id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def run_backup_with_status_updates(job: BackupJob, backup_record_id: int, db: Session):
    """Run backup job and update status in database"""
    try:
        backup_engine = app.state.backup_engine
        
        # Run the actual backup
        result = await backup_engine.run_backup(job)
        
        # Update job and record status based on result
        db.refresh(job)
        backup_record = db.query(BackupRecord).filter(BackupRecord.id == backup_record_id).first()
        
        if result["status"] == "success":
            job.status = BackupJobStatus.COMPLETED
            if backup_record:
                backup_record.status = "completed"
                backup_record.end_time = datetime.now()
                backup_record.size_mb = result.get("size_mb", 0)
                backup_record.file_path = result.get("path", "")
        else:
            job.status = BackupJobStatus.FAILED
            if backup_record:
                backup_record.status = "failed" 
                backup_record.end_time = datetime.now()
                backup_record.error_message = result.get("error", "Unknown error")
        
        db.commit()
        logger.info(f"Backup job {job.id} completed with status: {result['status']}")
        
    except Exception as e:
        logger.error(f"Backup job {job.id} failed with exception: {e}")
        
        # Update status to failed
        db.refresh(job)
        job.status = BackupJobStatus.FAILED
        
        backup_record = db.query(BackupRecord).filter(BackupRecord.id == backup_record_id).first()
        if backup_record:
            backup_record.status = "failed"
            backup_record.end_time = datetime.now()
            backup_record.error_message = str(e)
        
        db.commit()

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
        return {"message": "Backup job deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting backup job: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Storage Management Endpoints
@app.get("/api/v1/storage/backends")
async def list_storage_backends():
    """List all configured storage backends"""
    try:
        storage_manager = app.state.storage_manager
        backends_info = []
        
        for backend_id, backend in storage_manager.backends.items():
            test_result = await backend.test_connection()
            backends_info.append({
                "id": backend_id,
                "name": backend.name,
                "storage_type": backend.storage_type,
                "capacity_gb": backend.capacity_gb,
                "is_mounted": backend.is_mounted,
                "mount_point": backend.mount_point,
                "health": test_result,
                "is_default": backend_id == storage_manager.default_backend
            })
        
        return backends_info
    except Exception as e:
        logger.error(f"Error listing storage backends: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/storage/backends")
async def create_storage_backend(
    backend_config: dict,
    db: Session = Depends(get_db)
):
    """Create and configure a new storage backend"""
    try:
        storage_manager = app.state.storage_manager
        
        # Validate configuration
        required_fields = ['name', 'storage_type']
        for field in required_fields:
            if field not in backend_config:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Create backend
        backend = storage_manager.create_backend_from_config(backend_config)
        backend_id = f"{backend_config['storage_type']}_{backend_config['name'].replace(' ', '_').lower()}"
        
        # Test connection
        test_result = await backend.test_connection()
        if test_result["status"] == "error":
            raise HTTPException(status_code=400, detail=f"Storage backend test failed: {test_result['message']}")
        
        # Connect to backend
        connected = await backend.connect()
        if not connected:
            raise HTTPException(status_code=400, detail="Failed to connect to storage backend")
        
        # Register backend
        storage_manager.register_backend(backend_id, backend)
        
        # Save to database
        db_backend = BackupRepository(
            name=backend_config['name'],
            storage_type=backend_config['storage_type'],
            connection_string=json.dumps(backend_config),
            capacity_gb=backend_config.get('capacity_gb', 0),
            encryption_enabled=True,
            settings=backend_config
        )
        db.add(db_backend)
        db.commit()
        db.refresh(db_backend)
        
        logger.info(f"Created storage backend: {backend_id}")
        return {
            "id": backend_id,
            "name": backend.name,
            "storage_type": backend.storage_type,
            "status": "connected",
            "database_id": db_backend.id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating storage backend: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/storage/backends/{backend_id}")
async def delete_storage_backend(
    backend_id: str,
    db: Session = Depends(get_db)
):
    """Delete a storage backend"""
    try:
        storage_manager = app.state.storage_manager
        
        backend = storage_manager.get_backend(backend_id)
        if not backend:
            raise HTTPException(status_code=404, detail="Storage backend not found")
        
        # Disconnect backend
        await backend.disconnect()
        
        # Remove from storage manager
        del storage_manager.backends[backend_id]
        
        # Remove from database
        db_backend = db.query(BackupRepository).filter(
            BackupRepository.name == backend.name
        ).first()
        if db_backend:
            db.delete(db_backend)
            db.commit()
        
        logger.info(f"Deleted storage backend: {backend_id}")
        return {"message": "Storage backend deleted"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting storage backend: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/storage/backends/{backend_id}/test")
async def test_storage_backend(backend_id: str):
    """Test storage backend connection"""
    try:
        storage_manager = app.state.storage_manager
        backend = storage_manager.get_backend(backend_id)
        
        if not backend:
            raise HTTPException(status_code=404, detail="Storage backend not found")
        
        test_result = await backend.test_connection()
        return test_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error testing storage backend: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/storage/backups")
async def list_all_backups():
    """List all backups across all storage backends"""
    try:
        storage_manager = app.state.storage_manager
        all_backups = await storage_manager.list_all_backups()
        
        # Flatten the results
        flattened_backups = []
        for backend_id, backups in all_backups.items():
            for backup in backups:
                backup['storage_backend_id'] = backend_id
                flattened_backups.append(backup)
        
        # Sort by creation date
        flattened_backups.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return flattened_backups
        
    except Exception as e:
        logger.error(f"Error listing all backups: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# VM Restore Endpoints
@app.post("/api/v1/restore/instant")
async def instant_restore_vm(
    restore_request: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Perform instant VM restore"""
    try:
        backup_id = restore_request.get('backup_id')
        target_platform = restore_request.get('target_platform')
        restore_config = restore_request.get('restore_config', {})
        
        if not backup_id or not target_platform:
            raise HTTPException(status_code=400, detail="backup_id and target_platform are required")
        
        backup_engine = app.state.backup_engine
        
        # Create restore record
        restore_record = BackupRecord(
            backup_id=f"restore-{backup_id}-{int(datetime.now().timestamp())}",
            job_id=0,  # Special ID for restore operations
            vm_id=restore_request.get('vm_id', 'unknown'),
            backup_type=BackupType.FULL,
            status="running",
            start_time=datetime.now(),
            record_metadata={"operation": "restore", "source_backup": backup_id}
        )
        db.add(restore_record)
        db.commit()
        db.refresh(restore_record)
        
        # Start restore in background
        background_tasks.add_task(
            perform_instant_restore, 
            backup_id, 
            PlatformType(target_platform), 
            restore_config,
            restore_record.id,
            db
        )
        
        logger.info(f"Started instant restore for backup {backup_id}")
        return {
            "message": "Instant restore started",
            "restore_record_id": restore_record.id,
            "backup_id": backup_id,
            "target_platform": target_platform
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting instant restore: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def perform_instant_restore(backup_id: str, target_platform: PlatformType, 
                                restore_config: dict, restore_record_id: int, db: Session):
    """Perform the actual instant restore operation"""
    try:
        backup_engine = app.state.backup_engine
        
        # Perform the restore
        result = await backup_engine.instant_restore(backup_id, target_platform, restore_config)
        
        # Update restore record
        restore_record = db.query(BackupRecord).filter(BackupRecord.id == restore_record_id).first()
        if restore_record:
            restore_record.status = "completed"
            restore_record.end_time = datetime.now()
            restore_record.record_metadata = {
                "operation": "restore",
                "source_backup": backup_id,
                "new_vm_id": result.get("new_vm_id"),
                "restore_time": result.get("restore_time")
            }
        
        db.commit()
        logger.info(f"Instant restore completed: {result}")
        
    except Exception as e:
        logger.error(f"Instant restore failed: {e}")
        
        # Update restore record with error
        restore_record = db.query(BackupRecord).filter(BackupRecord.id == restore_record_id).first()
        if restore_record:
            restore_record.status = "failed"
            restore_record.end_time = datetime.now()
            restore_record.error_message = str(e)
        
        db.commit()

@app.post("/api/v1/restore/files")
async def file_level_restore(
    restore_request: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Perform file-level restore"""
    try:
        backup_id = restore_request.get('backup_id')
        file_paths = restore_request.get('file_paths', [])
        target_path = restore_request.get('target_path')
        
        if not backup_id or not file_paths or not target_path:
            raise HTTPException(status_code=400, detail="backup_id, file_paths, and target_path are required")
        
        backup_engine = app.state.backup_engine
        
        # Create restore record
        restore_record = BackupRecord(
            backup_id=f"file-restore-{backup_id}-{int(datetime.now().timestamp())}",
            job_id=0,
            vm_id=restore_request.get('vm_id', 'unknown'),
            backup_type=BackupType.INCREMENTAL,
            status="running",
            start_time=datetime.now(),
            record_metadata={
                "operation": "file_restore", 
                "source_backup": backup_id,
                "file_paths": file_paths,
                "target_path": target_path
            }
        )
        db.add(restore_record)
        db.commit()
        db.refresh(restore_record)
        
        # Start file restore in background
        background_tasks.add_task(
            perform_file_restore, 
            backup_id, 
            file_paths, 
            target_path,
            restore_record.id,
            db
        )
        
        logger.info(f"Started file-level restore for backup {backup_id}")
        return {
            "message": "File-level restore started",
            "restore_record_id": restore_record.id,
            "files_count": len(file_paths)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting file restore: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def perform_file_restore(backup_id: str, file_paths: List[str], target_path: str, 
                             restore_record_id: int, db: Session):
    """Perform the actual file-level restore operation"""
    try:
        backup_engine = app.state.backup_engine
        
        # Perform the file restore
        result = await backup_engine.file_restore(backup_id, file_paths, target_path)
        
        # Update restore record
        restore_record = db.query(BackupRecord).filter(BackupRecord.id == restore_record_id).first()
        if restore_record:
            restore_record.status = "completed"
            restore_record.end_time = datetime.now()
            restore_record.record_metadata.update({
                "files_restored": result.get("files_restored", 0)
            })
        
        db.commit()
        logger.info(f"File restore completed: {result}")
        
    except Exception as e:
        logger.error(f"File restore failed: {e}")
        
        # Update restore record with error
        restore_record = db.query(BackupRecord).filter(BackupRecord.id == restore_record_id).first()
        if restore_record:
            restore_record.status = "failed"
            restore_record.end_time = datetime.now()
            restore_record.error_message = str(e)
        
        db.commit()

@app.get("/api/v1/restore/history")
async def get_restore_history(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get restore operation history"""
    try:
        restore_records = db.query(BackupRecord).filter(
            BackupRecord.job_id == 0  # Restore operations have job_id = 0
        ).order_by(BackupRecord.start_time.desc()).offset(skip).limit(limit).all()
        
        results = []
        for record in restore_records:
            results.append({
                "id": record.id,
                "backup_id": record.backup_id,
                "vm_id": record.vm_id,
                "status": record.status,
                "start_time": record.start_time.isoformat() if record.start_time else None,
                "end_time": record.end_time.isoformat() if record.end_time else None,
                "error_message": record.error_message,
                "metadata": record.record_metadata or {}
            })
        
        return results
        
    except Exception as e:
        logger.error(f"Error getting restore history: {e}")
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/api/v1/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    """Get backup system statistics from database"""
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
        
        # Calculate success rate
        if total_jobs > 0:
            success_rate = f"{(completed_jobs / total_jobs) * 100:.1f}%"
        else:
            success_rate = "N/A"
        
        # Get platform connection status
        platform_status = getattr(app.state, 'platform_status', {})
        connected_platforms = sum(platform_status.values())
        
        # Calculate storage used from backup records
        backup_records = db.query(BackupRecord).all()
        total_storage_mb = sum(record.size_mb or 0 for record in backup_records)
        total_storage_gb = total_storage_mb / 1024 if total_storage_mb > 0 else 0
        
        return {
            "total_backup_jobs": total_jobs,
            "running_jobs": running_jobs,
            "total_vms_protected": total_vms,
            "connected_platforms": connected_platforms,
            "total_backups_size": f"{total_storage_gb:.1f} GB",
            "last_24h_jobs": recent_jobs,
            "success_rate": success_rate
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Authentication endpoints (keeping existing...)
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

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
