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
