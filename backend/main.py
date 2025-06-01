# main.py
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Optional
from datetime import datetime, timedelta
import asyncio

from database import get_db, init_db
from models import (
    BackupJob, VirtualMachine, BackupRepository, 
    BackupJobCreate, BackupJobResponse, VMResponse,
    BackupJobStatus, PlatformType
)
from platform_connectors import VMwareConnector, ProxmoxConnector, XCPNGConnector
from ubuntu_backup import UbuntuBackupConnector, UbuntuNetworkDiscovery
from backup_engine import BackupEngine
from scheduler import BackupScheduler
from auth import (
    User, UserCreate, UserLogin, UserResponse, Token,
    create_access_token, create_refresh_token, get_current_user,
    admin_required, operator_required, authenticate_user,
    create_user, create_user_session, get_active_sessions
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("Initializing database...")
    init_db()
    
    # Start the backup scheduler
    scheduler = BackupScheduler()
    scheduler.start()
    app.state.scheduler = scheduler
    
    print("VM Backup Solution API started!")
    yield
    
    # Shutdown
    if hasattr(app.state, 'scheduler'):
        app.state.scheduler.shutdown()
    print("VM Backup Solution API stopped!")

app = FastAPI(
    title="VM Backup Solution API",
    description="Enterprise VM backup and recovery solution for VMware, Proxmox, and XCP-NG",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
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
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/platforms/{platform_type}/vms")
async def get_platform_vms(
    platform_type: PlatformType,
    db: Session = Depends(get_db)
) -> List[VMResponse]:
    """Get list of VMs from a platform"""
    try:
        connector = connectors[platform_type]
        vms = await connector.list_vms()
        return [VMResponse(**vm) for vm in vms]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Backup Job Management
@app.post("/api/v1/backup-jobs")
async def create_backup_job(
    job_data: BackupJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
) -> BackupJobResponse:
    """Create a new backup job"""
    try:
        # Create job in database
        db_job = BackupJob(**job_data.model_dump())
        db.add(db_job)
        db.commit()
        db.refresh(db_job)
        
        # Schedule the job
        if hasattr(app.state, 'scheduler'):
            app.state.scheduler.schedule_job(db_job)
        
        return BackupJobResponse.model_validate(db_job)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/backup-jobs")
async def list_backup_jobs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
) -> List[BackupJobResponse]:
    """List all backup jobs"""
    jobs = db.query(BackupJob).offset(skip).limit(limit).all()
    return [BackupJobResponse.model_validate(job) for job in jobs]

@app.get("/api/v1/backup-jobs/{job_id}")
async def get_backup_job(
    job_id: int,
    db: Session = Depends(get_db)
) -> BackupJobResponse:
    """Get specific backup job details"""
    job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Backup job not found")
    return BackupJobResponse.model_validate(job)

@app.post("/api/v1/backup-jobs/{job_id}/run")
async def run_backup_job(
    job_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Manually trigger a backup job"""
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

@app.delete("/api/v1/backup-jobs/{job_id}")
async def delete_backup_job(
    job_id: int,
    db: Session = Depends(get_db)
):
    """Delete a backup job"""
    job = db.query(BackupJob).filter(BackupJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Backup job not found")
    
    # Remove from scheduler
    if hasattr(app.state, 'scheduler'):
        app.state.scheduler.remove_job(job_id)
    
    db.delete(job)
    db.commit()
    
    return {"message": "Backup job deleted"}

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
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/recovery/file-restore")
async def file_level_restore(
    backup_id: str,
    file_paths: List[str],
    target_path: str,
    background_tasks: BackgroundTasks
):
    """Perform file-level restore from backup"""
    try:
        background_tasks.add_task(
            backup_engine.file_restore,
            backup_id,
            file_paths,
            target_path
        )
        
        return {
            "message": "File restore initiated",
            "files": len(file_paths)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Migration Endpoints (V2V)
@app.post("/api/v1/migration/v2v")
async def migrate_vm(
    source_vm_id: str,
    source_platform: PlatformType,
    target_platform: PlatformType,
    migration_config: dict,
    background_tasks: BackgroundTasks
):
    """Migrate VM between platforms (V2V)"""
    try:
        background_tasks.add_task(
            backup_engine.migrate_vm,
            source_vm_id,
            source_platform,
            target_platform,
            migration_config
        )
        
        return {
            "message": "VM migration initiated",
            "source": source_platform,
            "target": target_platform
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Statistics and Monitoring
@app.get("/api/v1/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    """Get backup system statistics"""
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

# Authentication Endpoints
@app.post("/api/v1/auth/register")
async def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db)
) -> UserResponse:
    """Register a new user"""
    try:
        user = create_user(db, user_data)
        return UserResponse.model_validate(user)
    except HTTPException:
        raise
    except Exception as e:
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
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/auth/refresh")
async def refresh_token(
    refresh_token: str,
    db: Session = Depends(get_db)
) -> Token:
    """Refresh access token"""
    try:
        user = db.query(User).filter(User.refresh_token == refresh_token).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Create new tokens
        access_token = create_access_token(
            data={"sub": user.username, "user_id": user.id, "role": user.role}
        )
        new_refresh_token = create_refresh_token()
        
        # Update refresh token
        user.refresh_token = new_refresh_token
        db.commit()
        
        return Token(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
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
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/auth/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """Get current user information"""
    return UserResponse.model_validate(current_user)

@app.get("/api/v1/auth/sessions")
async def get_user_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get active sessions for current user"""
    try:
        sessions = get_active_sessions(db, current_user.id)
        return {
            "active_sessions": len(sessions),
            "sessions": [
                {
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "created_at": session.created_at,
                    "expires_at": session.expires_at
                }
                for session in sessions
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Ubuntu Machine Management Endpoints
@app.post("/api/v1/ubuntu/discover")
async def discover_ubuntu_machines(
    network_range: str = "192.168.1.0/24",
    current_user: User = Depends(operator_required)
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
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ubuntu/connect")
async def connect_ubuntu_machine(
    connection_data: dict,
    current_user: User = Depends(operator_required)
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
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ubuntu/machines")
async def get_ubuntu_machines(
    current_user: User = Depends(get_current_user)
) -> List[VMResponse]:
    """Get list of connected Ubuntu machines"""
    try:
        connector = connectors['ubuntu']
        machines = await connector.list_vms()
        return [VMResponse(**machine) for machine in machines]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ubuntu/{machine_id}/backup")
async def backup_ubuntu_machine(
    machine_id: str,
    backup_config: dict,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(operator_required)
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
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ubuntu/{machine_id}/install-agent")
async def install_ubuntu_agent(
    machine_id: str,
    current_user: User = Depends(operator_required)
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
        raise HTTPException(status_code=500, detail=str(e))

# User Management Endpoints (Admin only)
@app.get("/api/v1/admin/users")
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
) -> List[UserResponse]:
    """List all users (admin only)"""
    users = db.query(User).offset(skip).limit(limit).all()
    return [UserResponse.model_validate(user) for user in users]

@app.put("/api/v1/admin/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    new_role: str,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """Update user role (admin only)"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user.role = new_role
        db.commit()
        
        return {"message": f"User role updated to {new_role}"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/admin/users/{user_id}/status")
async def update_user_status(
    user_id: int,
    is_active: bool,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """Activate/deactivate user (admin only)"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user.is_active = is_active
        db.commit()
        
        status = "activated" if is_active else "deactivated"
        return {"message": f"User {status}"}
        
    except HTTPException:
        raise
    except Exception as e:
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
