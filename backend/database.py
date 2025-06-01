# database.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, JSON, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
import enum
import os

# Database URL - use SQLite for development, PostgreSQL for production
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./backup_solution.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Enums
class PlatformType(enum.Enum):
    VMWARE = "vmware"
    PROXMOX = "proxmox"
    XCPNG = "xcpng"
    UBUNTU = "ubuntu"  # Added Ubuntu platform type

class BackupJobStatus(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

class BackupType(enum.Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"

# Database Models
class VirtualMachine(Base):
    __tablename__ = "virtual_machines"
    
    id = Column(Integer, primary_key=True, index=True)
    vm_id = Column(String, unique=True, index=True)  # Platform-specific VM ID
    name = Column(String, index=True)
    platform = Column(Enum(PlatformType))
    host = Column(String)
    cpu_count = Column(Integer)
    memory_mb = Column(Integer)
    disk_size_gb = Column(Integer)
    operating_system = Column(String)
    power_state = Column(String)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    vm_metadata = Column(JSON)  # Renamed from 'metadata' to avoid SQLAlchemy conflict

class BackupRepository(Base):
    __tablename__ = "backup_repositories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    storage_type = Column(String)  # local, nfs, iscsi, s3
    connection_string = Column(String)
    capacity_gb = Column(Integer)
    used_gb = Column(Integer, default=0)
    encryption_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now)
    settings = Column(JSON)

class BackupJob(Base):
    __tablename__ = "backup_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(Text)
    vm_id = Column(String)  # Reference to VM
    platform = Column(Enum(PlatformType))
    backup_type = Column(Enum(BackupType), default=BackupType.INCREMENTAL)
    repository_id = Column(Integer)
    schedule_cron = Column(String)  # Cron expression for scheduling
    retention_days = Column(Integer, default=30)
    compression_enabled = Column(Boolean, default=True)
    encryption_enabled = Column(Boolean, default=True)
    status = Column(Enum(BackupJobStatus), default=BackupJobStatus.PENDING)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    settings = Column(JSON)

class BackupRecord(Base):
    __tablename__ = "backup_records"
    
    id = Column(Integer, primary_key=True, index=True)
    backup_id = Column(String, unique=True, index=True)
    job_id = Column(Integer)
    vm_id = Column(String)
    backup_type = Column(Enum(BackupType))
    status = Column(String)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    size_mb = Column(Integer)
    compressed_size_mb = Column(Integer)
    file_path = Column(String)
    checksum = Column(String)
    error_message = Column(Text)
    record_metadata = Column(JSON)  # Renamed from 'metadata' to avoid SQLAlchemy conflict

class PlatformConnection(Base):
    __tablename__ = "platform_connections"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    platform = Column(Enum(PlatformType))
    host = Column(String)
    port = Column(Integer)
    username = Column(String)
    password_encrypted = Column(String)  # Encrypted password
    ssl_enabled = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    last_connected = Column(DateTime)
    created_at = Column(DateTime, default=datetime.now)
    connection_settings = Column(JSON)

class SystemLog(Base):
    __tablename__ = "system_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    level = Column(String)  # INFO, WARNING, ERROR, CRITICAL
    component = Column(String)  # backup_engine, scheduler, api
    message = Column(Text)
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.now)

# Database dependency
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize database
def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise


# models.py - Pydantic models for API
from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from database import PlatformType, BackupJobStatus, BackupType

# VM Models
class VMBase(BaseModel):
    vm_id: str
    name: str
    platform: PlatformType
    host: Optional[str] = None
    cpu_count: Optional[int] = None
    memory_mb: Optional[int] = None
    disk_size_gb: Optional[int] = None
    operating_system: Optional[str] = None
    power_state: Optional[str] = None

class VMCreate(VMBase):
    pass

class VMResponse(VMBase):
    id: int
    created_at: datetime
    updated_at: datetime
    vm_metadata: Optional[Dict[str, Any]] = None  # Updated to match renamed column
    
    model_config = ConfigDict(from_attributes=True)

# Backup Job Models
class BackupJobBase(BaseModel):
    name: str
    description: Optional[str] = None
    vm_id: str
    platform: PlatformType
    backup_type: BackupType = BackupType.INCREMENTAL
    repository_id: int
    schedule_cron: str
    retention_days: int = 30
    compression_enabled: bool = True
    encryption_enabled: bool = True

class BackupJobCreate(BackupJobBase):
    pass

class BackupJobResponse(BackupJobBase):
    id: int
    status: BackupJobStatus
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    settings: Optional[Dict[str, Any]] = None
    
    model_config = ConfigDict(from_attributes=True)

# Backup Repository Models
class BackupRepositoryBase(BaseModel):
    name: str
    storage_type: str
    connection_string: str
    capacity_gb: int
    encryption_enabled: bool = True

class BackupRepositoryCreate(BackupRepositoryBase):
    pass

class BackupRepositoryResponse(BackupRepositoryBase):
    id: int
    used_gb: int = 0
    created_at: datetime
    settings: Optional[Dict[str, Any]] = None
    
    model_config = ConfigDict(from_attributes=True)

# Platform Connection Models
class PlatformConnectionBase(BaseModel):
    name: str
    platform: PlatformType
    host: str
    port: int
    username: str
    ssl_enabled: bool = True

class PlatformConnectionCreate(PlatformConnectionBase):
    password: str

class PlatformConnectionResponse(PlatformConnectionBase):
    id: int
    is_active: bool
    last_connected: Optional[datetime] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

# Backup Record Models
class BackupRecordBase(BaseModel):
    backup_id: str
    job_id: int
    vm_id: str
    backup_type: BackupType
    status: str

class BackupRecordResponse(BackupRecordBase):
    id: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    size_mb: Optional[int] = None
    compressed_size_mb: Optional[int] = None
    file_path: Optional[str] = None
    checksum: Optional[str] = None
    error_message: Optional[str] = None
    record_metadata: Optional[Dict[str, Any]] = None  # Updated to match renamed column
    
    model_config = ConfigDict(from_attributes=True)

# Dashboard Statistics Model
class DashboardStats(BaseModel):
    total_vms: int
    protected_vms: int
    total_backup_jobs: int
    running_jobs: int
    failed_jobs_24h: int
    success_rate: float
    total_storage_used: str
    storage_saved_compression: str
    last_backup_time: Optional[datetime] = None

# API Response Models
class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    error: Optional[str] = None

class JobExecutionResponse(BaseModel):
    job_id: int
    status: str
    message: str
    estimated_completion: Optional[datetime] = None
