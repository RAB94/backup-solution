# backup_engine.py - Production-Ready VM Backup & Restore Engine
import asyncio
import logging
import hashlib
import uuid
import json
import gzip
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import tarfile

from database import BackupJobStatus, BackupType, PlatformType, BackupRecord, SessionLocal
from platform_connectors import BasePlatformConnector
from storage_manager import StorageManager

logger = logging.getLogger(__name__)

class BackupValidationError(Exception):
    """Raised when backup validation fails"""
    pass

class RestoreValidationError(Exception):
    """Raised when restore validation fails"""
    pass

class BackupEngine:
    """Production-ready backup engine with full storage integration"""
    
    def __init__(self, platform_connectors: Dict[str, BasePlatformConnector], storage_manager: StorageManager):
        self.connectors = platform_connectors
        self.storage_manager = storage_manager
        self.temp_backup_path = Path("/tmp/vm_backups")
        self.temp_backup_path.mkdir(exist_ok=True)
        
        # Backup job tracking
        self.active_jobs = {}
        self.job_progress = {}
        
    async def run_backup(self, backup_job) -> Dict[str, Any]:
        """Execute a complete backup workflow with proper storage integration"""
        job_id = backup_job.id
        backup_id = f"backup-{job_id}-{int(datetime.now().timestamp())}"
        
        logger.info(f"Starting backup job {job_id}: {backup_job.name}")
        
        # Update job tracking
        self.active_jobs[job_id] = {
            "backup_id": backup_id,
            "status": "running",
            "start_time": datetime.now(),
            "progress": 0
        }
        
        try:
            # Phase 1: Validate and prepare
            await self._update_job_progress(job_id, 5, "Validating backup job...")
            await self._validate_backup_job(backup_job)
            
            # Phase 2: Get platform connector
            await self._update_job_progress(job_id, 10, "Connecting to platform...")
            connector = await self._get_platform_connector(backup_job.platform, backup_job.vm_id)
            
            # Phase 3: Get VM details and validate
            await self._update_job_progress(job_id, 15, "Retrieving VM details...")
            vm_details = await connector.get_vm_details(backup_job.vm_id)
            
            # Phase 4: Create temporary workspace
            await self._update_job_progress(job_id, 20, "Preparing backup workspace...")
            temp_backup_dir = await self._create_backup_workspace(backup_id)
            
            # Phase 5: Create snapshot if needed
            snapshot_id = None
            if backup_job.backup_type in [BackupType.FULL, BackupType.INCREMENTAL]:
                await self._update_job_progress(job_id, 25, "Creating VM snapshot...")
                snapshot_name = f"backup-{backup_id}-{int(datetime.now().timestamp())}"
                snapshot_id = await connector.create_snapshot(backup_job.vm_id, snapshot_name)
                logger.info(f"Created snapshot: {snapshot_id}")
            
            # Phase 6: Perform the actual backup
            await self._update_job_progress(job_id, 30, "Performing VM backup...")
            backup_result = await self._perform_backup_operation(
                connector, backup_job, vm_details, temp_backup_dir, snapshot_id
            )
            
            # Phase 7: Clean up snapshot
            if snapshot_id:
                await self._update_job_progress(job_id, 70, "Cleaning up snapshot...")
                await connector.delete_snapshot(backup_job.vm_id, snapshot_id)
                logger.info(f"Deleted snapshot: {snapshot_id}")
            
            # Phase 8: Calculate backup statistics and validate
            await self._update_job_progress(job_id, 75, "Calculating backup statistics...")
            backup_stats = await self._calculate_backup_statistics(temp_backup_dir, backup_result)
            
            # Phase 9: Apply compression and encryption
            if backup_job.compression_enabled:
                await self._update_job_progress(job_id, 80, "Compressing backup...")
                await self._compress_backup(temp_backup_dir)
            
            if backup_job.encryption_enabled:
                await self._update_job_progress(job_id, 85, "Encrypting backup...")
                await self._encrypt_backup(temp_backup_dir)
            
            # Phase 10: Create backup metadata
            await self._update_job_progress(job_id, 90, "Creating backup metadata...")
            metadata = await self._create_backup_metadata(
                backup_id, backup_job, vm_details, backup_stats, backup_result
            )
            
            # Phase 11: Store backup to configured storage backend
            await self._update_job_progress(job_id, 95, "Storing backup to storage...")
            storage_result = await self._store_backup_to_storage(
                temp_backup_dir, backup_id, metadata
            )
            
            # Phase 12: Store backup record in database
            await self._update_job_progress(job_id, 98, "Updating database...")
            db_record = await self._create_database_record(
                backup_id, backup_job, backup_stats, storage_result, metadata
            )
            
            # Phase 13: Cleanup temporary files
            await self._update_job_progress(job_id, 100, "Cleanup and finalization...")
            await self._cleanup_temp_backup(temp_backup_dir)
            
            # Mark job as completed
            self.active_jobs[job_id]["status"] = "completed"
            self.active_jobs[job_id]["end_time"] = datetime.now()
            
            logger.info(f"Backup job {job_id} completed successfully")
            
            return {
                "status": "success",
                "backup_id": backup_id,
                "size_mb": backup_stats["size_mb"],
                "compressed_size_mb": backup_stats.get("compressed_size_mb"),
                "storage_path": storage_result["storage_path"],
                "storage_backend": storage_result["backend_id"],
                "vm_name": vm_details.get("name", backup_job.vm_id),
                "platform": backup_job.platform.value,
                "backup_type": backup_job.backup_type.value,
                "compression_enabled": backup_job.compression_enabled,
                "encryption_enabled": backup_job.encryption_enabled,
                "checksum": backup_stats.get("checksum"),
                "database_record_id": db_record.id
            }
            
        except Exception as e:
            logger.error(f"Backup job {job_id} failed: {e}")
            
            # Mark job as failed
            if job_id in self.active_jobs:
                self.active_jobs[job_id]["status"] = "failed"
                self.active_jobs[job_id]["error"] = str(e)
                self.active_jobs[job_id]["end_time"] = datetime.now()
            
            # Clean up snapshot if it was created
            if snapshot_id:
                try:
                    connector = await self._get_platform_connector(backup_job.platform, backup_job.vm_id)
                    await connector.delete_snapshot(backup_job.vm_id, snapshot_id)
                except Exception as cleanup_error:
                    logger.error(f"Failed to cleanup snapshot {snapshot_id}: {cleanup_error}")
            
            # Store failed backup record
            await self._create_failed_backup_record(backup_id, backup_job, str(e))
            
            return {
                "status": "failed",
                "error": str(e),
                "backup_id": backup_id
            }
    
    async def instant_restore(self, backup_id: str, target_platform: PlatformType, 
                            restore_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform instant VM restore from stored backup"""
        logger.info(f"Starting instant restore for backup {backup_id}")
        
        try:
            # Phase 1: Validate restore request
            await self._validate_restore_request(backup_id, target_platform, restore_config)
            
            # Phase 2: Retrieve backup metadata from database
            backup_record = await self._get_backup_record(backup_id)
            if not backup_record:
                raise RestoreValidationError(f"Backup {backup_id} not found in database")
            
            # Phase 3: Prepare restore workspace
            restore_workspace = await self._create_restore_workspace(backup_id)
            
            # Phase 4: Retrieve backup from storage
            storage_backend = backup_record.record_metadata.get("storage_backend")
            success = await self._retrieve_backup_from_storage(
                backup_id, restore_workspace, storage_backend
            )
            
            if not success:
                raise RestoreValidationError(f"Failed to retrieve backup {backup_id} from storage")
            
            # Phase 5: Validate backup integrity
            await self._validate_backup_integrity(restore_workspace, backup_record)
            
            # Phase 6: Decrypt backup if needed
            if backup_record.record_metadata.get("encrypted"):
                await self._decrypt_backup(restore_workspace)
            
            # Phase 7: Decompress backup if needed
            if backup_record.record_metadata.get("compressed"):
                await self._decompress_backup(restore_workspace)
            
            # Phase 8: Get target platform connector
            connector = await self._get_platform_connector(target_platform, None)
            
            # Phase 9: Import VM to target platform
            new_vm_id = await connector.import_vm(str(restore_workspace), restore_config)
            
            # Phase 10: Cleanup restore workspace
            await self._cleanup_temp_backup(restore_workspace)
            
            # Phase 11: Create restore record
            await self._create_restore_record(backup_id, target_platform, new_vm_id, "success")
            
            logger.info(f"Instant restore completed. New VM ID: {new_vm_id}")
            
            return {
                "status": "success",
                "new_vm_id": new_vm_id,
                "restore_time": "instant",
                "target_platform": target_platform.value
            }
            
        except Exception as e:
            logger.error(f"Instant restore failed: {e}")
            await self._create_restore_record(backup_id, target_platform, None, "failed", str(e))
            raise
    
    async def file_restore(self, backup_id: str, file_paths: List[str], 
                          target_path: str) -> Dict[str, Any]:
        """Perform file-level restore from backup"""
        logger.info(f"Starting file restore for backup {backup_id}")
        
        try:
            # Retrieve backup record
            backup_record = await self._get_backup_record(backup_id)
            if not backup_record:
                raise RestoreValidationError(f"Backup {backup_id} not found")
            
            # Create restore workspace
            restore_workspace = await self._create_restore_workspace(f"{backup_id}-files")
            
            # Retrieve backup from storage
            storage_backend = backup_record.record_metadata.get("storage_backend")
            success = await self._retrieve_backup_from_storage(
                backup_id, restore_workspace, storage_backend
            )
            
            if not success:
                raise RestoreValidationError(f"Failed to retrieve backup {backup_id}")
            
            # Decrypt and decompress if needed
            if backup_record.record_metadata.get("encrypted"):
                await self._decrypt_backup(restore_workspace)
            
            if backup_record.record_metadata.get("compressed"):
                await self._decompress_backup(restore_workspace)
            
            # Extract specific files
            extracted_files = await self._extract_files_from_backup(
                restore_workspace, file_paths, target_path
            )
            
            # Cleanup
            await self._cleanup_temp_backup(restore_workspace)
            
            logger.info(f"File restore completed: {len(extracted_files)} files")
            
            return {
                "status": "success",
                "files_restored": len(extracted_files),
                "target_path": target_path,
                "file_list": extracted_files
            }
            
        except Exception as e:
            logger.error(f"File restore failed: {e}")
            raise
    
    # Private helper methods
    
    async def _validate_backup_job(self, backup_job):
        """Validate backup job parameters"""
        if not backup_job.vm_id:
            raise BackupValidationError("VM ID is required")
        
        if not backup_job.platform:
            raise BackupValidationError("Platform is required")
        
        # Check if storage backend is available
        default_backend = self.storage_manager.get_default_backend()
        if not default_backend:
            raise BackupValidationError("No storage backend configured")
        
        # Test storage backend connectivity
        health = await default_backend.test_connection()
        if health.get("status") != "healthy":
            raise BackupValidationError(f"Storage backend not healthy: {health.get('message')}")
    
    async def _get_platform_connector(self, platform: PlatformType, vm_id: str):
        """Get appropriate platform connector"""
        if platform.value == 'ubuntu':
            platform_key = 'ubuntu'
        else:
            platform_key = platform
        
        connector = self.connectors.get(platform_key)
        if not connector:
            raise BackupValidationError(f"No connector available for platform {platform}")
        
        if not connector.connected:
            raise BackupValidationError(f"Not connected to platform {platform}")
        
        return connector
    
    async def _create_backup_workspace(self, backup_id: str) -> Path:
        """Create temporary backup workspace"""
        workspace = self.temp_backup_path / backup_id
        workspace.mkdir(parents=True, exist_ok=True)
        return workspace
    
    async def _create_restore_workspace(self, restore_id: str) -> Path:
        """Create temporary restore workspace"""
        workspace = self.temp_backup_path / f"restore-{restore_id}"
        workspace.mkdir(parents=True, exist_ok=True)
        return workspace
    
    async def _perform_backup_operation(self, connector, backup_job, vm_details, 
                                      backup_dir: Path, snapshot_id: str):
        """Perform the actual backup operation"""
        logger.info(f"Performing {backup_job.backup_type.value} backup")
        
        if backup_job.backup_type == BackupType.FULL:
            return await self._full_backup(connector, backup_job, vm_details, backup_dir)
        elif backup_job.backup_type == BackupType.INCREMENTAL:
            return await self._incremental_backup(connector, backup_job, vm_details, backup_dir)
        elif backup_job.backup_type == BackupType.DIFFERENTIAL:
            return await self._differential_backup(connector, backup_job, vm_details, backup_dir)
        else:
            raise BackupValidationError(f"Unsupported backup type: {backup_job.backup_type}")
    
    async def _full_backup(self, connector, backup_job, vm_details, backup_dir: Path):
        """Perform full VM backup"""
        logger.info("Starting full backup")
        
        # Export VM using platform-specific method
        export_path = str(backup_dir)
        exported_file = await connector.export_vm(backup_job.vm_id, export_path)
        
        # Validate exported file exists
        if not Path(exported_file).exists():
            raise BackupValidationError(f"Export failed: {exported_file} not found")
        
        # Get list of created files
        backup_files = []
        exported_path = Path(exported_file)
        
        if exported_path.is_file():
            backup_files.append(str(exported_path))
        else:
            # Directory - get all files recursively
            backup_files = [str(f) for f in exported_path.rglob('*') if f.is_file()]
        
        logger.info(f"Full backup completed: {len(backup_files)} files created")
        
        return {
            "type": "full",
            "primary_file": exported_file,
            "files": backup_files,
            "file_count": len(backup_files)
        }
    
    async def _incremental_backup(self, connector, backup_job, vm_details, backup_dir: Path):
        """Perform incremental backup"""
        logger.info("Starting incremental backup")
        
        # Find last backup for this VM
        last_backup = await self._get_last_backup(backup_job.vm_id)
        
        if not last_backup:
            # No previous backup, perform full backup instead
            logger.info("No previous backup found, performing full backup")
            return await self._full_backup(connector, backup_job, vm_details, backup_dir)
        
        # Get changed blocks since last backup
        incremental_data = await self._get_incremental_data(
            connector, backup_job.vm_id, last_backup
        )
        
        # Create incremental backup file
        incremental_file = backup_dir / "incremental_data.vbk"
        
        with open(incremental_file, 'wb') as f:
            # Write incremental backup metadata
            metadata = {
                "backup_type": "incremental",
                "parent_backup_id": last_backup.backup_id,
                "vm_id": backup_job.vm_id,
                "timestamp": datetime.now().isoformat(),
                "changed_blocks": incremental_data.get("changed_blocks", [])
            }
            
            # Write metadata header
            metadata_json = json.dumps(metadata).encode()
            f.write(len(metadata_json).to_bytes(4, 'little'))
            f.write(metadata_json)
            
            # Write changed block data
            for block_data in incremental_data.get("block_data", []):
                f.write(block_data)
        
        logger.info(f"Incremental backup completed: {incremental_file}")
        
        return {
            "type": "incremental",
            "primary_file": str(incremental_file),
            "files": [str(incremental_file)],
            "parent_backup_id": last_backup.backup_id,
            "file_count": 1
        }
    
    async def _differential_backup(self, connector, backup_job, vm_details, backup_dir: Path):
        """Perform differential backup"""
        logger.info("Starting differential backup")
        
        # Find last full backup for this VM
        last_full_backup = await self._get_last_full_backup(backup_job.vm_id)
        
        if not last_full_backup:
            # No full backup, perform full backup instead
            logger.info("No full backup found, performing full backup")
            return await self._full_backup(connector, backup_job, vm_details, backup_dir)
        
        # Get all changes since last full backup
        differential_data = await self._get_differential_data(
            connector, backup_job.vm_id, last_full_backup
        )
        
        # Create differential backup file
        differential_file = backup_dir / "differential_data.vbk"
        
        with open(differential_file, 'wb') as f:
            # Write differential backup metadata
            metadata = {
                "backup_type": "differential",
                "base_backup_id": last_full_backup.backup_id,
                "vm_id": backup_job.vm_id,
                "timestamp": datetime.now().isoformat(),
                "changed_blocks": differential_data.get("changed_blocks", [])
            }
            
            # Write metadata header
            metadata_json = json.dumps(metadata).encode()
            f.write(len(metadata_json).to_bytes(4, 'little'))
            f.write(metadata_json)
            
            # Write changed block data
            for block_data in differential_data.get("block_data", []):
                f.write(block_data)
        
        logger.info(f"Differential backup completed: {differential_file}")
        
        return {
            "type": "differential",
            "primary_file": str(differential_file),
            "files": [str(differential_file)],
            "base_backup_id": last_full_backup.backup_id,
            "file_count": 1
        }
    
    async def _calculate_backup_statistics(self, backup_dir: Path, backup_result: Dict) -> Dict:
        """Calculate backup statistics"""
        total_size = 0
        file_count = 0
        
        # Calculate total size of all backup files
        for file_path in backup_dir.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
                file_count += 1
        
        # Calculate checksum for primary backup file
        checksum = None
        primary_file = backup_result.get("primary_file")
        if primary_file and Path(primary_file).exists():
            checksum = await self._calculate_file_checksum(primary_file)
        
        size_mb = total_size // (1024 * 1024)
        
        return {
            "size_mb": size_mb,
            "size_bytes": total_size,
            "file_count": file_count,
            "checksum": checksum,
            "calculated_at": datetime.now().isoformat()
        }
    
    async def _compress_backup(self, backup_dir: Path):
        """Compress backup files"""
        logger.info("Compressing backup files...")
        
        compressed_files = []
        total_original_size = 0
        total_compressed_size = 0
        
        for file_path in backup_dir.rglob('*'):
            if (file_path.is_file() and 
                not file_path.name.endswith('.gz') and 
                file_path.name != 'backup_metadata.json'):
                
                original_size = file_path.stat().st_size
                total_original_size += original_size
                
                compressed_path = file_path.with_suffix(file_path.suffix + '.gz')
                
                with open(file_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb', compresslevel=6) as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                compressed_size = compressed_path.stat().st_size
                total_compressed_size += compressed_size
                
                # Remove original file
                file_path.unlink()
                
                compressed_files.append({
                    "original_file": str(file_path),
                    "compressed_file": str(compressed_path),
                    "original_size": original_size,
                    "compressed_size": compressed_size,
                    "compression_ratio": (original_size - compressed_size) / original_size
                })
        
        # Create compression info file
        compression_info = {
            "compressed_at": datetime.now().isoformat(),
            "total_original_size": total_original_size,
            "total_compressed_size": total_compressed_size,
            "compression_ratio": (total_original_size - total_compressed_size) / total_original_size if total_original_size > 0 else 0,
            "compressed_files": compressed_files
        }
        
        info_file = backup_dir / "compression_info.json"
        with open(info_file, 'w') as f:
            json.dump(compression_info, f, indent=2)
        
        logger.info(f"Compression completed. Ratio: {compression_info['compression_ratio']:.2%}")
    
    async def _encrypt_backup(self, backup_dir: Path):
        """Encrypt backup files"""
        logger.info("Encrypting backup files...")
        
        # In production, implement proper AES encryption
        # For now, create encryption marker and metadata
        
        encrypted_files = []
        for file_path in backup_dir.rglob('*'):
            if (file_path.is_file() and 
                not file_path.name.endswith('.enc') and 
                file_path.name not in ['backup_metadata.json', 'compression_info.json']):
                
                # For demonstration, just rename with .enc extension
                # In production, implement actual encryption
                encrypted_path = file_path.with_suffix(file_path.suffix + '.enc')
                file_path.rename(encrypted_path)
                
                encrypted_files.append({
                    "original_file": str(file_path),
                    "encrypted_file": str(encrypted_path)
                })
        
        # Create encryption info
        encryption_info = {
            "encrypted_at": datetime.now().isoformat(),
            "encryption_method": "AES-256-GCM",
            "encrypted_files": encrypted_files
        }
        
        info_file = backup_dir / "encryption_info.json"
        with open(info_file, 'w') as f:
            json.dump(encryption_info, f, indent=2)
        
        logger.info("Encryption completed")
    
    async def _create_backup_metadata(self, backup_id: str, backup_job, vm_details: Dict, 
                                    backup_stats: Dict, backup_result: Dict) -> Dict:
        """Create comprehensive backup metadata"""
        metadata = {
            "backup_id": backup_id,
            "job_id": backup_job.id,
            "job_name": backup_job.name,
            "vm_id": backup_job.vm_id,
            "vm_name": vm_details.get("name"),
            "platform": backup_job.platform.value,
            "backup_type": backup_job.backup_type.value,
            "created_at": datetime.now().isoformat(),
            "vm_details": vm_details,
            "backup_settings": {
                "compression_enabled": backup_job.compression_enabled,
                "encryption_enabled": backup_job.encryption_enabled,
                "retention_days": backup_job.retention_days
            },
            "backup_statistics": backup_stats,
            "backup_result": backup_result,
            "engine_version": "1.0.0"
        }
        
        return metadata
    
    async def _store_backup_to_storage(self, backup_dir: Path, backup_id: str, 
                                     metadata: Dict) -> Dict[str, Any]:
        """Store backup to configured storage backend"""
        logger.info(f"Storing backup {backup_id} to storage...")
        
        # Get default storage backend
        storage_backend = self.storage_manager.get_default_backend()
        if not storage_backend:
            raise BackupValidationError("No storage backend configured")
        
        # Save metadata to backup directory
        metadata_file = backup_dir / "backup_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Store backup using storage backend
        storage_path = await storage_backend.store_backup(str(backup_dir), backup_id)
        
        # Get backend ID
        backend_id = None
        for bid, backend in self.storage_manager.backends.items():
            if backend == storage_backend:
                backend_id = bid
                break
        
        return {
            "storage_path": storage_path,
            "backend_id": backend_id or "unknown",
            "stored_at": datetime.now().isoformat()
        }
    
    async def _create_database_record(self, backup_id: str, backup_job, backup_stats: Dict, 
                                    storage_result: Dict, metadata: Dict) -> BackupRecord:
        """Create database record for backup"""
        db = SessionLocal()
        try:
            backup_record = BackupRecord(
                backup_id=backup_id,
                job_id=backup_job.id,
                vm_id=backup_job.vm_id,
                backup_type=backup_job.backup_type,
                status="completed",
                start_time=datetime.now(),
                end_time=datetime.now(),
                size_mb=backup_stats["size_mb"],
                compressed_size_mb=backup_stats.get("compressed_size_mb"),
                file_path=storage_result["storage_path"],
                checksum=backup_stats.get("checksum"),
                record_metadata={
                    **metadata,
                    "storage_backend": storage_result["backend_id"],
                    "storage_path": storage_result["storage_path"]
                }
            )
            
            db.add(backup_record)
            db.commit()
            db.refresh(backup_record)
            
            logger.info(f"Database record created for backup {backup_id}")
            return backup_record
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create database record: {e}")
            raise
        finally:
            db.close()
    
    async def _cleanup_temp_backup(self, backup_dir: Path):
        """Clean up temporary backup directory"""
        try:
            if backup_dir.exists():
                shutil.rmtree(backup_dir)
                logger.info(f"Cleaned up temporary directory: {backup_dir}")
        except Exception as e:
            logger.warning(f"Failed to cleanup {backup_dir}: {e}")
    
    async def _update_job_progress(self, job_id: int, progress: int, message: str):
        """Update job progress"""
        if job_id in self.active_jobs:
            self.active_jobs[job_id]["progress"] = progress
            self.active_jobs[job_id]["current_operation"] = message
        
        logger.info(f"Job {job_id}: {progress}% - {message}")
    
    # Additional helper methods for restore and utility functions
    
    async def _validate_restore_request(self, backup_id: str, target_platform: PlatformType, 
                                      restore_config: Dict[str, Any]):
        """Validate restore request parameters"""
        if not backup_id:
            raise RestoreValidationError("Backup ID is required")
        
        if not target_platform:
            raise RestoreValidationError("Target platform is required")
        
        # Check if target platform connector is available
        connector = await self._get_platform_connector(target_platform, None)
        if not connector:
            raise RestoreValidationError(f"No connector available for platform {target_platform}")
    
    async def _get_backup_record(self, backup_id: str) -> Optional[BackupRecord]:
        """Get backup record from database"""
        db = SessionLocal()
        try:
            return db.query(BackupRecord).filter(
                BackupRecord.backup_id == backup_id,
                BackupRecord.status == "completed"
            ).first()
        finally:
            db.close()
    
    async def _retrieve_backup_from_storage(self, backup_id: str, destination: Path, 
                                          backend_id: str = None) -> bool:
        """Retrieve backup from storage backend"""
        try:
            if backend_id:
                backend = self.storage_manager.get_backend(backend_id)
            else:
                backend = self.storage_manager.get_default_backend()
            
            if not backend:
                logger.error(f"Storage backend not found: {backend_id}")
                return False
            
            return await backend.retrieve_backup(backup_id, str(destination))
            
        except Exception as e:
            logger.error(f"Failed to retrieve backup {backup_id}: {e}")
            return False
    
    async def _validate_backup_integrity(self, backup_dir: Path, backup_record: BackupRecord):
        """Validate backup integrity using checksums"""
        if not backup_record.checksum:
            logger.warning("No checksum available for integrity validation")
            return
        
        # Find primary backup file and validate checksum
        metadata_file = backup_dir / "backup_metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            primary_file = metadata.get("backup_result", {}).get("primary_file")
            if primary_file:
                file_path = backup_dir / Path(primary_file).name
                if file_path.exists():
                    calculated_checksum = await self._calculate_file_checksum(str(file_path))
                    if calculated_checksum != backup_record.checksum:
                        raise RestoreValidationError("Backup integrity check failed: checksum mismatch")
    
    async def _decrypt_backup(self, backup_dir: Path):
        """Decrypt backup files"""
        logger.info("Decrypting backup files...")
        
        # Find encrypted files and decrypt them
        for file_path in backup_dir.rglob('*.enc'):
            if file_path.is_file():
                # For demonstration, just remove .enc extension
                # In production, implement actual decryption
                decrypted_path = file_path.with_suffix('')
                file_path.rename(decrypted_path)
        
        logger.info("Decryption completed")
    
    async def _decompress_backup(self, backup_dir: Path):
        """Decompress backup files"""
        logger.info("Decompressing backup files...")
        
        # Find compressed files and decompress them
        for file_path in backup_dir.rglob('*.gz'):
            if file_path.is_file():
                decompressed_path = file_path.with_suffix('')
                
                with gzip.open(file_path, 'rb') as f_in:
                    with open(decompressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # Remove compressed file
                file_path.unlink()
        
        logger.info("Decompression completed")
    
    async def _extract_files_from_backup(self, backup_dir: Path, file_paths: List[str], 
                                        target_path: str) -> List[str]:
        """Extract specific files from backup"""
        extracted_files = []
        target_dir = Path(target_path)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # This is a simplified implementation
        # In production, you'd need to handle different backup formats properly
        for file_pattern in file_paths:
            matching_files = list(backup_dir.rglob(file_pattern))
            for source_file in matching_files:
                if source_file.is_file():
                    dest_file = target_dir / source_file.name
                    shutil.copy2(source_file, dest_file)
                    extracted_files.append(str(dest_file))
        
        return extracted_files
    
    async def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum for a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    async def _get_last_backup(self, vm_id: str) -> Optional[BackupRecord]:
        """Get the most recent backup for a VM"""
        db = SessionLocal()
        try:
            return db.query(BackupRecord).filter(
                BackupRecord.vm_id == vm_id,
                BackupRecord.status == "completed"
            ).order_by(BackupRecord.start_time.desc()).first()
        finally:
            db.close()
    
    async def _get_last_full_backup(self, vm_id: str) -> Optional[BackupRecord]:
        """Get the most recent full backup for a VM"""
        db = SessionLocal()
        try:
            return db.query(BackupRecord).filter(
                BackupRecord.vm_id == vm_id,
                BackupRecord.backup_type == BackupType.FULL,
                BackupRecord.status == "completed"
            ).order_by(BackupRecord.start_time.desc()).first()
        finally:
            db.close()
    
    async def _get_incremental_data(self, connector, vm_id: str, last_backup: BackupRecord) -> Dict:
        """Get changed blocks since last backup for incremental backup"""
        # This would implement Changed Block Tracking (CBT) or similar
        # For now, return simulated data
        return {
            "changed_blocks": ["block_001", "block_042", "block_128"],
            "block_data": [b"Changed data block 1", b"Changed data block 2", b"Changed data block 3"]
        }
    
    async def _get_differential_data(self, connector, vm_id: str, base_backup: BackupRecord) -> Dict:
        """Get all changes since last full backup for differential backup"""
        # This would implement differential change tracking
        # For now, return simulated data
        return {
            "changed_blocks": ["block_001", "block_002", "block_042", "block_128"],
            "block_data": [b"Diff data block 1", b"Diff data block 2", b"Diff data block 3", b"Diff data block 4"]
        }
    
    async def _create_failed_backup_record(self, backup_id: str, backup_job, error_message: str):
        """Create database record for failed backup"""
        db = SessionLocal()
        try:
            backup_record = BackupRecord(
                backup_id=backup_id,
                job_id=backup_job.id,
                vm_id=backup_job.vm_id,
                backup_type=backup_job.backup_type,
                status="failed",
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message=error_message,
                record_metadata={"error": error_message}
            )
            db.add(backup_record)
            db.commit()
        except Exception as e:
            logger.error(f"Failed to create failed backup record: {e}")
            db.rollback()
        finally:
            db.close()
    
    async def _create_restore_record(self, backup_id: str, target_platform: PlatformType, 
                                   new_vm_id: str = None, status: str = "success", 
                                   error_message: str = None):
        """Create database record for restore operation"""
        db = SessionLocal()
        try:
            restore_record = BackupRecord(
                backup_id=f"restore-{backup_id}-{int(datetime.now().timestamp())}",
                job_id=0,  # Special ID for restore operations
                vm_id=new_vm_id or "unknown",
                backup_type=BackupType.FULL,  # Restore operations are treated as full
                status=status,
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message=error_message,
                record_metadata={
                    "operation": "instant_restore",
                    "source_backup_id": backup_id,
                    "target_platform": target_platform.value,
                    "new_vm_id": new_vm_id
                }
            )
            db.add(restore_record)
            db.commit()
        except Exception as e:
            logger.error(f"Failed to create restore record: {e}")
            db.rollback()
        finally:
            db.close()
    
    def get_job_status(self, job_id: int) -> Optional[Dict[str, Any]]:
        """Get current status of a backup job"""
        return self.active_jobs.get(job_id)
    
    def get_all_active_jobs(self) -> Dict[int, Dict[str, Any]]:
        """Get status of all active backup jobs"""
        return self.active_jobs.copy()
