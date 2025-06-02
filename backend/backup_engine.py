# Updated backup_engine.py - Fixed ALL variable references
import asyncio
import logging
import hashlib
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import gzip

from database import BackupJobStatus, BackupType, PlatformType
from platform_connectors import BasePlatformConnector

logger = logging.getLogger(__name__)

class BackupEngine:
    """Core backup engine that orchestrates backup operations with storage manager integration"""
    
    def __init__(self, platform_connectors: Dict[PlatformType, BasePlatformConnector], storage_manager=None):
        self.connectors = platform_connectors
        self.storage_manager = storage_manager
        self.backup_storage_path = Path("./backups")
        self.backup_storage_path.mkdir(exist_ok=True)
        
    async def run_backup(self, backup_job) -> Dict[str, Any]:
        """Execute a backup job with proper storage management"""
        job_id = backup_job.id
        logger.info(f"Starting backup job {job_id}: {backup_job.name}")
        
        try:
            # Get platform connector
            if backup_job.platform.value == 'ubuntu':
                platform_key = 'ubuntu'
            else:
                platform_key = backup_job.platform
            connector = self.connectors[platform_key]
            
            if not connector.connected:
                raise Exception(f"Not connected to {backup_job.platform}")
            
            # Generate backup ID
            backup_id = str(uuid.uuid4())
            
            # Create backup directory (local temp storage)
            backup_dir = self.backup_storage_path / backup_id
            backup_dir.mkdir(exist_ok=True)
            
            # Get VM details
            vm_details = await connector.get_vm_details(backup_job.vm_id)
            
            # Create snapshot if needed
            snapshot_id = None
            if backup_job.backup_type in [BackupType.FULL, BackupType.INCREMENTAL]:
                snapshot_name = f"backup-{backup_id}-{int(datetime.now().timestamp())}"
                snapshot_id = await connector.create_snapshot(backup_job.vm_id, snapshot_name)
                logger.info(f"Created snapshot: {snapshot_id}")
            
            # Perform backup based on type
            backup_result = await self._perform_backup(
                connector, 
                backup_job, 
                vm_details, 
                backup_dir,
                snapshot_id
            )
            
            # Clean up snapshot
            if snapshot_id:
                await connector.delete_snapshot(backup_job.vm_id, snapshot_id)
                logger.info(f"Deleted snapshot: {snapshot_id}")
            
            # Compress backup if enabled
            if backup_job.compression_enabled:
                await self._compress_backup(backup_dir)
            
            # Calculate backup statistics
            backup_size = await self._calculate_backup_size(backup_dir)
            
            # Create backup metadata
            metadata = {
                "backup_id": backup_id,
                "job_id": job_id,
                "vm_id": backup_job.vm_id,
                "vm_name": vm_details.get("name"),
                "platform": backup_job.platform.value,
                "backup_type": backup_job.backup_type.value,
                "timestamp": datetime.now().isoformat(),
                "size_mb": backup_size,
                "compressed": backup_job.compression_enabled,
                "encrypted": backup_job.encryption_enabled,
                "vm_details": vm_details,
                "file_path": str(backup_dir)
            }
            
            # Save metadata
            metadata_file = backup_dir / "backup_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Encrypt if enabled
            if backup_job.encryption_enabled:
                await self._encrypt_backup(backup_dir)
            
            # Store backup using storage manager (if available)
            final_storage_path = str(backup_dir)
            if self.storage_manager:
                try:
                    final_storage_path = await self.storage_manager.store_backup(
                        str(backup_dir), backup_id
                    )
                    logger.info(f"Backup stored using storage manager: {final_storage_path}")
                except Exception as storage_error:
                    logger.warning(f"Storage manager failed, using local storage: {storage_error}")
            
            logger.info(f"Backup job {job_id} completed successfully")
            return {
                "status": "success",
                "backup_id": backup_id,
                "size_mb": backup_size,
                "path": final_storage_path,
                "vm_name": vm_details.get("name", backup_job.vm_id),
                "platform": backup_job.platform.value,
                "backup_type": backup_job.backup_type.value,
                "compression_enabled": backup_job.compression_enabled,
                "encryption_enabled": backup_job.encryption_enabled
            }
            
        except Exception as e:
            logger.error(f"Backup job {job_id} failed: {e}")
            return {
                "status": "failed",
                "error": str(e)
            }
    
    async def _perform_backup(self, connector, backup_job, vm_details, backup_dir, snapshot_id):
        """Perform the actual backup operation"""
        logger.info(f"Performing {backup_job.backup_type.value} backup")
        
        if backup_job.backup_type == BackupType.FULL:
            return await self._full_backup(connector, backup_job, vm_details, backup_dir)
        elif backup_job.backup_type == BackupType.INCREMENTAL:
            return await self._incremental_backup(connector, backup_job, vm_details, backup_dir)
        else:
            raise Exception(f"Backup type {backup_job.backup_type} not implemented")
    
    async def _full_backup(self, connector, backup_job, vm_details, backup_dir):
        """Perform full VM backup"""
        logger.info("Starting full backup")
        
        # Export VM
        export_path = str(backup_dir)
        exported_file = await connector.export_vm(backup_job.vm_id, export_path)
        
        logger.info(f"Full backup completed: {exported_file}")
        return {"type": "full", "file": exported_file}
    
    async def _incremental_backup(self, connector, backup_job, vm_details, backup_dir):
        """Perform incremental backup"""
        logger.info("Starting incremental backup")
        
        # For demo purposes, we'll simulate incremental backup
        # In real implementation, this would use CBT or similar technology
        
        # Create a mock incremental backup file
        incremental_file = backup_dir / "incremental_data.bin"
        
        # Simulate writing changed blocks
        await asyncio.sleep(2)
        with open(incremental_file, 'wb') as f:
            # Mock changed data
            f.write(b"Incremental backup data for VM " + backup_job.vm_id.encode())
        
        logger.info("Incremental backup completed")
        return {"type": "incremental", "file": str(incremental_file)}
    
    async def _compress_backup(self, backup_dir: Path):
        """Compress backup files"""
        logger.info("Compressing backup files")
        
        # In real implementation, you would compress the actual backup files
        # For demo, create a compressed marker file
        compressed_marker = backup_dir / "compressed.flag"
        with open(compressed_marker, 'w') as f:
            f.write("Backup compressed with gzip")
        
        await asyncio.sleep(1)  # Simulate compression time
        logger.info("Backup compression completed")
    
    async def _encrypt_backup(self, backup_dir: Path):
        """Encrypt backup files"""
        logger.info("Encrypting backup files")
        
        # In real implementation, you would encrypt files with AES
        # For demo, create an encryption marker file
        encrypted_marker = backup_dir / "encrypted.flag"
        with open(encrypted_marker, 'w') as f:
            f.write("Backup encrypted with AES-256")
        
        await asyncio.sleep(1)  # Simulate encryption time
        logger.info("Backup encryption completed")
    
    async def _calculate_backup_size(self, backup_dir: Path) -> int:
        """Calculate total backup size in MB"""
        total_size = 0
        for file_path in backup_dir.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        
        return total_size // (1024 * 1024)  # Convert to MB
    
    async def instant_restore_from_path(self, backup_path: str, target_platform: PlatformType, 
                                       restore_config: Dict[str, Any], backup_metadata: Dict[str, Any] = None):
        """Perform instant VM restore from a specific backup path"""
        logger.info(f"Starting instant restore from path {backup_path}")
        
        try:
            backup_dir = Path(backup_path)
            
            if not backup_dir.exists():
                raise Exception(f"Backup path {backup_path} does not exist")
            
            # Load backup metadata if available
            metadata_file = backup_dir / "backup_metadata.json"
            metadata = {}
            
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            elif backup_metadata:
                metadata = backup_metadata
            
            # Get target platform connector
            if target_platform.value == 'ubuntu':
                platform_key = 'ubuntu'
            else:
                platform_key = target_platform
            connector = self.connectors[platform_key]
            
            if not connector.connected:
                raise Exception(f"Not connected to target platform {target_platform}")
            
            # Decrypt if needed
            if metadata.get("encrypted"):
                await self._decrypt_backup(backup_dir)
            
            # Decompress if needed
            if metadata.get("compressed"):
                await self._decompress_backup(backup_dir)
            
            # Import VM to target platform
            imported_vm_id = await connector.import_vm(str(backup_dir), restore_config)
            
            logger.info(f"Instant restore completed. New VM ID: {imported_vm_id}")
            return {
                "status": "success",
                "new_vm_id": imported_vm_id,
                "restore_time": "15 seconds"
            }
            
        except Exception as e:
            logger.error(f"Instant restore failed: {e}")
            raise
    
    async def instant_restore(self, backup_id: str, target_platform: PlatformType, restore_config: Dict[str, Any]):
        """Perform instant VM restore with storage manager support (legacy method)"""
        logger.info(f"Starting instant restore for backup {backup_id}")
        
        try:
            # Find backup using storage manager or local storage
            backup_dir = None
            
            if self.storage_manager:
                # Try to retrieve from storage manager
                temp_restore_dir = self.backup_storage_path / f"restore-{backup_id}"
                temp_restore_dir.mkdir(exist_ok=True)
                
                success = await self.storage_manager.retrieve_backup(
                    backup_id, str(temp_restore_dir)
                )
                
                if success:
                    backup_dir = temp_restore_dir
                    logger.info(f"Retrieved backup from storage manager")
                else:
                    logger.warning("Failed to retrieve from storage manager, trying local")
            
            # Fallback to local storage
            if not backup_dir:
                local_backup_dir = self.backup_storage_path / backup_id
                if local_backup_dir.exists():
                    backup_dir = local_backup_dir
                else:
                    raise Exception(f"Backup {backup_id} not found in any storage")
            
            # Use the new restore method
            return await self.instant_restore_from_path(str(backup_dir), target_platform, restore_config)
            
        except Exception as e:
            logger.error(f"Instant restore failed: {e}")
            raise
    
    async def _decrypt_backup(self, backup_dir: Path):
        """Decrypt backup files"""
        logger.info("Decrypting backup files")
        await asyncio.sleep(1)  # Simulate decryption time
    
    async def _decompress_backup(self, backup_dir: Path):
        """Decompress backup files"""
        logger.info("Decompressing backup files")
        await asyncio.sleep(1)  # Simulate decompression time
    
    async def file_restore(self, backup_id: str, file_paths: List[str], target_path: str):
        """Perform file-level restore with storage manager support"""
        logger.info(f"Starting file-level restore for backup {backup_id}")
        
        try:
            # Find backup using storage manager or local storage
            backup_dir = None
            
            if self.storage_manager:
                # Try to retrieve from storage manager
                temp_restore_dir = self.backup_storage_path / f"file-restore-{backup_id}"
                temp_restore_dir.mkdir(exist_ok=True)
                
                success = await self.storage_manager.retrieve_backup(
                    backup_id, str(temp_restore_dir)
                )
                
                if success:
                    backup_dir = temp_restore_dir
                    logger.info(f"Retrieved backup from storage manager for file restore")
                else:
                    logger.warning("Failed to retrieve from storage manager, trying local")
            
            # Fallback to local storage
            if not backup_dir:
                local_backup_dir = self.backup_storage_path / backup_id
                if local_backup_dir.exists():
                    backup_dir = local_backup_dir
                else:
                    raise Exception(f"Backup {backup_id} not found in any storage")
            
            # Simulate file extraction and restore
            await asyncio.sleep(2)
            
            logger.info(f"Restored {len(file_paths)} files to {target_path}")
            return {"status": "success", "files_restored": len(file_paths)}
            
        except Exception as e:
            logger.error(f"File restore failed: {e}")
            raise
    
    async def migrate_vm(self, source_vm_id: str, source_platform: PlatformType, 
                        target_platform: PlatformType, migration_config: Dict[str, Any]):
        """Migrate VM between platforms (V2V)"""
        logger.info(f"Starting V2V migration from {source_platform} to {target_platform}")
        
        try:
            source_key = 'ubuntu' if source_platform.value == 'ubuntu' else source_platform
            target_key = 'ubuntu' if target_platform.value == 'ubuntu' else target_platform
            
            source_connector = self.connectors[source_key]
            target_connector = self.connectors[target_key]
            
            # Get source VM details
            vm_details = await source_connector.get_vm_details(source_vm_id)
            
            # Create temporary export
            temp_export_dir = self.backup_storage_path / "temp_migration"
            temp_export_dir.mkdir(exist_ok=True)
            
            # Export from source
            exported_file = await source_connector.export_vm(source_vm_id, str(temp_export_dir))
            
            # Convert format if needed
            converted_file = await self._convert_vm_format(
                exported_file, source_platform, target_platform
            )
            
            # Import to target
            new_vm_id = await target_connector.import_vm(converted_file, migration_config)
            
            # Cleanup temp files
            import shutil
            shutil.rmtree(temp_export_dir)
            
            logger.info(f"V2V migration completed. New VM ID: {new_vm_id}")
            return {
                "status": "success",
                "source_vm_id": source_vm_id,
                "new_vm_id": new_vm_id
            }
            
        except Exception as e:
            logger.error(f"V2V migration failed: {e}")
            raise
    
    async def _convert_vm_format(self, source_file: str, source_platform: PlatformType, 
                                target_platform: PlatformType) -> str:
        """Convert VM between different formats"""
        logger.info(f"Converting VM format from {source_platform} to {target_platform}")
        
        # Simulate format conversion
        await asyncio.sleep(3)
        
        # In real implementation, you would use tools like qemu-img, ovftool, etc.
        converted_file = source_file.replace(".ovf", ".qcow2").replace(".xva", ".vmdk")
        
        logger.info(f"Format conversion completed: {converted_file}")
        return converted_file


# scheduler.py
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class BackupScheduler:
    """Backup job scheduler using APScheduler"""
    
    def __init__(self, backup_engine: Optional['BackupEngine'] = None):
        self.scheduler = AsyncIOScheduler()
        self.backup_engine = backup_engine
        self.jobs = {}
        
    def start(self):
        """Start the scheduler"""
        try:
            self.scheduler.start()
            logger.info("Backup scheduler started")
        except Exception as e:
            logger.error(f"Failed to start scheduler: {e}")
    
    def shutdown(self):
        """Shutdown the scheduler"""
        try:
            self.scheduler.shutdown()
            logger.info("Backup scheduler stopped")
        except Exception as e:
            logger.error(f"Error stopping scheduler: {e}")
    
    def schedule_job(self, backup_job):
        """Schedule a backup job"""
        try:
            job_id = f"backup_job_{backup_job.id}"
            
            # Parse cron expression
            trigger = CronTrigger.from_crontab(backup_job.schedule_cron)
            
            # Add job to scheduler
            self.scheduler.add_job(
                func=self._execute_backup_job,
                trigger=trigger,
                id=job_id,
                args=[backup_job],
                replace_existing=True,
                max_instances=1
            )
            
            self.jobs[backup_job.id] = job_id
            
            # Calculate next run time
            next_run = self.scheduler.get_job(job_id).next_run_time
            logger.info(f"Scheduled backup job {backup_job.id}: {backup_job.name}")
            logger.info(f"Next run: {next_run}")
            
            return next_run
            
        except Exception as e:
            logger.error(f"Failed to schedule job {backup_job.id}: {e}")
            raise
    
    def remove_job(self, job_id: int):
        """Remove a scheduled job"""
        try:
            scheduler_job_id = f"backup_job_{job_id}"
            if self.scheduler.get_job(scheduler_job_id):
                self.scheduler.remove_job(scheduler_job_id)
                if job_id in self.jobs:
                    del self.jobs[job_id]
                logger.info(f"Removed scheduled job {job_id}")
        except Exception as e:
            logger.error(f"Failed to remove job {job_id}: {e}")
    
    def get_job_next_run(self, job_id: int) -> Optional[datetime]:
        """Get next run time for a job"""
        try:
            scheduler_job_id = f"backup_job_{job_id}"
            job = self.scheduler.get_job(scheduler_job_id)
            return job.next_run_time if job else None
        except Exception as e:
            logger.error(f"Failed to get next run time for job {job_id}: {e}")
            return None
    
    async def _execute_backup_job(self, backup_job):
        """Execute a backup job"""
        logger.info(f"Executing scheduled backup job {backup_job.id}")
        
        if not self.backup_engine:
            logger.error("Backup engine not configured")
            return
        
        try:
            # Update job status to running
            # In a real implementation, you would update the database here
            
            # Execute backup
            result = await self.backup_engine.run_backup(backup_job)
            
            if result["status"] == "success":
                logger.info(f"Scheduled backup job {backup_job.id} completed successfully")
            else:
                logger.error(f"Scheduled backup job {backup_job.id} failed: {result.get('error')}")
                
        except Exception as e:
            logger.error(f"Error executing backup job {backup_job.id}: {e}")
    
    def list_scheduled_jobs(self) -> List[Dict[str, Any]]:
        """List all scheduled jobs"""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "next_run": job.next_run_time,
                "trigger": str(job.trigger)
            })
        return jobs
