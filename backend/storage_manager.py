# storage_manager.py - Enhanced Storage Management with Full Backup Integration
import os
import asyncio
import logging
import subprocess
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from datetime import datetime
import json
import hashlib

logger = logging.getLogger(__name__)

class StorageBackend(ABC):
    """Enhanced base class for storage backends with backup-specific features"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get('name', 'Unnamed Storage')
        self.storage_type = config.get('storage_type')
        self.capacity_gb = config.get('capacity_gb', 0)
        self.used_gb = 0
        self.is_mounted = False
        self.mount_point = None
        self.backup_index = {}  # Track stored backups
        
    @abstractmethod
    async def connect(self) -> bool:
        """Connect/mount the storage backend"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Disconnect/unmount the storage backend"""
        pass
    
    @abstractmethod
    async def test_connection(self) -> Dict[str, Any]:
        """Test storage connectivity and return detailed status"""
        pass
    
    @abstractmethod
    async def get_available_space(self) -> int:
        """Get available space in GB"""
        pass
    
    async def store_backup(self, source_path: str, backup_id: str) -> str:
        """Store a backup and return the storage path with validation"""
        if not self.is_mounted:
            raise Exception(f"Storage backend {self.name} is not mounted")
        
        # Validate source exists
        source = Path(source_path)
        if not source.exists():
            raise Exception(f"Source backup path does not exist: {source_path}")
        
        # Check available space
        available_space = await self.get_available_space()
        source_size = await self._calculate_directory_size(source)
        source_size_gb = source_size / (1024**3)
        
        if available_space < source_size_gb * 1.1:  # Add 10% buffer
            raise Exception(f"Insufficient storage space. Required: {source_size_gb:.1f}GB, Available: {available_space}GB")
        
        # Perform the actual storage operation
        storage_path = await self._do_store_backup(source_path, backup_id)
        
        # Update backup index
        await self._update_backup_index(backup_id, storage_path, source_size)
        
        logger.info(f"Backup {backup_id} stored successfully at {storage_path}")
        return storage_path
    
    async def retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Retrieve a backup to destination path with validation"""
        if not self.is_mounted:
            raise Exception(f"Storage backend {self.name} is not mounted")
        
        # Check if backup exists in index
        if backup_id not in self.backup_index:
            logger.warning(f"Backup {backup_id} not found in index, attempting direct retrieval")
        
        success = await self._do_retrieve_backup(backup_id, destination_path)
        
        if success:
            logger.info(f"Backup {backup_id} retrieved successfully to {destination_path}")
        else:
            logger.error(f"Failed to retrieve backup {backup_id}")
        
        return success
    
    async def delete_backup(self, backup_id: str) -> bool:
        """Delete a backup with proper cleanup"""
        if not self.is_mounted:
            raise Exception(f"Storage backend {self.name} is not mounted")
        
        success = await self._do_delete_backup(backup_id)
        
        if success:
            # Remove from backup index
            if backup_id in self.backup_index:
                del self.backup_index[backup_id]
                await self._save_backup_index()
            
            logger.info(f"Backup {backup_id} deleted successfully")
        else:
            logger.error(f"Failed to delete backup {backup_id}")
        
        return success
    
    async def list_backups(self) -> List[Dict[str, Any]]:
        """List all backups with enhanced metadata"""
        backups = await self._do_list_backups()
        
        # Enhance with index information
        for backup in backups:
            backup_id = backup.get('backup_id')
            if backup_id in self.backup_index:
                backup.update(self.backup_index[backup_id])
        
        return backups
    
    async def verify_backup_integrity(self, backup_id: str) -> Dict[str, Any]:
        """Verify backup integrity using checksums"""
        try:
            backup_info = self.backup_index.get(backup_id, {})
            stored_checksum = backup_info.get('checksum')
            
            if not stored_checksum:
                return {"status": "warning", "message": "No checksum available for verification"}
            
            # Calculate current checksum
            current_checksum = await self._calculate_backup_checksum(backup_id)
            
            if current_checksum == stored_checksum:
                return {"status": "valid", "message": "Backup integrity verified"}
            else:
                return {"status": "corrupted", "message": "Backup integrity check failed"}
                
        except Exception as e:
            return {"status": "error", "message": f"Integrity check failed: {e}"}
    
    # Abstract methods for subclasses to implement
    @abstractmethod
    async def _do_store_backup(self, source_path: str, backup_id: str) -> str:
        """Implement actual backup storage"""
        pass
    
    @abstractmethod
    async def _do_retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Implement actual backup retrieval"""
        pass
    
    @abstractmethod
    async def _do_delete_backup(self, backup_id: str) -> bool:
        """Implement actual backup deletion"""
        pass
    
    @abstractmethod
    async def _do_list_backups(self) -> List[Dict[str, Any]]:
        """Implement actual backup listing"""
        pass
    
    # Helper methods
    async def _calculate_directory_size(self, path: Path) -> int:
        """Calculate total size of directory in bytes"""
        total_size = 0
        if path.is_file():
            return path.stat().st_size
        
        for file_path in path.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        return total_size
    
    async def _update_backup_index(self, backup_id: str, storage_path: str, size_bytes: int):
        """Update backup index with new backup information"""
        self.backup_index[backup_id] = {
            "backup_id": backup_id,
            "storage_path": storage_path,
            "size_bytes": size_bytes,
            "size_mb": size_bytes // (1024 * 1024),
            "stored_at": datetime.now().isoformat(),
            "storage_backend": self.storage_type
        }
        await self._save_backup_index()
    
    async def _save_backup_index(self):
        """Save backup index to storage"""
        if self.mount_point:
            index_file = Path(self.mount_point) / ".backup_index.json"
            try:
                with open(index_file, 'w') as f:
                    json.dump(self.backup_index, f, indent=2)
            except Exception as e:
                logger.warning(f"Failed to save backup index: {e}")
    
    async def _load_backup_index(self):
        """Load backup index from storage"""
        if self.mount_point:
            index_file = Path(self.mount_point) / ".backup_index.json"
            if index_file.exists():
                try:
                    with open(index_file, 'r') as f:
                        self.backup_index = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to load backup index: {e}")
                    self.backup_index = {}
    
    async def _calculate_backup_checksum(self, backup_id: str) -> str:
        """Calculate checksum for a stored backup"""
        # This would need to be implemented based on storage structure
        return "checksum_placeholder"

class LocalStorageBackend(StorageBackend):
    """Enhanced local filesystem storage backend"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_path = Path(config.get('path', '/app/backups'))
        
    async def connect(self) -> bool:
        """Connect to local storage with enhanced validation"""
        try:
            # Ensure directory exists
            self.base_path.mkdir(parents=True, exist_ok=True)
            
            # Test write permissions
            test_file = self.base_path / '.write_test'
            test_file.write_text('test')
            test_file.unlink()
            
            # Test space availability
            statvfs = os.statvfs(self.base_path)
            available_space = (statvfs.f_bavail * statvfs.f_frsize) / (1024**3)
            
            if available_space < 1:  # Minimum 1GB required
                logger.warning(f"Low disk space: {available_space:.1f}GB available")
            
            self.is_mounted = True
            self.mount_point = str(self.base_path)
            
            # Load backup index
            await self._load_backup_index()
            
            logger.info(f"Local storage connected at {self.base_path} ({available_space:.1f}GB available)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to local storage: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from local storage"""
        await self._save_backup_index()
        self.is_mounted = False
        return True
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test local storage with detailed health information"""
        try:
            if not self.base_path.exists():
                return {"status": "error", "message": "Storage path does not exist"}
            
            # Check available space
            statvfs = os.statvfs(self.base_path)
            available_gb = (statvfs.f_bavail * statvfs.f_frsize) / (1024**3)
            total_gb = (statvfs.f_blocks * statvfs.f_frsize) / (1024**3)
            used_gb = total_gb - available_gb
            
            # Test write performance
            test_start = datetime.now()
            test_file = self.base_path / f'.perf_test_{int(test_start.timestamp())}'
            test_data = b'0' * (1024 * 1024)  # 1MB test
            test_file.write_bytes(test_data)
            test_file.unlink()
            write_time = (datetime.now() - test_start).total_seconds()
            
            # Calculate write speed
            write_speed_mbps = 1 / write_time if write_time > 0 else 0
            
            status = "healthy"
            if available_gb < 5:
                status = "warning"
            elif available_gb < 1:
                status = "error"
            
            return {
                "status": status,
                "available_gb": round(available_gb, 2),
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "usage_percent": round((used_gb / total_gb) * 100, 1),
                "write_speed_mbps": round(write_speed_mbps, 2),
                "mount_point": str(self.base_path),
                "backup_count": len(self.backup_index)
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def get_available_space(self) -> int:
        """Get available space in GB"""
        try:
            statvfs = os.statvfs(self.base_path)
            return int((statvfs.f_bavail * statvfs.f_frsize) / (1024**3))
        except:
            return 0
    
    async def _do_store_backup(self, source_path: str, backup_id: str) -> str:
        """Store backup to local filesystem"""
        backup_dir = self.base_path / backup_id
        backup_dir.mkdir(exist_ok=True)
        
        source = Path(source_path)
        
        if source.is_file():
            # Single file
            destination = backup_dir / source.name
            shutil.copy2(source, destination)
        else:
            # Directory - copy entire structure
            destination = backup_dir / "backup_data"
            shutil.copytree(source, destination, dirs_exist_ok=True)
        
        return str(backup_dir)
    
    async def _do_retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Retrieve backup from local filesystem"""
        try:
            backup_path = self.base_path / backup_id
            if not backup_path.exists():
                logger.error(f"Backup path not found: {backup_path}")
                return False
            
            destination = Path(destination_path)
            destination.mkdir(parents=True, exist_ok=True)
            
            # Copy backup data to destination
            if backup_path.is_file():
                shutil.copy2(backup_path, destination)
            else:
                # Copy directory contents
                for item in backup_path.iterdir():
                    if item.is_file():
                        shutil.copy2(item, destination / item.name)
                    else:
                        shutil.copytree(item, destination / item.name, dirs_exist_ok=True)
            
            return True
        except Exception as e:
            logger.error(f"Failed to retrieve backup {backup_id}: {e}")
            return False
    
    async def _do_delete_backup(self, backup_id: str) -> bool:
        """Delete backup from local filesystem"""
        try:
            backup_path = self.base_path / backup_id
            if backup_path.exists():
                if backup_path.is_file():
                    backup_path.unlink()
                else:
                    shutil.rmtree(backup_path)
            return True
        except Exception as e:
            logger.error(f"Failed to delete backup {backup_id}: {e}")
            return False
    
    async def _do_list_backups(self) -> List[Dict[str, Any]]:
        """List all backups in local storage"""
        backups = []
        try:
            for item in self.base_path.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    # Try to load backup metadata
                    metadata_file = item / 'backup_metadata.json'
                    if metadata_file.exists():
                        try:
                            with open(metadata_file, 'r') as f:
                                metadata = json.load(f)
                            backups.append(metadata)
                        except Exception as e:
                            logger.warning(f"Failed to read metadata for {item.name}: {e}")
                            # Fallback metadata
                            stat = item.stat()
                            backups.append({
                                "backup_id": item.name,
                                "size_mb": await self._calculate_directory_size(item) // (1024*1024),
                                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                "storage_backend": "local"
                            })
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
        
        return backups

class NFSStorageBackend(StorageBackend):
    """Enhanced NFS storage backend with improved error handling"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.nfs_server = config.get('server')
        self.nfs_path = config.get('remote_path')
        self.mount_options = config.get('mount_options', 'rw,hard,intr,timeo=300,retrans=3')
        self.local_mount_point = Path(config.get('local_mount_point', f'/mnt/nfs_{self.name.replace(" ", "_")}'))
        
    async def connect(self) -> bool:
        """Mount NFS share with enhanced error handling"""
        try:
            # Create mount point
            self.local_mount_point.mkdir(parents=True, exist_ok=True)
            
            # Check if already mounted
            result = await asyncio.create_subprocess_exec(
                'mountpoint', '-q', str(self.local_mount_point),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode == 0:
                logger.info(f"NFS already mounted at {self.local_mount_point}")
                self.is_mounted = True
                self.mount_point = str(self.local_mount_point)
                await self._load_backup_index()
                return True
            
            # Test NFS server connectivity first
            ping_result = await asyncio.create_subprocess_exec(
                'ping', '-c', '3', '-W', '5', self.nfs_server,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await ping_result.communicate()
            
            if ping_result.returncode != 0:
                logger.error(f"NFS server {self.nfs_server} is not reachable")
                return False
            
            # Mount NFS
            mount_cmd = [
                'mount', '-t', 'nfs',
                '-o', self.mount_options,
                f'{self.nfs_server}:{self.nfs_path}',
                str(self.local_mount_point)
            ]
            
            logger.info(f"Mounting NFS: {' '.join(mount_cmd)}")
            
            result = await asyncio.create_subprocess_exec(
                *mount_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                self.is_mounted = True
                self.mount_point = str(self.local_mount_point)
                await self._load_backup_index()
                logger.info(f"NFS mounted successfully at {self.local_mount_point}")
                return True
            else:
                error_msg = stderr.decode().strip()
                logger.error(f"NFS mount failed: {error_msg}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to mount NFS: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Unmount NFS share"""
        try:
            if not self.is_mounted:
                return True
            
            await self._save_backup_index()
            
            # Force unmount if necessary
            for attempt in range(2):
                umount_cmd = ['umount', str(self.local_mount_point)]
                if attempt == 1:
                    umount_cmd.insert(1, '-f')  # Force unmount on second attempt
                
                result = await asyncio.create_subprocess_exec(
                    *umount_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                
                if result.returncode == 0:
                    self.is_mounted = False
                    logger.info("NFS unmounted successfully")
                    return True
                elif attempt == 0:
                    logger.warning("Normal unmount failed, trying force unmount...")
                    await asyncio.sleep(2)
            
            logger.error("Failed to unmount NFS")
            return False
            
        except Exception as e:
            logger.error(f"Failed to unmount NFS: {e}")
            return False
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test NFS connection with comprehensive diagnostics"""
        try:
            # Test server connectivity
            ping_result = await asyncio.create_subprocess_exec(
                'ping', '-c', '3', '-W', '5', self.nfs_server,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await ping_result.communicate()
            
            if ping_result.returncode != 0:
                return {"status": "error", "message": f"NFS server {self.nfs_server} unreachable"}
            
            # Test NFS exports
            showmount_result = await asyncio.create_subprocess_exec(
                'showmount', '-e', self.nfs_server,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await showmount_result.communicate()
            
            if showmount_result.returncode != 0:
                return {"status": "error", "message": f"Cannot list NFS exports: {stderr.decode()}"}
            
            # Check if our path is exported
            exports = stdout.decode()
            if self.nfs_path not in exports:
                return {"status": "warning", "message": f"Path {self.nfs_path} not found in exports"}
            
            # If mounted, check space and performance
            if self.is_mounted:
                statvfs = os.statvfs(self.local_mount_point)
                available_gb = (statvfs.f_bavail * statvfs.f_frsize) / (1024**3)
                total_gb = (statvfs.f_blocks * statvfs.f_frsize) / (1024**3)
                
                # Test write performance
                test_start = datetime.now()
                test_file = self.local_mount_point / f'.nfs_perf_test_{int(test_start.timestamp())}'
                try:
                    test_data = b'0' * (1024 * 1024)  # 1MB test
                    test_file.write_bytes(test_data)
                    test_file.unlink()
                    write_time = (datetime.now() - test_start).total_seconds()
                    write_speed_mbps = 1 / write_time if write_time > 0 else 0
                except Exception as perf_e:
                    write_speed_mbps = 0
                    logger.warning(f"NFS performance test failed: {perf_e}")
                
                return {
                    "status": "healthy",
                    "available_gb": round(available_gb, 2),
                    "total_gb": round(total_gb, 2),
                    "write_speed_mbps": round(write_speed_mbps, 2),
                    "mount_point": str(self.local_mount_point),
                    "backup_count": len(self.backup_index)
                }
            
            return {"status": "healthy", "message": "NFS server accessible, not mounted"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def get_available_space(self) -> int:
        """Get available space in GB"""
        try:
            if not self.is_mounted:
                return 0
            statvfs = os.statvfs(self.local_mount_point)
            return int((statvfs.f_bavail * statvfs.f_frsize) / (1024**3))
        except:
            return 0
    
    async def _do_store_backup(self, source_path: str, backup_id: str) -> str:
        """Store backup on NFS"""
        backup_dir = self.local_mount_point / backup_id
        backup_dir.mkdir(exist_ok=True)
        
        source = Path(source_path)
        if source.is_file():
            destination = backup_dir / source.name
            shutil.copy2(source, destination)
        else:
            destination = backup_dir / "backup_data"
            shutil.copytree(source, destination, dirs_exist_ok=True)
        
        return str(backup_dir)
    
    async def _do_retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Retrieve backup from NFS"""
        try:
            backup_path = self.local_mount_point / backup_id
            if not backup_path.exists():
                return False
            
            destination = Path(destination_path)
            destination.mkdir(parents=True, exist_ok=True)
            
            for item in backup_path.iterdir():
                if item.is_file():
                    shutil.copy2(item, destination / item.name)
                else:
                    shutil.copytree(item, destination / item.name, dirs_exist_ok=True)
            
            return True
        except Exception as e:
            logger.error(f"Failed to retrieve backup {backup_id}: {e}")
            return False
    
    async def _do_delete_backup(self, backup_id: str) -> bool:
        """Delete backup from NFS"""
        try:
            backup_path = self.local_mount_point / backup_id
            if backup_path.exists():
                if backup_path.is_file():
                    backup_path.unlink()
                else:
                    shutil.rmtree(backup_path)
            return True
        except Exception as e:
            logger.error(f"Failed to delete backup {backup_id}: {e}")
            return False
    
    async def _do_list_backups(self) -> List[Dict[str, Any]]:
        """List all backups on NFS"""
        backups = []
        try:
            for item in self.local_mount_point.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    metadata_file = item / 'backup_metadata.json'
                    if metadata_file.exists():
                        try:
                            with open(metadata_file, 'r') as f:
                                metadata = json.load(f)
                            backups.append(metadata)
                        except:
                            stat = item.stat()
                            backups.append({
                                "backup_id": item.name,
                                "size_mb": await self._calculate_directory_size(item) // (1024*1024),
                                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                "storage_backend": "nfs"
                            })
        except Exception as e:
            logger.error(f"Failed to list NFS backups: {e}")
        
        return backups

class ISCSIStorageBackend(StorageBackend):
    """Enhanced iSCSI storage backend with better session management"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.target_ip = config.get('target_ip')
        self.target_port = config.get('target_port', 3260)
        self.target_iqn = config.get('target_iqn')
        self.initiator_name = config.get('initiator_name')
        self.username = config.get('username')
        self.password = config.get('password')
        self.local_mount_point = Path(config.get('local_mount_point', f'/mnt/iscsi_{self.name.replace(" ", "_")}'))
        self.device_path = None
        self.session_active = False
        
    async def connect(self) -> bool:
        """Connect to iSCSI target with full session management"""
        try:
            # Configure initiator name if provided
            if self.initiator_name:
                initiator_file = Path('/etc/iscsi/initiatorname.iscsi')
                if initiator_file.exists():
                    with open(initiator_file, 'w') as f:
                        f.write(f'InitiatorName={self.initiator_name}\n')
            
            # Start iSCSI services
            services = ['iscsid', 'open-iscsi']
            for service in services:
                try:
                    result = await asyncio.create_subprocess_exec(
                        'systemctl', 'start', service,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await result.communicate()
                except:
                    pass  # Service might not exist or already running
            
            # Test target connectivity
            test_result = await asyncio.create_subprocess_exec(
                'nc', '-z', '-v', self.target_ip, str(self.target_port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await test_result.communicate()
            
            if test_result.returncode != 0:
                logger.error(f"iSCSI target {self.target_ip}:{self.target_port} is not reachable")
                return False
            
            # Discover targets
            discover_cmd = ['iscsiadm', '-m', 'discovery', '-t', 'st', '-p', f'{self.target_ip}:{self.target_port}']
            result = await asyncio.create_subprocess_exec(
                *discover_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                logger.error(f"iSCSI discovery failed: {stderr.decode()}")
                return False
            
            # Check if our target is in the discovery results
            if self.target_iqn not in stdout.decode():
                logger.error(f"Target IQN {self.target_iqn} not found in discovery results")
                return False
            
            # Configure authentication if provided
            if self.username and self.password:
                auth_commands = [
                    ['iscsiadm', '-m', 'node', '-T', self.target_iqn, '-p', f'{self.target_ip}:{self.target_port}', 
                     '--op=update', '--name', 'node.session.auth.authmethod', '--value=CHAP'],
                    ['iscsiadm', '-m', 'node', '-T', self.target_iqn, '-p', f'{self.target_ip}:{self.target_port}', 
                     '--op=update', '--name', 'node.session.auth.username', f'--value={self.username}'],
                    ['iscsiadm', '-m', 'node', '-T', self.target_iqn, '-p', f'{self.target_ip}:{self.target_port}', 
                     '--op=update', '--name', 'node.session.auth.password', f'--value={self.password}']
                ]
                
                for cmd in auth_commands:
                    result = await asyncio.create_subprocess_exec(*cmd)
                    await result.communicate()
            
            # Login to target
            login_cmd = ['iscsiadm', '-m', 'node', '-T', self.target_iqn, '-p', f'{self.target_ip}:{self.target_port}', '--login']
            result = await asyncio.create_subprocess_exec(
                *login_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0 and "already exists" not in stderr.decode():
                logger.error(f"iSCSI login failed: {stderr.decode()}")
                return False
            
            self.session_active = True
            
            # Wait for device to appear
            await asyncio.sleep(3)
            
            # Find the device
            device_pattern = f"ip-{self.target_ip}:*-iscsi-{self.target_iqn}-*"
            by_path_dir = Path('/dev/disk/by-path/')
            
            if by_path_dir.exists():
                devices = list(by_path_dir.glob(device_pattern))
                if devices:
                    self.device_path = devices[0].resolve()
                else:
                    logger.error("iSCSI device not found in /dev/disk/by-path/")
                    return False
            else:
                logger.error("/dev/disk/by-path/ directory not found")
                return False
            
            # Check if device has a filesystem
            fstype_result = await asyncio.create_subprocess_exec(
                'blkid', '-o', 'value', '-s', 'TYPE', str(self.device_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await fstype_result.communicate()
            
            if not stdout.decode().strip():
                # Create ext4 filesystem
                logger.info(f"Creating filesystem on {self.device_path}")
                mkfs_result = await asyncio.create_subprocess_exec(
                    'mkfs.ext4', '-F', str(self.device_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await mkfs_result.communicate()
                
                if mkfs_result.returncode != 0:
                    logger.error("Failed to create filesystem")
                    return False
            
            # Mount the device
            self.local_mount_point.mkdir(parents=True, exist_ok=True)
            
            mount_result = await asyncio.create_subprocess_exec(
                'mount', str(self.device_path), str(self.local_mount_point),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await mount_result.communicate()
            
            if mount_result.returncode == 0:
                self.is_mounted = True
                self.mount_point = str(self.local_mount_point)
                await self._load_backup_index()
                logger.info(f"iSCSI mounted successfully at {self.local_mount_point}")
                return True
            else:
                logger.error(f"Failed to mount iSCSI device: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to iSCSI: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from iSCSI target with proper cleanup"""
        try:
            if self.is_mounted:
                await self._save_backup_index()
                
                # Unmount filesystem
                umount_result = await asyncio.create_subprocess_exec(
                    'umount', str(self.local_mount_point),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await umount_result.communicate()
                self.is_mounted = False
            
            if self.session_active:
                # Logout from iSCSI target
                logout_cmd = ['iscsiadm', '-m', 'node', '-T', self.target_iqn, '-p', f'{self.target_ip}:{self.target_port}', '--logout']
                result = await asyncio.create_subprocess_exec(
                    *logout_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                self.session_active = False
            
            logger.info("iSCSI disconnected successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disconnect iSCSI: {e}")
            return False
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test iSCSI connection with detailed diagnostics"""
        try:
            # Test target reachability
            test_result = await asyncio.create_subprocess_exec(
                'nc', '-z', '-v', self.target_ip, str(self.target_port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await test_result.communicate()
            
            if test_result.returncode != 0:
                return {"status": "error", "message": f"iSCSI target {self.target_ip}:{self.target_port} unreachable"}
            
            # Test discovery
            discover_result = await asyncio.create_subprocess_exec(
                'iscsiadm', '-m', 'discovery', '-t', 'st', '-p', f'{self.target_ip}:{self.target_port}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await discover_result.communicate()
            
            if discover_result.returncode != 0:
                return {"status": "error", "message": f"iSCSI discovery failed: {stderr.decode()}"}
            
            if self.target_iqn not in stdout.decode():
                return {"status": "error", "message": f"Target IQN {self.target_iqn} not found"}
            
            if self.is_mounted:
                statvfs = os.statvfs(self.local_mount_point)
                available_gb = (statvfs.f_bavail * statvfs.f_frsize) / (1024**3)
                total_gb = (statvfs.f_blocks * statvfs.f_frsize) / (1024**3)
                
                # Test write performance
                test_start = datetime.now()
                test_file = self.local_mount_point / f'.iscsi_perf_test_{int(test_start.timestamp())}'
                try:
                    test_data = b'0' * (1024 * 1024)  # 1MB test
                    test_file.write_bytes(test_data)
                    test_file.unlink()
                    write_time = (datetime.now() - test_start).total_seconds()
                    write_speed_mbps = 1 / write_time if write_time > 0 else 0
                except Exception:
                    write_speed_mbps = 0
                
                return {
                    "status": "healthy",
                    "available_gb": round(available_gb, 2),
                    "total_gb": round(total_gb, 2),
                    "write_speed_mbps": round(write_speed_mbps, 2),
                    "mount_point": str(self.local_mount_point),
                    "device": str(self.device_path),
                    "session_active": self.session_active,
                    "backup_count": len(self.backup_index)
                }
            
            return {"status": "healthy", "message": "iSCSI target accessible, not mounted"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def get_available_space(self) -> int:
        """Get available space in GB"""
        try:
            if not self.is_mounted:
                return 0
            statvfs = os.statvfs(self.local_mount_point)
            return int((statvfs.f_bavail * statvfs.f_frsize) / (1024**3))
        except:
            return 0
    
    async def _do_store_backup(self, source_path: str, backup_id: str) -> str:
        """Store backup on iSCSI"""
        backup_dir = self.local_mount_point / backup_id
        backup_dir.mkdir(exist_ok=True)
        
        source = Path(source_path)
        if source.is_file():
            destination = backup_dir / source.name
            shutil.copy2(source, destination)
        else:
            destination = backup_dir / "backup_data"
            shutil.copytree(source, destination, dirs_exist_ok=True)
        
        return str(backup_dir)
    
    async def _do_retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Retrieve backup from iSCSI"""
        try:
            backup_path = self.local_mount_point / backup_id
            if not backup_path.exists():
                return False
            
            destination = Path(destination_path)
            destination.mkdir(parents=True, exist_ok=True)
            
            for item in backup_path.iterdir():
                if item.is_file():
                    shutil.copy2(item, destination / item.name)
                else:
                    shutil.copytree(item, destination / item.name, dirs_exist_ok=True)
            
            return True
        except Exception as e:
            logger.error(f"Failed to retrieve backup {backup_id}: {e}")
            return False
    
    async def _do_delete_backup(self, backup_id: str) -> bool:
        """Delete backup from iSCSI"""
        try:
            backup_path = self.local_mount_point / backup_id
            if backup_path.exists():
                if backup_path.is_file():
                    backup_path.unlink()
                else:
                    shutil.rmtree(backup_path)
            return True
        except Exception as e:
            logger.error(f"Failed to delete backup {backup_id}: {e}")
            return False
    
    async def _do_list_backups(self) -> List[Dict[str, Any]]:
        """List all backups on iSCSI"""
        backups = []
        try:
            for item in self.local_mount_point.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    metadata_file = item / 'backup_metadata.json'
                    if metadata_file.exists():
                        try:
                            with open(metadata_file, 'r') as f:
                                metadata = json.load(f)
                            backups.append(metadata)
                        except:
                            stat = item.stat()
                            backups.append({
                                "backup_id": item.name,
                                "size_mb": await self._calculate_directory_size(item) // (1024*1024),
                                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                "storage_backend": "iscsi"
                            })
        except Exception as e:
            logger.error(f"Failed to list iSCSI backups: {e}")
        
        return backups

class StorageManager:
    """Enhanced storage management system with advanced features"""
    
    def __init__(self):
        self.backends: Dict[str, StorageBackend] = {}
        self.default_backend = None
        self.backup_distribution = {}  # Track backup distribution across backends
        
    def register_backend(self, backend_id: str, backend: StorageBackend):
        """Register a storage backend"""
        self.backends[backend_id] = backend
        if self.default_backend is None:
            self.default_backend = backend_id
        logger.info(f"Registered storage backend: {backend_id} ({backend.storage_type})")
    
    def get_backend(self, backend_id: str) -> Optional[StorageBackend]:
        """Get a storage backend by ID"""
        return self.backends.get(backend_id)
    
    def get_default_backend(self) -> Optional[StorageBackend]:
        """Get the default storage backend"""
        if self.default_backend:
            return self.backends.get(self.default_backend)
        return None
    
    async def connect_all(self) -> Dict[str, bool]:
        """Connect all storage backends with detailed results"""
        results = {}
        for backend_id, backend in self.backends.items():
            try:
                logger.info(f"Connecting to storage backend: {backend_id}")
                results[backend_id] = await backend.connect()
                if results[backend_id]:
                    logger.info(f"✅ {backend_id} connected successfully")
                else:
                    logger.error(f"❌ {backend_id} connection failed")
            except Exception as e:
                logger.error(f"Failed to connect backend {backend_id}: {e}")
                results[backend_id] = False
        return results
    
    async def disconnect_all(self) -> Dict[str, bool]:
        """Disconnect all storage backends"""
        results = {}
        for backend_id, backend in self.backends.items():
            try:
                results[backend_id] = await backend.disconnect()
            except Exception as e:
                logger.error(f"Failed to disconnect backend {backend_id}: {e}")
                results[backend_id] = False
        return results
    
    async def test_all_connections(self) -> Dict[str, Dict[str, Any]]:
        """Test all storage backend connections with health details"""
        results = {}
        for backend_id, backend in self.backends.items():
            try:
                results[backend_id] = await backend.test_connection()
            except Exception as e:
                results[backend_id] = {"status": "error", "message": str(e)}
        return results
    
    def create_backend_from_config(self, config: Dict[str, Any]) -> StorageBackend:
        """Create a storage backend from configuration"""
        storage_type = config.get('storage_type')
        
        if storage_type == 'local':
            return LocalStorageBackend(config)
        elif storage_type == 'nfs':
            return NFSStorageBackend(config)
        elif storage_type == 'iscsi':
            return ISCSIStorageBackend(config)
        else:
            raise ValueError(f"Unsupported storage type: {storage_type}")
    
    async def store_backup(self, source_path: str, backup_id: str, backend_id: str = None) -> str:
        """Store a backup using specified or optimal backend"""
        backend = self.get_backend(backend_id) if backend_id else await self._select_optimal_backend()
        if not backend:
            raise Exception("No storage backend available")
        
        storage_path = await backend.store_backup(source_path, backup_id)
        
        # Update distribution tracking
        self.backup_distribution[backup_id] = {
            "backend_id": backend_id or self.default_backend,
            "storage_path": storage_path,
            "stored_at": datetime.now().isoformat()
        }
        
        return storage_path
    
    async def retrieve_backup(self, backup_id: str, destination_path: str, backend_id: str = None) -> bool:
        """Retrieve a backup using specified backend or auto-detect"""
        if backend_id:
            backend = self.get_backend(backend_id)
        else:
            # Try to find which backend has this backup
            backend = await self._find_backup_backend(backup_id)
        
        if not backend:
            raise Exception("No storage backend available or backup not found")
        
        return await backend.retrieve_backup(backup_id, destination_path)
    
    async def delete_backup(self, backup_id: str, backend_id: str = None) -> bool:
        """Delete a backup from specified or all backends"""
        if backend_id:
            backend = self.get_backend(backend_id)
            if backend:
                return await backend.delete_backup(backup_id)
            return False
        else:
            # Try all backends
            success = False
            for backend in self.backends.values():
                try:
                    if await backend.delete_backup(backup_id):
                        success = True
                except Exception as e:
                    logger.warning(f"Failed to delete from {backend.name}: {e}")
            
            # Remove from distribution tracking
            if backup_id in self.backup_distribution:
                del self.backup_distribution[backup_id]
            
            return success
    
    async def list_all_backups(self) -> Dict[str, List[Dict[str, Any]]]:
        """List backups from all storage backends"""
        all_backups = {}
        for backend_id, backend in self.backends.items():
            try:
                all_backups[backend_id] = await backend.list_backups()
            except Exception as e:
                logger.error(f"Failed to list backups from {backend_id}: {e}")
                all_backups[backend_id] = []
        return all_backups
    
    async def verify_backup_integrity(self, backup_id: str, backend_id: str = None) -> Dict[str, Any]:
        """Verify backup integrity across storage backends"""
        if backend_id:
            backend = self.get_backend(backend_id)
            if backend:
                return await backend.verify_backup_integrity(backup_id)
            return {"status": "error", "message": "Backend not found"}
        else:
            # Check all backends
            results = {}
            for bid, backend in self.backends.items():
                try:
                    results[bid] = await backend.verify_backup_integrity(backup_id)
                except Exception as e:
                    results[bid] = {"status": "error", "message": str(e)}
            return results
    
    async def get_storage_statistics(self) -> Dict[str, Any]:
        """Get comprehensive storage statistics"""
        stats = {
            "total_backends": len(self.backends),
            "connected_backends": 0,
            "total_capacity_gb": 0,
            "total_used_gb": 0,
            "total_available_gb": 0,
            "backend_details": {},
            "backup_distribution": self.backup_distribution
        }
        
        for backend_id, backend in self.backends.items():
            try:
                health = await backend.test_connection()
                if health.get("status") == "healthy":
                    stats["connected_backends"] += 1
                
                if "total_gb" in health:
                    stats["total_capacity_gb"] += health["total_gb"]
                if "available_gb" in health:
                    stats["total_available_gb"] += health["available_gb"]
                if "used_gb" in health:
                    stats["total_used_gb"] += health.get("used_gb", 0)
                
                stats["backend_details"][backend_id] = health
                
            except Exception as e:
                stats["backend_details"][backend_id] = {"status": "error", "message": str(e)}
        
        return stats
    
    # Private helper methods
    async def _select_optimal_backend(self) -> Optional[StorageBackend]:
        """Select optimal backend based on space and performance"""
        best_backend = None
        best_score = -1
        
        for backend in self.backends.values():
            if not backend.is_mounted:
                continue
            
            try:
                health = await backend.test_connection()
                if health.get("status") != "healthy":
                    continue
                
                # Calculate score based on available space and speed
                available_gb = health.get("available_gb", 0)
                write_speed = health.get("write_speed_mbps", 1)
                
                # Score formula: available space + speed factor
                score = available_gb + (write_speed * 10)
                
                if score > best_score:
                    best_score = score
                    best_backend = backend
                    
            except Exception as e:
                logger.warning(f"Failed to evaluate backend {backend.name}: {e}")
        
        return best_backend or self.get_default_backend()
    
    async def _find_backup_backend(self, backup_id: str) -> Optional[StorageBackend]:
        """Find which backend contains a specific backup"""
        # First check distribution tracking
        if backup_id in self.backup_distribution:
            backend_id = self.backup_distribution[backup_id]["backend_id"]
            return self.get_backend(backend_id)
        
        # Search all backends
        for backend in self.backends.values():
            try:
                backups = await backend.list_backups()
                for backup in backups:
                    if backup.get("backup_id") == backup_id:
                        return backend
            except Exception as e:
                logger.warning(f"Failed to search backend {backend.name}: {e}")
        
        return None
