# storage_manager.py - Advanced Storage Backend Management
import os
import asyncio
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from datetime import datetime
import json
import tempfile

logger = logging.getLogger(__name__)

class StorageBackend(ABC):
    """Abstract base class for storage backends"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get('name', 'Unnamed Storage')
        self.storage_type = config.get('storage_type')
        self.capacity_gb = config.get('capacity_gb', 0)
        self.used_gb = 0
        self.is_mounted = False
        self.mount_point = None
        
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
        """Test storage connectivity and return status"""
        pass
    
    @abstractmethod
    async def get_available_space(self) -> int:
        """Get available space in GB"""
        pass
    
    @abstractmethod
    async def store_backup(self, source_path: str, backup_id: str) -> str:
        """Store a backup and return the storage path"""
        pass
    
    @abstractmethod
    async def retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Retrieve a backup to destination path"""
        pass
    
    @abstractmethod
    async def delete_backup(self, backup_id: str) -> bool:
        """Delete a backup"""
        pass
    
    @abstractmethod
    async def list_backups(self) -> List[Dict[str, Any]]:
        """List all backups in this storage"""
        pass

class LocalStorageBackend(StorageBackend):
    """Local filesystem storage backend"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_path = Path(config.get('path', '/app/backups'))
        
    async def connect(self) -> bool:
        """Connect to local storage"""
        try:
            # Ensure directory exists
            self.base_path.mkdir(parents=True, exist_ok=True)
            
            # Test write permissions
            test_file = self.base_path / '.write_test'
            test_file.write_text('test')
            test_file.unlink()
            
            self.is_mounted = True
            self.mount_point = str(self.base_path)
            logger.info(f"Local storage connected at {self.base_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to local storage: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from local storage"""
        self.is_mounted = False
        return True
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test local storage"""
        try:
            if not self.base_path.exists():
                return {"status": "error", "message": "Path does not exist"}
            
            # Check available space
            statvfs = os.statvfs(self.base_path)
            available_gb = (statvfs.f_bavail * statvfs.f_frsize) / (1024**3)
            total_gb = (statvfs.f_blocks * statvfs.f_frsize) / (1024**3)
            
            return {
                "status": "healthy",
                "available_gb": round(available_gb, 2),
                "total_gb": round(total_gb, 2),
                "mount_point": str(self.base_path)
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
    
    async def store_backup(self, source_path: str, backup_id: str) -> str:
        """Store backup locally"""
        backup_dir = self.base_path / backup_id
        backup_dir.mkdir(exist_ok=True)
        
        source = Path(source_path)
        if source.is_file():
            # Single file
            destination = backup_dir / source.name
            shutil.copy2(source, destination)
        else:
            # Directory
            shutil.copytree(source, backup_dir / source.name, dirs_exist_ok=True)
        
        return str(backup_dir)
    
    async def retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Retrieve backup from local storage"""
        try:
            backup_path = self.base_path / backup_id
            if not backup_path.exists():
                return False
            
            destination = Path(destination_path)
            destination.mkdir(parents=True, exist_ok=True)
            
            if backup_path.is_file():
                shutil.copy2(backup_path, destination)
            else:
                shutil.copytree(backup_path, destination, dirs_exist_ok=True)
            
            return True
        except Exception as e:
            logger.error(f"Failed to retrieve backup {backup_id}: {e}")
            return False
    
    async def delete_backup(self, backup_id: str) -> bool:
        """Delete backup from local storage"""
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
    
    async def list_backups(self) -> List[Dict[str, Any]]:
        """List all backups in local storage"""
        backups = []
        try:
            for item in self.base_path.iterdir():
                if item.is_dir():
                    # Try to load backup metadata
                    metadata_file = item / 'backup_metadata.json'
                    if metadata_file.exists():
                        try:
                            with open(metadata_file, 'r') as f:
                                metadata = json.load(f)
                            backups.append(metadata)
                        except:
                            # Fallback metadata
                            stat = item.stat()
                            backups.append({
                                "backup_id": item.name,
                                "size_mb": sum(f.stat().st_size for f in item.rglob('*') if f.is_file()) // (1024*1024),
                                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                "storage_backend": "local"
                            })
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
        
        return backups

class NFSStorageBackend(StorageBackend):
    """NFS storage backend"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.nfs_server = config.get('server')
        self.nfs_path = config.get('remote_path')
        self.mount_options = config.get('mount_options', 'rw,hard,intr')
        self.local_mount_point = Path(config.get('local_mount_point', f'/mnt/nfs_{self.name}'))
        
    async def connect(self) -> bool:
        """Mount NFS share"""
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
                return True
            
            # Mount NFS
            mount_cmd = [
                'mount', '-t', 'nfs',
                '-o', self.mount_options,
                f'{self.nfs_server}:{self.nfs_path}',
                str(self.local_mount_point)
            ]
            
            result = await asyncio.create_subprocess_exec(
                *mount_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                self.is_mounted = True
                self.mount_point = str(self.local_mount_point)
                logger.info(f"NFS mounted successfully at {self.local_mount_point}")
                return True
            else:
                logger.error(f"NFS mount failed: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to mount NFS: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Unmount NFS share"""
        try:
            if not self.is_mounted:
                return True
                
            result = await asyncio.create_subprocess_exec(
                'umount', str(self.local_mount_point),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            self.is_mounted = False
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Failed to unmount NFS: {e}")
            return False
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test NFS connection"""
        try:
            # Test server connectivity
            result = await asyncio.create_subprocess_exec(
                'showmount', '-e', self.nfs_server,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                return {"status": "error", "message": f"NFS server unreachable: {stderr.decode()}"}
            
            # Check if our path is exported
            exports = stdout.decode()
            if self.nfs_path not in exports:
                return {"status": "warning", "message": f"Path {self.nfs_path} not found in exports"}
            
            # If mounted, check space
            if self.is_mounted:
                statvfs = os.statvfs(self.local_mount_point)
                available_gb = (statvfs.f_bavail * statvfs.f_frsize) / (1024**3)
                total_gb = (statvfs.f_blocks * statvfs.f_frsize) / (1024**3)
                
                return {
                    "status": "healthy",
                    "available_gb": round(available_gb, 2),
                    "total_gb": round(total_gb, 2),
                    "mount_point": str(self.local_mount_point)
                }
            
            return {"status": "healthy", "message": "NFS server accessible"}
            
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
    
    async def store_backup(self, source_path: str, backup_id: str) -> str:
        """Store backup on NFS"""
        if not self.is_mounted:
            raise Exception("NFS not mounted")
        
        backup_dir = self.local_mount_point / backup_id
        backup_dir.mkdir(exist_ok=True)
        
        source = Path(source_path)
        if source.is_file():
            destination = backup_dir / source.name
            shutil.copy2(source, destination)
        else:
            shutil.copytree(source, backup_dir / source.name, dirs_exist_ok=True)
        
        return str(backup_dir)
    
    async def retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Retrieve backup from NFS"""
        try:
            if not self.is_mounted:
                return False
                
            backup_path = self.local_mount_point / backup_id
            if not backup_path.exists():
                return False
            
            destination = Path(destination_path)
            destination.mkdir(parents=True, exist_ok=True)
            
            if backup_path.is_file():
                shutil.copy2(backup_path, destination)
            else:
                shutil.copytree(backup_path, destination, dirs_exist_ok=True)
            
            return True
        except Exception as e:
            logger.error(f"Failed to retrieve backup {backup_id}: {e}")
            return False
    
    async def delete_backup(self, backup_id: str) -> bool:
        """Delete backup from NFS"""
        try:
            if not self.is_mounted:
                return False
                
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
    
    async def list_backups(self) -> List[Dict[str, Any]]:
        """List all backups on NFS"""
        if not self.is_mounted:
            return []
        
        backups = []
        try:
            for item in self.local_mount_point.iterdir():
                if item.is_dir():
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
                                "size_mb": sum(f.stat().st_size for f in item.rglob('*') if f.is_file()) // (1024*1024),
                                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                "storage_backend": "nfs"
                            })
        except Exception as e:
            logger.error(f"Failed to list NFS backups: {e}")
        
        return backups

class ISCSIStorageBackend(StorageBackend):
    """iSCSI storage backend"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.target_ip = config.get('target_ip')
        self.target_port = config.get('target_port', 3260)
        self.target_iqn = config.get('target_iqn')
        self.initiator_name = config.get('initiator_name')
        self.username = config.get('username')
        self.password = config.get('password')
        self.local_mount_point = Path(config.get('local_mount_point', f'/mnt/iscsi_{self.name}'))
        self.device_path = None
        
    async def connect(self) -> bool:
        """Connect to iSCSI target"""
        try:
            # Configure initiator name if provided
            if self.initiator_name:
                with open('/etc/iscsi/initiatorname.iscsi', 'w') as f:
                    f.write(f'InitiatorName={self.initiator_name}\n')
            
            # Configure authentication if provided
            if self.username and self.password:
                iscsid_conf = f'''
node.session.auth.authmethod = CHAP
node.session.auth.username = {self.username}
node.session.auth.password = {self.password}
discovery.sendtargets.auth.authmethod = CHAP
discovery.sendtargets.auth.username = {self.username}
discovery.sendtargets.auth.password = {self.password}
'''
                with open('/etc/iscsi/iscsid.conf', 'a') as f:
                    f.write(iscsid_conf)
            
            # Start iSCSI service
            await asyncio.create_subprocess_exec('systemctl', 'start', 'iscsid')
            await asyncio.create_subprocess_exec('systemctl', 'start', 'open-iscsi')
            
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
            
            # Login to target
            login_cmd = ['iscsiadm', '-m', 'node', '-T', self.target_iqn, '-p', f'{self.target_ip}:{self.target_port}', '--login']
            result = await asyncio.create_subprocess_exec(
                *login_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode != 0:
                logger.error(f"iSCSI login failed: {stderr.decode()}")
                return False
            
            # Wait for device to appear and find it
            await asyncio.sleep(2)
            
            # Find the device
            devices = list(Path('/dev/disk/by-path/').glob(f'ip-{self.target_ip}:*-iscsi-{self.target_iqn}-*'))
            if not devices:
                logger.error("iSCSI device not found")
                return False
            
            self.device_path = devices[0].resolve()
            
            # Create filesystem if needed
            fstype_result = await asyncio.create_subprocess_exec(
                'blkid', '-o', 'value', '-s', 'TYPE', str(self.device_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await fstype_result.communicate()
            
            if not stdout.decode().strip():
                # Create ext4 filesystem
                mkfs_result = await asyncio.create_subprocess_exec(
                    'mkfs.ext4', '-F', str(self.device_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await mkfs_result.communicate()
            
            # Mount the device
            self.local_mount_point.mkdir(parents=True, exist_ok=True)
            
            mount_result = await asyncio.create_subprocess_exec(
                'mount', str(self.device_path), str(self.local_mount_point),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await mount_result.communicate()
            
            if mount_result.returncode == 0:
                self.is_mounted = True
                self.mount_point = str(self.local_mount_point)
                logger.info(f"iSCSI mounted successfully at {self.local_mount_point}")
                return True
            else:
                logger.error("Failed to mount iSCSI device")
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to iSCSI: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from iSCSI target"""
        try:
            if self.is_mounted:
                # Unmount
                await asyncio.create_subprocess_exec('umount', str(self.local_mount_point))
                self.is_mounted = False
            
            # Logout from iSCSI target
            logout_cmd = ['iscsiadm', '-m', 'node', '-T', self.target_iqn, '-p', f'{self.target_ip}:{self.target_port}', '--logout']
            await asyncio.create_subprocess_exec(*logout_cmd)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to disconnect iSCSI: {e}")
            return False
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test iSCSI connection"""
        try:
            # Test target reachability
            result = await asyncio.create_subprocess_exec(
                'nc', '-z', '-v', self.target_ip, str(self.target_port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            
            if result.returncode != 0:
                return {"status": "error", "message": f"iSCSI target {self.target_ip}:{self.target_port} unreachable"}
            
            if self.is_mounted:
                statvfs = os.statvfs(self.local_mount_point)
                available_gb = (statvfs.f_bavail * statvfs.f_frsize) / (1024**3)
                total_gb = (statvfs.f_blocks * statvfs.f_frsize) / (1024**3)
                
                return {
                    "status": "healthy",
                    "available_gb": round(available_gb, 2),
                    "total_gb": round(total_gb, 2),
                    "mount_point": str(self.local_mount_point),
                    "device": str(self.device_path)
                }
            
            return {"status": "healthy", "message": "iSCSI target reachable"}
            
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
    
    async def store_backup(self, source_path: str, backup_id: str) -> str:
        """Store backup on iSCSI"""
        if not self.is_mounted:
            raise Exception("iSCSI not mounted")
        
        backup_dir = self.local_mount_point / backup_id
        backup_dir.mkdir(exist_ok=True)
        
        source = Path(source_path)
        if source.is_file():
            destination = backup_dir / source.name
            shutil.copy2(source, destination)
        else:
            shutil.copytree(source, backup_dir / source.name, dirs_exist_ok=True)
        
        return str(backup_dir)
    
    async def retrieve_backup(self, backup_id: str, destination_path: str) -> bool:
        """Retrieve backup from iSCSI"""
        try:
            if not self.is_mounted:
                return False
                
            backup_path = self.local_mount_point / backup_id
            if not backup_path.exists():
                return False
            
            destination = Path(destination_path)
            destination.mkdir(parents=True, exist_ok=True)
            
            if backup_path.is_file():
                shutil.copy2(backup_path, destination)
            else:
                shutil.copytree(backup_path, destination, dirs_exist_ok=True)
            
            return True
        except Exception as e:
            logger.error(f"Failed to retrieve backup {backup_id}: {e}")
            return False
    
    async def delete_backup(self, backup_id: str) -> bool:
        """Delete backup from iSCSI"""
        try:
            if not self.is_mounted:
                return False
                
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
    
    async def list_backups(self) -> List[Dict[str, Any]]:
        """List all backups on iSCSI"""
        if not self.is_mounted:
            return []
        
        backups = []
        try:
            for item in self.local_mount_point.iterdir():
                if item.is_dir():
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
                                "size_mb": sum(f.stat().st_size for f in item.rglob('*') if f.is_file()) // (1024*1024),
                                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                "storage_backend": "iscsi"
                            })
        except Exception as e:
            logger.error(f"Failed to list iSCSI backups: {e}")
        
        return backups

class StorageManager:
    """Central storage management system"""
    
    def __init__(self):
        self.backends: Dict[str, StorageBackend] = {}
        self.default_backend = None
        
    def register_backend(self, backend_id: str, backend: StorageBackend):
        """Register a storage backend"""
        self.backends[backend_id] = backend
        if self.default_backend is None:
            self.default_backend = backend_id
    
    def get_backend(self, backend_id: str) -> Optional[StorageBackend]:
        """Get a storage backend by ID"""
        return self.backends.get(backend_id)
    
    def get_default_backend(self) -> Optional[StorageBackend]:
        """Get the default storage backend"""
        if self.default_backend:
            return self.backends.get(self.default_backend)
        return None
    
    async def connect_all(self) -> Dict[str, bool]:
        """Connect all storage backends"""
        results = {}
        for backend_id, backend in self.backends.items():
            try:
                results[backend_id] = await backend.connect()
            except Exception as e:
                logger.error(f"Failed to connect backend {backend_id}: {e}")
                results[backend_id] = False
        return results
    
    async def test_all_connections(self) -> Dict[str, Dict[str, Any]]:
        """Test all storage backend connections"""
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
        """Store a backup using specified or default backend"""
        backend = self.get_backend(backend_id) if backend_id else self.get_default_backend()
        if not backend:
            raise Exception("No storage backend available")
        
        return await backend.store_backup(source_path, backup_id)
    
    async def retrieve_backup(self, backup_id: str, destination_path: str, backend_id: str = None) -> bool:
        """Retrieve a backup using specified or default backend"""
        backend = self.get_backend(backend_id) if backend_id else self.get_default_backend()
        if not backend:
            raise Exception("No storage backend available")
        
        return await backend.retrieve_backup(backup_id, destination_path)
    
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
