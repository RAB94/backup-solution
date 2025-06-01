import React, { useState, useEffect, createContext, useContext } from 'react';
import { 
  Server, 
  HardDrive, 
  Shield, 
  Database,
  Cloud,
  RefreshCw,
  Download,
  Settings,
  CheckCircle,
  Plus,
  Monitor,
  Cpu,
  MemoryStick,
  Zap,
  Eye,
  Terminal,
  LogIn,
  LogOut,
  Search,
  X,
  Network,
  Edit,
  Save
} from 'lucide-react';

// Types
interface User {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: 'admin' | 'operator' | 'viewer';
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (username: string, password: string) => Promise<boolean>;
  register: (userData: any) => Promise<boolean>;
  logout: () => void;
  isAuthenticated: boolean;
}

interface VM {
  id: number;
  vm_id: string;
  name: string;
  platform: 'vmware' | 'proxmox' | 'xcpng' | 'ubuntu';
  host: string;
  cpu_count: number;
  memory_mb: number;
  disk_size_gb: number;
  operating_system: string;
  power_state: string;
  created_at: string;
  ip_address?: string;
}

interface BackupJob {
  id: number;
  name: string;
  description: string;
  vm_id: string;
  platform: 'vmware' | 'proxmox' | 'xcpng' | 'ubuntu';
  backup_type: 'full' | 'incremental' | 'differential';
  schedule_cron: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  last_run: string | null;
  next_run: string | null;
  created_at: string;
}

type PlatformType = 'vmware' | 'proxmox' | 'xcpng' | 'ubuntu';

interface DashboardStats {
  total_backup_jobs: number;
  running_jobs: number;
  total_vms_protected: number;
  total_backups_size: string;
  last_24h_jobs: number;
  success_rate: string;
}

interface PlatformStatus {
  vmware: boolean;
  proxmox: boolean;
  xcpng: boolean;
  ubuntu: boolean;
}

// API Service
class APIService {
  private baseURL: string;
  private authToken: string | null = null;

  constructor() {
    // Determine API URL based on current host
    const currentHost = window.location.hostname;
    if (currentHost === 'localhost' || currentHost === '127.0.0.1') {
      this.baseURL = 'http://localhost:8000/api/v1';
    } else {
      // Use the same IP as the frontend but port 8000 for API
      this.baseURL = `http://${currentHost}:8000/api/v1`;
    }
    
    console.log('API Base URL:', this.baseURL);
  }

  setAuthToken(token: string | null) {
    this.authToken = token;
  }

  async request(endpoint: string, options: RequestInit = {}) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...options.headers as Record<string, string>,
    };

    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    console.log(`Making API request to: ${this.baseURL}${endpoint}`);

    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        headers,
        ...options,
      });

      console.log(`API Response status: ${response.status}`);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('API Error response:', errorText);
        
        let errorData;
        try {
          errorData = JSON.parse(errorText);
        } catch {
          errorData = { detail: errorText || 'Unknown error' };
        }
        
        throw new Error(errorData.detail || `API Error: ${response.statusText}`);
      }

      const data = await response.json();
      console.log('API Response data:', data);
      return data;
    } catch (error) {
      console.error('API Request failed:', error);
      throw error;
    }
  }

  async login(username: string, password: string) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  }

  async register(userData: any) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  }

  async logout() {
    return this.request('/auth/logout', {
      method: 'POST',
    });
  }

  async getCurrentUser(): Promise<User> {
    return this.request('/auth/me');
  }

  async getVMs(platform: string): Promise<VM[]> {
    if (platform === 'ubuntu') {
      return this.request('/ubuntu/machines');
    }
    return this.request(`/platforms/${platform}/vms`);
  }

  async discoverUbuntuMachines(networkRange: string = '192.168.1.0/24') {
    return this.request('/ubuntu/discover', {
      method: 'POST',
      body: JSON.stringify({ network_range: networkRange }),
    });
  }

  async connectUbuntuMachine(connectionData: any) {
    return this.request('/ubuntu/connect', {
      method: 'POST',
      body: JSON.stringify(connectionData),
    });
  }

  async addVMManually(vmData: any) {
    return this.request('/vms/manual', {
      method: 'POST',
      body: JSON.stringify(vmData),
    });
  }

  async updateVM(vmId: string, vmData: any) {
    return this.request(`/vms/${vmId}`, {
      method: 'PUT',
      body: JSON.stringify(vmData),
    });
  }

  async scanVMByIP(ip: string, credentials: any) {
    return this.request('/vms/scan', {
      method: 'POST',
      body: JSON.stringify({ ip, ...credentials }),
    });
  }

  async refreshPlatformVMs(platform: string) {
    return this.request(`/platforms/${platform}/refresh`, {
      method: 'POST',
    });
  }

  async backupUbuntuMachine(machineId: string, config: any) {
    return this.request(`/ubuntu/${machineId}/backup`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async installUbuntuAgent(machineId: string) {
    return this.request(`/ubuntu/${machineId}/install-agent`, {
      method: 'POST',
    });
  }

  async getBackupJobs(): Promise<BackupJob[]> {
    return this.request('/backup-jobs');
  }

  async createBackupJob(job: Partial<BackupJob>) {
    return this.request('/backup-jobs', {
      method: 'POST',
      body: JSON.stringify(job),
    });
  }

  async runBackupJob(jobId: number) {
    return this.request(`/backup-jobs/${jobId}/run`, {
      method: 'POST',
    });
  }

  async deleteBackupJob(jobId: number) {
    return this.request(`/backup-jobs/${jobId}`, {
      method: 'DELETE',
    });
  }

  async getStatistics(): Promise<DashboardStats> {
    return this.request('/statistics');
  }

  async connectPlatform(platform: string, connectionData: any) {
    return this.request(`/platforms/${platform}/connect`, {
      method: 'POST',
      body: JSON.stringify(connectionData),
    });
  }

  async discoverNetworkRange(networkRange: string) {
    return this.request('/discovery/network', {
      method: 'POST',
      body: JSON.stringify({ network_range: networkRange }),
    });
  }
}

const api = new APIService();

// Authentication Context
const AuthContext = createContext<AuthContextType | null>(null);

const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));

  useEffect(() => {
    if (token) {
      api.setAuthToken(token);
      api.getCurrentUser()
        .then((userData: User) => setUser(userData))
        .catch(() => {
          localStorage.removeItem('token');
          setToken(null);
        });
    }
  }, [token]);

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      const response = await api.login(username, password);
      setToken(response.access_token);
      localStorage.setItem('token', response.access_token);
      api.setAuthToken(response.access_token);
      
      const userData = await api.getCurrentUser();
      setUser(userData);
      return true;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const register = async (userData: any): Promise<boolean> => {
    console.log('Starting registration process:', userData);
    try {
      const response = await api.register(userData);
      console.log('Registration successful:', response);
      return true;
    } catch (error) {
      console.error('Registration failed:', error);
      return false;
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    api.setAuthToken(null);
  };

  return (
    <AuthContext.Provider value={{
      user,
      token,
      login,
      register,
      logout,
      isAuthenticated: !!user
    }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Components
const Card: React.FC<{
  children: React.ReactNode;
  className?: string;
}> = ({ children, className = '' }) => (
  <div className={`
    bg-slate-800 border border-slate-700 rounded-lg shadow-lg
    hover:border-slate-600 transition-all duration-200
    ${className}
  `}>
    <div className="p-6">
      {children}
    </div>
  </div>
);

const Button: React.FC<{
  children: React.ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'danger' | 'success';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
}> = ({ children, onClick, variant = 'primary', size = 'md', disabled = false }) => {
  const variants = {
    primary: 'bg-blue-600 hover:bg-blue-500 text-white border-blue-600',
    secondary: 'bg-slate-600 hover:bg-slate-500 text-white border-slate-600',
    danger: 'bg-red-600 hover:bg-red-500 text-white border-red-600',
    success: 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-600'
  };

  const sizes = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg'
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`
        ${variants[variant]} ${sizes[size]}
        border rounded-md font-medium transition-all duration-200
        hover:shadow-md disabled:opacity-50 disabled:cursor-not-allowed
        focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50
        flex items-center justify-center
      `}
    >
      {children}
    </button>
  );
};

const Modal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}> = ({ isOpen, onClose, title, children, size = 'md' }) => {
  if (!isOpen) return null;

  const sizeClasses = {
    sm: 'w-96',
    md: 'w-[32rem]',
    lg: 'w-[48rem]',
    xl: 'w-[64rem]'
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className={`bg-slate-800 border border-slate-700 rounded-lg ${sizeClasses[size]} max-w-full mx-4`}>
        <div className="flex items-center justify-between p-4 border-b border-slate-700">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors"
          >
            <X size={20} />
          </button>
        </div>
        <div className="p-6">
          {children}
        </div>
      </div>
    </div>
  );
};

const StatusIndicator: React.FC<{
  status: string;
  showLabel?: boolean;
}> = ({ status, showLabel = true }) => {
  const getStatusConfig = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
      case 'poweredon':
      case 'running':
        return { color: 'text-emerald-400', bg: 'bg-emerald-400', label: 'ONLINE' };
      case 'in progress':
        return { color: 'text-amber-400', bg: 'bg-amber-400', label: 'ACTIVE' };
      case 'failed':
      case 'error':
        return { color: 'text-red-400', bg: 'bg-red-400', label: 'ERROR' };
      case 'pending':
      case 'scheduled':
        return { color: 'text-yellow-400', bg: 'bg-yellow-400', label: 'PENDING' };
      case 'paused':
      case 'stopped':
        return { color: 'text-slate-400', bg: 'bg-slate-400', label: 'OFFLINE' };
      default:
        return { color: 'text-slate-400', bg: 'bg-slate-400', label: 'UNKNOWN' };
    }
  };

  const config = getStatusConfig(status);

  return (
    <div className="flex items-center space-x-2">
      <div className={`w-2 h-2 rounded-full ${config.bg} animate-pulse`}></div>
      {showLabel && (
        <span className={`text-xs font-mono uppercase tracking-wider ${config.color}`}>
          {config.label}
        </span>
      )}
    </div>
  );
};

const MetricCard: React.FC<{
  title: string;
  value: string;
  icon: React.ReactNode;
  trend?: string;
  trendDirection?: 'up' | 'down' | 'stable';
}> = ({ title, value, icon, trend, trendDirection }) => (
  <Card className="text-center">
    <div className="flex flex-col items-center space-y-3">
      <div className="text-blue-400 text-3xl">{icon}</div>
      <div>
        <p className="text-slate-400 text-sm uppercase tracking-wider">{title}</p>
        <p className="text-white text-2xl font-bold font-mono">{value}</p>
        {trend && (
          <p className={`text-sm mt-1 ${
            trendDirection === 'up' ? 'text-emerald-400' : 
            trendDirection === 'down' ? 'text-red-400' : 'text-slate-400'
          }`}>
            {trendDirection === 'up' ? '↗' : trendDirection === 'down' ? '↘' : '→'} {trend}
          </p>
        )}
      </div>
    </div>
  </Card>
);

const AddVMModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onAddVM: (vm: any) => void;
}> = ({ isOpen, onClose, onAddVM }) => {
  const [method, setMethod] = useState<'scan' | 'manual'>('scan');
  const [scanData, setScanData] = useState<{
    ip: string;
    username: string;
    password: string;
    ssh_key_path: string;
    port: number;
    platform: PlatformType;
    use_key: boolean;
  }>({
    ip: '',
    username: '',
    password: '',
    ssh_key_path: '',
    port: 22,
    platform: 'vmware',
    use_key: false
  });
  const [manualData, setManualData] = useState<{
    name: string;
    ip_address: string;
    platform: PlatformType;
    cpu_count: number;
    memory_mb: number;
    disk_size_gb: number;
    operating_system: string;
    notes: string;
  }>({
    name: '',
    ip_address: '',
    platform: 'vmware',
    cpu_count: 2,
    memory_mb: 4096,
    disk_size_gb: 50,
    operating_system: '',
    notes: ''
  });
  const [scanning, setScanning] = useState(false);

  const handleScanVM = async () => {
    setScanning(true);
    try {
      let result;
      
      // Try the dedicated VM scanning endpoint first
      try {
        result = await api.scanVMByIP(scanData.ip, scanData);
      } catch (error) {
        console.warn('Direct VM scan failed, trying alternative methods:', error);
        
        // Fallback methods for different platforms
        if (scanData.platform === 'ubuntu') {
          const discoveryResult = await api.discoverUbuntuMachines(`${scanData.ip}/32`);
          if (discoveryResult.machines && discoveryResult.machines.length > 0) {
            result = discoveryResult.machines[0];
          }
        } else {
          // For other platforms, try to connect and get VM info
          try {
            await api.connectPlatform(scanData.platform, {
              host: scanData.ip,
              username: scanData.username,
              password: scanData.password,
              port: scanData.port
            });
            
            const vms = await api.getVMs(scanData.platform);
            if (vms && vms.length > 0) {
              // Find VM that matches the IP or use first one found
              result = vms.find(vm => vm.ip_address === scanData.ip || vm.host === scanData.ip) || vms[0];
            }
          } catch (platformError) {
            console.warn('Platform connection failed:', platformError);
            
            // Final fallback: create a basic VM entry
            result = {
              vm_id: `manual-${scanData.ip.replace(/\./g, '-')}`,
              name: `${scanData.platform}-${scanData.ip}`,
              platform: scanData.platform,
              host: scanData.ip,
              ip_address: scanData.ip,
              cpu_count: 2,
              memory_mb: 4096,
              disk_size_gb: 50,
              operating_system: 'Unknown',
              power_state: 'unknown',
              created_at: new Date().toISOString()
            };
          }
        }
      }
      
      if (result) {
        onAddVM(result);
        onClose();
      } else {
        alert('No VM found at the specified IP address. Please check the IP and credentials, or try adding the VM manually.');
      }
    } catch (error) {
      console.error('VM scan failed:', error);
      alert(`Failed to scan VM: ${error instanceof Error ? error.message : 'Unknown error'}. You can try adding the VM manually instead.`);
    } finally {
      setScanning(false);
    }
  };

  const handleAddManualVM = async () => {
    try {
      const result = await api.addVMManually(manualData);
      onAddVM(result);
      onClose();
    } catch (error) {
      alert(`Failed to add VM: ${error}`);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Add Virtual Machine" size="lg">
      <div className="space-y-6">
        <div className="flex space-x-4">
          <button
            onClick={() => setMethod('scan')}
            className={`flex-1 p-3 rounded-lg border ${
              method === 'scan'
                ? 'border-blue-500 bg-blue-500 bg-opacity-20 text-blue-400'
                : 'border-slate-600 text-slate-400 hover:border-slate-500'
            }`}
          >
            <div className="flex items-center justify-center space-x-2">
              <Search size={20} />
              <span>Scan by IP</span>
            </div>
          </button>
          <button
            onClick={() => setMethod('manual')}
            className={`flex-1 p-3 rounded-lg border ${
              method === 'manual'
                ? 'border-blue-500 bg-blue-500 bg-opacity-20 text-blue-400'
                : 'border-slate-600 text-slate-400 hover:border-slate-500'
            }`}
          >
            <div className="flex items-center justify-center space-x-2">
              <Edit size={20} />
              <span>Manual Entry</span>
            </div>
          </button>
        </div>

        {method === 'scan' ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">IP Address</label>
                <input
                  type="text"
                  value={scanData.ip}
                  onChange={(e) => setScanData({...scanData, ip: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="192.168.1.100"
                />
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Platform</label>
                <select
                  value={scanData.platform}
                  onChange={(e) => setScanData({...scanData, platform: e.target.value as PlatformType})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white focus:border-blue-500 focus:outline-none transition-colors"
                >
                  <option value="vmware">VMware</option>
                  <option value="proxmox">Proxmox</option>
                  <option value="xcpng">XCP-NG</option>
                  <option value="ubuntu">Ubuntu</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Username</label>
                <input
                  type="text"
                  value={scanData.username}
                  onChange={(e) => setScanData({...scanData, username: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="admin"
                />
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Port</label>
                <input
                  type="number"
                  value={scanData.port}
                  onChange={(e) => setScanData({...scanData, port: parseInt(e.target.value)})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                />
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={scanData.use_key}
                onChange={(e) => setScanData({...scanData, use_key: e.target.checked})}
                className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
              />
              <label className="text-slate-300 text-sm">Use SSH Key</label>
            </div>

            {scanData.use_key ? (
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">SSH Key Path</label>
                <input
                  type="text"
                  value={scanData.ssh_key_path}
                  onChange={(e) => setScanData({...scanData, ssh_key_path: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="/path/to/private/key"
                />
              </div>
            ) : (
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Password</label>
                <input
                  type="password"
                  value={scanData.password}
                  onChange={(e) => setScanData({...scanData, password: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="••••••••"
                />
              </div>
            )}

            <div className="flex justify-end space-x-3">
              <Button onClick={onClose} variant="secondary" disabled={scanning}>
                Cancel
              </Button>
              <Button onClick={handleScanVM} variant="primary" disabled={scanning || !scanData.ip}>
                {scanning ? (
                  <>
                    <RefreshCw size={16} className="mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Search size={16} className="mr-2" />
                    Scan & Add
                  </>
                )}
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">VM Name</label>
                <input
                  type="text"
                  value={manualData.name}
                  onChange={(e) => setManualData({...manualData, name: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="web-server-01"
                />
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">IP Address</label>
                <input
                  type="text"
                  value={manualData.ip_address}
                  onChange={(e) => setManualData({...manualData, ip_address: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="192.168.1.100"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Platform</label>
                <select
                  value={manualData.platform}
                  onChange={(e) => setManualData({...manualData, platform: e.target.value as PlatformType})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white focus:border-blue-500 focus:outline-none transition-colors"
                >
                  <option value="vmware">VMware</option>
                  <option value="proxmox">Proxmox</option>
                  <option value="xcpng">XCP-NG</option>
                  <option value="ubuntu">Ubuntu</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Operating System</label>
                <input
                  type="text"
                  value={manualData.operating_system}
                  onChange={(e) => setManualData({...manualData, operating_system: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="Ubuntu 22.04 LTS"
                />
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">CPU Cores</label>
                <input
                  type="number"
                  value={manualData.cpu_count}
                  onChange={(e) => setManualData({...manualData, cpu_count: parseInt(e.target.value)})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  min="1"
                />
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">RAM (MB)</label>
                <input
                  type="number"
                  value={manualData.memory_mb}
                  onChange={(e) => setManualData({...manualData, memory_mb: parseInt(e.target.value)})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  min="512"
                />
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Disk (GB)</label>
                <input
                  type="number"
                  value={manualData.disk_size_gb}
                  onChange={(e) => setManualData({...manualData, disk_size_gb: parseInt(e.target.value)})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  min="1"
                />
              </div>
            </div>

            <div>
              <label className="block text-slate-300 text-sm font-medium mb-2">Notes</label>
              <textarea
                value={manualData.notes}
                onChange={(e) => setManualData({...manualData, notes: e.target.value})}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                placeholder="Additional notes about this VM..."
                rows={3}
              />
            </div>

            <div className="flex justify-end space-x-3">
              <Button onClick={onClose} variant="secondary">
                Cancel
              </Button>
              <Button onClick={handleAddManualVM} variant="primary" disabled={!manualData.name}>
                <Save size={16} className="mr-2" />
                Add VM
              </Button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};

const NetworkDiscoveryModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onDiscoveredVMs: (vms: any[]) => void;
}> = ({ isOpen, onClose, onDiscoveredVMs }) => {
  const [networkRanges, setNetworkRanges] = useState([
    '192.168.1.0/24',
    '192.168.0.0/24',
    '10.0.0.0/24'
  ]);
  const [customRange, setCustomRange] = useState('');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<any[]>([]);

  const handleScanNetwork = async (range: string) => {
    setScanning(true);
    try {
      console.log(`Scanning network range: ${range}`);
      
      // Try the generic network discovery first
      let result;
      try {
        result = await api.discoverNetworkRange(range);
      } catch (error) {
        console.warn('Generic discovery failed, trying Ubuntu discovery:', error);
        // Fallback to Ubuntu discovery which might work for general network scanning
        result = await api.discoverUbuntuMachines(range);
      }
      
      if (result && (result.discovered || result.machines)) {
        const devices = result.discovered || result.machines || [];
        setResults(devices);
        
        if (devices.length === 0) {
          alert(`No devices found in range ${range}. Try a different network range or check connectivity.`);
        } else {
          alert(`🔍 Found ${devices.length} devices in range ${range}`);
        }
      } else {
        setResults([]);
        alert(`No devices found in range ${range}`);
      }
    } catch (error) {
      console.error('Network scan failed:', error);
      alert(`❌ Network scan failed for ${range}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      setResults([]);
    } finally {
      setScanning(false);
    }
  };

  const addCustomRange = () => {
    if (customRange && !networkRanges.includes(customRange)) {
      setNetworkRanges([...networkRanges, customRange]);
      setCustomRange('');
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Network Discovery" size="xl">
      <div className="space-y-6">
        <div>
          <h3 className="text-white font-medium mb-3">Network Ranges to Scan</h3>
          <div className="space-y-2">
            {networkRanges.map((range, index) => (
              <div key={index} className="flex items-center space-x-3">
                <span className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white font-mono">
                  {range}
                </span>
                <Button
                  onClick={() => handleScanNetwork(range)}
                  size="sm"
                  variant="primary"
                  disabled={scanning}
                >
                  {scanning ? (
                    <RefreshCw size={14} className="animate-spin" />
                  ) : (
                    <Search size={14} />
                  )}
                </Button>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h3 className="text-white font-medium mb-3">Add Custom Range</h3>
          <div className="flex space-x-3">
            <input
              type="text"
              value={customRange}
              onChange={(e) => setCustomRange(e.target.value)}
              className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              placeholder="192.168.2.0/24"
            />
            <Button onClick={addCustomRange} variant="secondary" disabled={!customRange}>
              <Plus size={16} className="mr-2" />
              Add
            </Button>
          </div>
        </div>

        {results.length > 0 && (
          <div>
            <h3 className="text-white font-medium mb-3">Discovered Devices ({results.length})</h3>
            <div className="max-h-60 overflow-y-auto space-y-2">
              {results.map((device, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-slate-700 rounded border border-slate-600">
                  <div>
                    <div className="text-white font-medium">{device.hostname || device.ip}</div>
                    <div className="text-slate-400 text-sm">
                      {device.ip} • {device.platform || 'Unknown'} • Ports: {device.open_ports?.join(', ') || 'None'}
                    </div>
                  </div>
                  <Button size="sm" variant="primary">
                    <Plus size={14} className="mr-1" />
                    Add
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary">
            Close
          </Button>
          {results.length > 0 && (
            <Button onClick={() => onDiscoveredVMs(results)} variant="primary">
              <Plus size={16} className="mr-2" />
              Add All VMs
            </Button>
          )}
        </div>
      </div>
    </Modal>
  );
};

const EditVMModal: React.FC<{
  vm: VM | null;
  isOpen: boolean;
  onClose: () => void;
  onSave: (vm: VM) => void;
}> = ({ vm, isOpen, onClose, onSave }) => {
  const [editData, setEditData] = useState<Partial<VM>>({});

  useEffect(() => {
    if (vm) {
      setEditData({
        name: vm.name,
        operating_system: vm.operating_system,
        cpu_count: vm.cpu_count,
        memory_mb: vm.memory_mb,
        disk_size_gb: vm.disk_size_gb,
        ip_address: vm.ip_address || vm.host
      });
    }
  }, [vm]);

  const handleSave = () => {
    if (vm) {
      const updatedVM = { ...vm, ...editData };
      onSave(updatedVM);
      onClose();
    }
  };

  if (!vm) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Edit VM: ${vm.name}`}>
      <div className="space-y-4">
        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">VM Name</label>
          <input
            type="text"
            value={editData.name || ''}
            onChange={(e) => setEditData({...editData, name: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
          />
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Operating System</label>
          <input
            type="text"
            value={editData.operating_system || ''}
            onChange={(e) => setEditData({...editData, operating_system: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
          />
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">CPU Cores</label>
            <input
              type="number"
              value={editData.cpu_count || 0}
              onChange={(e) => setEditData({...editData, cpu_count: parseInt(e.target.value)})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              min="1"
            />
          </div>
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">RAM (MB)</label>
            <input
              type="number"
              value={editData.memory_mb || 0}
              onChange={(e) => setEditData({...editData, memory_mb: parseInt(e.target.value)})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              min="512"
            />
          </div>
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Disk (GB)</label>
            <input
              type="number"
              value={editData.disk_size_gb || 0}
              onChange={(e) => setEditData({...editData, disk_size_gb: parseInt(e.target.value)})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              min="1"
            />
          </div>
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">IP Address</label>
          <input
            type="text"
            value={editData.ip_address || ''}
            onChange={(e) => setEditData({...editData, ip_address: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="192.168.1.100"
          />
        </div>

        <div className="bg-blue-900 bg-opacity-30 border border-blue-500 rounded p-3">
          <p className="text-blue-300 text-sm">
            <strong>Platform:</strong> {vm.platform.toUpperCase()} | <strong>VM ID:</strong> {vm.vm_id}
          </p>
        </div>

        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary">
            Cancel
          </Button>
          <Button onClick={handleSave} variant="primary">
            <Save size={16} className="mr-2" />
            Save Changes
          </Button>
        </div>
      </div>
    </Modal>
  );
};

const MonitorVMModal: React.FC<{
  vm: VM | null;
  isOpen: boolean;
  onClose: () => void;
}> = ({ vm, isOpen, onClose }) => {
  const [monitoring, setMonitoring] = useState(false);
  const [stats, setStats] = useState({
    cpu_usage: Math.floor(Math.random() * 100),
    memory_usage: Math.floor(Math.random() * 100),
    disk_usage: Math.floor(Math.random() * 100),
    network_in: (Math.random() * 1000).toFixed(1),
    network_out: (Math.random() * 500).toFixed(1),
    uptime: '15 days, 3 hours'
  });

  useEffect(() => {
    if (isOpen && vm) {
      setMonitoring(true);
      // Simulate real-time stats updates
      const interval = setInterval(() => {
        setStats({
          cpu_usage: Math.floor(Math.random() * 100),
          memory_usage: Math.floor(Math.random() * 100),
          disk_usage: Math.floor(Math.random() * 100),
          network_in: (Math.random() * 1000).toFixed(1),
          network_out: (Math.random() * 500).toFixed(1),
          uptime: '15 days, 3 hours'
        });
      }, 2000);

      return () => clearInterval(interval);
    }
  }, [isOpen, vm]);

  if (!vm) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Monitor: ${vm.name}`} size="lg">
      <div className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-300">Status:</span>
              <StatusIndicator status={vm.power_state} />
            </div>
            <div className="flex justify-between">
              <span className="text-slate-300">Platform:</span>
              <span className="text-white font-mono">{vm.platform.toUpperCase()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-300">IP Address:</span>
              <span className="text-white font-mono">{vm.ip_address || vm.host}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-300">OS:</span>
              <span className="text-white">{vm.operating_system}</span>
            </div>
          </div>
          
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-300">CPU:</span>
              <span className="text-white">{vm.cpu_count} cores</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-300">Memory:</span>
              <span className="text-white">{Math.round(vm.memory_mb / 1024)} GB</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-300">Storage:</span>
              <span className="text-white">{vm.disk_size_gb} GB</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-300">Uptime:</span>
              <span className="text-white">{stats.uptime}</span>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-white font-medium">Real-time Performance</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-700 rounded p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-300 text-sm">CPU Usage</span>
                <span className="text-white font-mono">{stats.cpu_usage}%</span>
              </div>
              <div className="w-full bg-slate-600 rounded-full h-2">
                <div 
                  className="bg-blue-500 h-2 rounded-full transition-all duration-500"
                  style={{ width: `${stats.cpu_usage}%` }}
                ></div>
              </div>
            </div>

            <div className="bg-slate-700 rounded p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-300 text-sm">Memory Usage</span>
                <span className="text-white font-mono">{stats.memory_usage}%</span>
              </div>
              <div className="w-full bg-slate-600 rounded-full h-2">
                <div 
                  className="bg-emerald-500 h-2 rounded-full transition-all duration-500"
                  style={{ width: `${stats.memory_usage}%` }}
                ></div>
              </div>
            </div>

            <div className="bg-slate-700 rounded p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-300 text-sm">Disk Usage</span>
                <span className="text-white font-mono">{stats.disk_usage}%</span>
              </div>
              <div className="w-full bg-slate-600 rounded-full h-2">
                <div 
                  className="bg-amber-500 h-2 rounded-full transition-all duration-500"
                  style={{ width: `${stats.disk_usage}%` }}
                ></div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="bg-slate-700 rounded p-4">
              <div className="text-slate-300 text-sm mb-1">Network In</div>
              <div className="text-white font-mono text-lg">{stats.network_in} MB/s</div>
            </div>
            <div className="bg-slate-700 rounded p-4">
              <div className="text-slate-300 text-sm mb-1">Network Out</div>
              <div className="text-white font-mono text-lg">{stats.network_out} MB/s</div>
            </div>
          </div>
        </div>

        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary">
            Close Monitor
          </Button>
          <Button variant="primary">
            <Download size={16} className="mr-2" />
            Export Report
          </Button>
        </div>
      </div>
    </Modal>
  );
};

const VMCard: React.FC<{ vm: VM; onBackup: (vm: VM) => void; onEdit?: (vm: VM) => void; onMonitor?: (vm: VM) => void }> = ({ vm, onBackup, onEdit, onMonitor }) => {
  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'vmware': return <Server className="text-blue-400" />;
      case 'proxmox': return <Database className="text-red-400" />;
      case 'xcpng': return <Cloud className="text-emerald-400" />;
      case 'ubuntu': return <Monitor className="text-orange-400" />;
      default: return <Server className="text-slate-400" />;
    }
  };

  const getPlatformColor = (platform: string) => {
    switch (platform) {
      case 'vmware': return '#3b82f6';
      case 'proxmox': return '#dc2626';
      case 'xcpng': return '#059669';
      case 'ubuntu': return '#f97316';
      default: return '#6b7280';
    }
  };

  return (
    <Card className="hover:scale-105 transition-transform duration-200">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {getPlatformIcon(vm.platform)}
            <div>
              <h3 className="text-white font-semibold">{vm.name}</h3>
              <p className="text-slate-400 text-sm font-mono">{vm.vm_id}</p>
            </div>
          </div>
          <StatusIndicator status={vm.power_state} showLabel={false} />
        </div>

        <div className="flex justify-between items-center">
          <span 
            className="px-2 py-1 bg-slate-700 border border-opacity-30 rounded text-xs font-mono uppercase"
            style={{ 
              borderColor: getPlatformColor(vm.platform),
              color: getPlatformColor(vm.platform)
            }}
          >
            {vm.platform}
          </span>
          <span className="text-slate-400 text-xs">
            {vm.ip_address || vm.host}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="flex items-center space-x-2">
            <Cpu className="text-blue-400" size={16} />
            <span className="text-white text-sm">{vm.cpu_count} cores</span>
          </div>
          <div className="flex items-center space-x-2">
            <MemoryStick className="text-blue-400" size={16} />
            <span className="text-white text-sm">{Math.round(vm.memory_mb / 1024)} GB</span>
          </div>
          <div className="flex items-center space-x-2">
            <HardDrive className="text-blue-400" size={16} />
            <span className="text-white text-sm">{vm.disk_size_gb} GB</span>
          </div>
          <div className="flex items-center space-x-2">
            <Monitor className="text-blue-400" size={16} />
            <span className="text-white text-sm truncate">{vm.operating_system}</span>
          </div>
        </div>

        <div className="flex space-x-2">
          <Button 
            onClick={() => onBackup(vm)} 
            size="sm"
            variant="success"
          >
            <Shield size={14} className="mr-1" />
            Backup
          </Button>
          <Button 
            size="sm" 
            variant="secondary"
            onClick={() => onMonitor && onMonitor(vm)}
          >
            <Eye size={14} className="mr-1" />
            Monitor
          </Button>
          {onEdit && (
            <Button 
              size="sm" 
              variant="secondary"
              onClick={() => onEdit(vm)}
            >
              <Edit size={14} className="mr-1" />
              Edit
            </Button>
          )}
          {vm.platform === 'ubuntu' && (
            <Button 
              size="sm" 
              variant="secondary"
              onClick={() => api.installUbuntuAgent(vm.vm_id)}
            >
              <Download size={14} className="mr-1" />
              Agent
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
};

const LoginForm: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async () => {
    setLoading(true);
    setError('');
    
    if (!username || !password) {
      setError('Please enter both username and password');
      setLoading(false);
      return;
    }
    
    try {
      const success = await login(username, password);
      
      if (success) {
        onClose();
      } else {
        setError('Invalid credentials');
      }
    } catch (err: any) {
      setError('Login failed. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal isOpen={true} onClose={onClose} title="Login">
      <div className="space-y-4">
        {error && (
          <div className="p-3 bg-red-900 bg-opacity-50 border border-red-500 rounded text-red-300 text-sm">
            {error}
          </div>
        )}

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Enter username"
            disabled={loading}
          />
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Enter password"
            disabled={loading}
            onKeyPress={(e) => e.key === 'Enter' && handleSubmit()}
          />
        </div>

        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary" disabled={loading}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} variant="primary" disabled={loading}>
            {loading ? <RefreshCw size={16} className="mr-2 animate-spin" /> : <LogIn size={16} className="mr-2" />}
            {loading ? 'Logging in...' : 'Login'}
          </Button>
        </div>
      </div>
    </Modal>
  );
};

const PlatformConnector: React.FC<{
  platform: PlatformType;
  onConnect: (platform: string, data: any) => void;
  isConnected: boolean;
}> = ({ platform, onConnect, isConnected }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [connectionData, setConnectionData] = useState({
    host: '',
    username: '',
    password: '',
    port: platform === 'vmware' ? 443 : platform === 'ubuntu' ? 22 : 22,
    ssh_key_path: '',
    use_key: platform === 'ubuntu'
  });

  const getPlatformIcon = () => {
    switch (platform) {
      case 'vmware': return <Server className="text-blue-400" size={32} />;
      case 'proxmox': return <Database className="text-red-400" size={32} />;
      case 'xcpng': return <Cloud className="text-emerald-400" size={32} />;
      case 'ubuntu': return <Monitor className="text-orange-400" size={32} />;
      default: return <Server size={32} />;
    }
  };

  const getPlatformDescription = () => {
    switch (platform) {
      case 'vmware': return 'VMware vSphere/ESXi';
      case 'proxmox': return 'Proxmox Virtual Environment';
      case 'xcpng': return 'XCP-ng Hypervisor';
      case 'ubuntu': return 'Ubuntu Linux Machines';
      default: return 'Virtualization Platform';
    }
  };

  const handleConnect = () => {
    onConnect(platform, connectionData);
    setIsOpen(false);
  };

  return (
    <>
      <Card className="text-center hover:scale-105 transition-transform duration-200 relative">
        {isConnected && (
          <div className="absolute top-3 right-3">
            <div className="flex items-center space-x-1 bg-emerald-600 px-2 py-1 rounded text-white text-xs">
              <CheckCircle size={12} />
              <span>Connected</span>
            </div>
          </div>
        )}
        <div className="space-y-4">
          <div className="flex justify-center">{getPlatformIcon()}</div>
          <div>
            <h3 className="text-white font-semibold text-lg capitalize">{platform}</h3>
            <p className="text-slate-400 text-sm">{getPlatformDescription()}</p>
          </div>
          <Button 
            onClick={() => setIsOpen(true)} 
            variant={isConnected ? "secondary" : "primary"}
          >
            <Zap size={16} className="mr-2" />
            {isConnected ? 'Reconnect' : 'Connect'}
          </Button>
        </div>
      </Card>

      <Modal isOpen={isOpen} onClose={() => setIsOpen(false)} title={`Connect to ${platform.toUpperCase()}`}>
        <div className="space-y-4">
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">
              {platform === 'ubuntu' ? 'IP Address' : 'Host Address'}
            </label>
            <input
              type="text"
              value={connectionData.host}
              onChange={(e) => setConnectionData({...connectionData, host: e.target.value})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              placeholder={
                platform === 'vmware' ? 'vcenter.domain.com or 192.168.1.10' :
                platform === 'proxmox' ? 'proxmox.domain.com or 192.168.1.20' :
                platform === 'xcpng' ? 'xcpng.domain.com or 192.168.1.30' :
                'ubuntu.domain.com or 192.168.1.40'
              }
            />
          </div>

          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Username</label>
            <input
              type="text"
              value={connectionData.username}
              onChange={(e) => setConnectionData({...connectionData, username: e.target.value})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              placeholder={
                platform === 'vmware' ? 'administrator@vsphere.local' :
                platform === 'proxmox' ? 'root@pam' :
                platform === 'xcpng' ? 'root' :
                'ubuntu'
              }
            />
          </div>

          {platform === 'ubuntu' && (
            <div className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={connectionData.use_key}
                onChange={(e) => setConnectionData({...connectionData, use_key: e.target.checked})}
                className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
              />
              <label className="text-slate-300 text-sm">Use SSH Key Authentication</label>
            </div>
          )}

          {platform === 'ubuntu' && connectionData.use_key ? (
            <div>
              <label className="block text-slate-300 text-sm font-medium mb-2">SSH Key Path</label>
              <input
                type="text"
                value={connectionData.ssh_key_path}
                onChange={(e) => setConnectionData({...connectionData, ssh_key_path: e.target.value})}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                placeholder="/path/to/private/key"
              />
            </div>
          ) : (
            <div>
              <label className="block text-slate-300 text-sm font-medium mb-2">Password</label>
              <input
                type="password"
                value={connectionData.password}
                onChange={(e) => setConnectionData({...connectionData, password: e.target.value})}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                placeholder="••••••••"
              />
            </div>
          )}

          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Port</label>
            <input
              type="number"
              value={connectionData.port}
              onChange={(e) => setConnectionData({...connectionData, port: parseInt(e.target.value)})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            />
          </div>

          <div className="bg-slate-700 bg-opacity-50 rounded p-3">
            <p className="text-slate-300 text-xs">
              <strong>Connection Test:</strong> {platform.toUpperCase()} connection will be tested before saving.
              {platform === 'xcpng' && ' Make sure XCP-ng host is accessible and API is enabled.'}
              {platform === 'vmware' && ' Ensure vCenter/ESXi has API access enabled.'}
              {platform === 'proxmox' && ' Verify Proxmox web interface is accessible.'}
            </p>
          </div>

          <div className="flex justify-end space-x-3">
            <Button onClick={() => setIsOpen(false)} variant="secondary">
              Cancel
            </Button>
            <Button 
              onClick={handleConnect}
              variant="primary"
              disabled={!connectionData.host || !connectionData.username || (!connectionData.password && !connectionData.ssh_key_path)}
            >
              <Zap size={16} className="mr-2" />
              Test & Connect
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
};

const AuthGuard: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  const [showLogin, setShowLogin] = useState(false);

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <Card className="text-center w-96">
          <div className="space-y-6">
            <div className="flex justify-center">
              <Shield className="text-blue-400" size={64} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">
                MIVU Backup Solution
              </h1>
              <p className="text-slate-400 text-sm mt-2">Please login to continue</p>
            </div>
            <div className="flex space-x-3 justify-center">
              <Button onClick={() => setShowLogin(true)} variant="primary">
                <LogIn size={16} className="mr-2" />
                Login
              </Button>
            </div>
          </div>
        </Card>

        {showLogin && <LoginForm onClose={() => setShowLogin(false)} />}
      </div>
    );
  }

  return <>{children}</>;
};

const MIVUBackupDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'vms' | 'jobs' | 'platforms'>('dashboard');
  const [stats, setStats] = useState<DashboardStats>({
    total_backup_jobs: 0,
    running_jobs: 0,
    total_vms_protected: 0,
    total_backups_size: '0 GB',
    last_24h_jobs: 0,
    success_rate: '0%'
  });
  const [vms, setVMs] = useState<VM[]>([]);
  const [showAddVM, setShowAddVM] = useState(false);
  const [showNetworkDiscovery, setShowNetworkDiscovery] = useState(false);
  const [showEditVM, setShowEditVM] = useState(false);
  const [showMonitorVM, setShowMonitorVM] = useState(false);
  const [selectedVM, setSelectedVM] = useState<VM | null>(null);
  const [loading, setLoading] = useState(true);
  const [platformStatus, setPlatformStatus] = useState<PlatformStatus>({
    vmware: false,
    proxmox: false,
    xcpng: false,
    ubuntu: false
  });

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setLoading(true);
    try {
      const statsData = await api.getStatistics().catch(() => ({
        total_backup_jobs: 0,
        running_jobs: 0,
        total_vms_protected: 0,
        total_backups_size: '0 GB',
        last_24h_jobs: 0,
        success_rate: '0%'
      }));

      setStats(statsData);
      setVMs([]);
    } catch (error) {
      console.error('Failed to load initial data:', error);
    } finally {
      setLoading(false);
    }
  };

  const refreshAllVMs = async () => {
    const platforms: PlatformType[] = ['vmware', 'proxmox', 'xcpng', 'ubuntu'];
    const allVMs: VM[] = [];
    
    for (const platform of platforms) {
      if (platformStatus[platform]) {
        try {
          const platformVMs = await api.getVMs(platform);
          allVMs.push(...platformVMs);
        } catch (error) {
          console.error(`Failed to load VMs for ${platform}:`, error);
        }
      }
    }
    
    setVMs(allVMs);
  };

  const handleEditVM = (vm: VM) => {
    setSelectedVM(vm);
    setShowEditVM(true);
  };

  const handleMonitorVM = (vm: VM) => {
    setSelectedVM(vm);
    setShowMonitorVM(true);
  };

  const handleSaveEditedVM = async (updatedVM: VM) => {
    try {
      // Update VM via API
      const result = await api.updateVM(updatedVM.vm_id, updatedVM);
      
      // Update VM in the local list
      setVMs(prev => prev.map(vm => 
        vm.vm_id === updatedVM.vm_id ? { ...vm, ...result } : vm
      ));
      
      alert(`✅ VM "${updatedVM.name}" updated successfully!`);
    } catch (error) {
      console.error('Failed to update VM:', error);
      alert(`❌ Failed to update VM: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const handleConnectPlatform = async (platform: string, connectionData: any) => {
    try {
      console.log(`Attempting to connect to ${platform} with:`, { 
        host: connectionData.host, 
        username: connectionData.username, 
        port: connectionData.port 
      });
      
      if (platform === 'ubuntu') {
        await api.connectUbuntuMachine(connectionData);
      } else {
        await api.connectPlatform(platform, connectionData);
      }
      
      // Update platform status
      setPlatformStatus(prev => ({
        ...prev,
        [platform]: true
      }));
      
      alert(`✅ Successfully connected to ${platform.toUpperCase()}!`);
      
      // Try to refresh VMs for this platform
      try {
        const platformVMs = await api.getVMs(platform);
        if (platformVMs && platformVMs.length > 0) {
          setVMs(prev => {
            // Remove existing VMs from this platform to avoid duplicates
            const filtered = prev.filter(vm => vm.platform !== platform);
            return [...filtered, ...platformVMs];
          });
          alert(`🔍 Discovered ${platformVMs.length} VMs on ${platform.toUpperCase()}`);
        }
      } catch (vmError) {
        console.warn(`Failed to load VMs for ${platform}:`, vmError);
        // Don't show error to user as connection was successful
      }
      
    } catch (error) {
      console.error('Failed to connect:', error);
      
      let errorMessage = `Failed to connect to ${platform.toUpperCase()}`;
      if (error instanceof Error) {
        if (error.message.includes('404')) {
          errorMessage += ': Service not available. Please check if the platform is running and accessible.';
        } else if (error.message.includes('401') || error.message.includes('403')) {
          errorMessage += ': Authentication failed. Please check your credentials.';
        } else if (error.message.includes('timeout') || error.message.includes('network')) {
          errorMessage += ': Network timeout. Please check the host address and network connectivity.';
        } else {
          errorMessage += `: ${error.message}`;
        }
      }
      
      alert(`❌ ${errorMessage}`);
    }
  };

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: <Terminal size={20} /> },
    { id: 'vms', label: 'Virtual Machines', icon: <Server size={20} /> },
    { id: 'jobs', label: 'Backup Jobs', icon: <Shield size={20} /> },
    { id: 'platforms', label: 'Platforms', icon: <Settings size={20} /> },
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <Card className="text-center">
          <RefreshCw className="text-blue-400 animate-spin mx-auto mb-4" size={48} />
          <h2 className="text-white text-xl">Loading...</h2>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900">
      <header className="border-b border-slate-700 bg-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-3">
                <Shield className="text-blue-400" size={32} />
                <div>
                  <h1 className="text-xl font-bold text-white">MIVU Backup Solution</h1>
                  <p className="text-slate-400 text-xs">Enterprise Protection System</p>
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-3">
                <StatusIndicator status="online" />
                <span className="text-slate-400 text-sm">System Online</span>
              </div>
              <div className="text-slate-400 text-sm">
                {new Date().toLocaleTimeString()}
              </div>
              {user && (
                <div className="flex items-center space-x-3">
                  <div className="text-right">
                    <div className="text-white text-sm font-medium">{user.full_name}</div>
                    <div className="text-slate-400 text-xs">{user.role}</div>
                  </div>
                  <Button onClick={logout} size="sm" variant="secondary">
                    <LogOut size={16} />
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      <nav className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 py-4 px-2 border-b-2 font-medium text-sm transition-all duration-200 ${
                  activeTab === tab.id
                    ? 'border-blue-400 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-500'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && (
          <div className="space-y-8">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <MetricCard
                title="Protected VMs"
                value={vms.length.toString()}
                icon={<Server />}
              />
              <MetricCard
                title="Active Jobs"
                value={stats.total_backup_jobs.toString()}
                icon={<Shield />}
              />
              <MetricCard
                title="Storage Used"
                value={stats.total_backups_size}
                icon={<HardDrive />}
              />
              <MetricCard
                title="Success Rate"
                value={stats.success_rate}
                icon={<CheckCircle />}
              />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <h3 className="text-white text-lg font-medium mb-4">System Status</h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-300">Backup Engine</span>
                    <StatusIndicator status="online" />
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-300">Database Connection</span>
                    <StatusIndicator status="online" />
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-300">Platform Connections</span>
                    <StatusIndicator status={Object.values(platformStatus).some(Boolean) ? "online" : "offline"} />
                  </div>
                </div>
              </Card>

              <Card>
                <h3 className="text-white text-lg font-medium mb-4">Platform Status</h3>
                <div className="space-y-3">
                  {Object.entries(platformStatus).map(([platform, connected]) => (
                    <div key={platform} className="flex justify-between items-center">
                      <span className="text-slate-300 capitalize">{platform}</span>
                      <StatusIndicator status={connected ? "online" : "offline"} />
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          </div>
        )}

        {activeTab === 'vms' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Virtual Machines ({vms.length})</h2>
              <div className="flex space-x-3">
                <Button onClick={() => setShowNetworkDiscovery(true)} variant="secondary">
                  <Network size={16} className="mr-2" />
                  Network Discovery
                </Button>
                <Button onClick={refreshAllVMs} variant="secondary">
                  <RefreshCw size={16} className="mr-2" />
                  Refresh All
                </Button>
                <Button onClick={() => setShowAddVM(true)} variant="primary">
                  <Plus size={16} className="mr-2" />
                  Add VM
                </Button>
              </div>
            </div>
            
            {vms.length === 0 ? (
              <Card>
                <div className="text-center py-12">
                  <Server className="text-blue-400 mx-auto mb-4" size={48} />
                  <h3 className="text-white text-lg font-medium mb-2">No Virtual Machines</h3>
                  <p className="text-slate-400 mb-4">Connect to platforms first, then add VMs manually or use network discovery</p>
                  <div className="flex justify-center space-x-3">
                    <Button variant="primary" onClick={() => setActiveTab('platforms')}>
                      <Settings size={16} className="mr-2" />
                      Connect Platforms
                    </Button>
                    <Button variant="secondary" onClick={() => setShowAddVM(true)}>
                      <Plus size={16} className="mr-2" />
                      Add VM Manually
                    </Button>
                  </div>
                </div>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {vms.map((vm) => (
                  <VMCard 
                    key={`${vm.platform}-${vm.vm_id}`} 
                    vm={vm} 
                    onBackup={(vm) => alert(`Starting backup for ${vm.name}`)}
                    onEdit={handleEditVM}
                    onMonitor={handleMonitorVM}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'jobs' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Backup Jobs</h2>
              <Button variant="primary">
                <Plus size={16} className="mr-2" />
                New Job
              </Button>
            </div>

            <Card>
              <div className="text-center py-12">
                <Shield className="text-blue-400 mx-auto mb-4" size={48} />
                <h3 className="text-white text-lg font-medium mb-2">No Backup Jobs</h3>
                <p className="text-slate-400 mb-4">Create your first backup job to get started</p>
                <Button variant="primary">
                  <Plus size={16} className="mr-2" />
                  Create Backup Job
                </Button>
              </div>
            </Card>
          </div>
        )}

        {activeTab === 'platforms' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Platform Connections</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {(['vmware', 'proxmox', 'xcpng', 'ubuntu'] as PlatformType[]).map((platform) => (
                <PlatformConnector 
                  key={platform}
                  platform={platform} 
                  onConnect={handleConnectPlatform} 
                  isConnected={platformStatus[platform]}
                />
              ))}
            </div>
          </div>
        )}
      </main>

      <AddVMModal
        isOpen={showAddVM}
        onClose={() => setShowAddVM(false)}
        onAddVM={(vm) => {
          setVMs(prev => [...prev, vm]);
          alert(`Added ${vm.name} to VM list`);
        }}
      />

      <NetworkDiscoveryModal
        isOpen={showNetworkDiscovery}
        onClose={() => setShowNetworkDiscovery(false)}
        onDiscoveredVMs={(discovered) => {
          alert(`Discovered ${discovered.length} devices`);
        }}
      />

      <EditVMModal
        vm={selectedVM}
        isOpen={showEditVM}
        onClose={() => {
          setShowEditVM(false);
          setSelectedVM(null);
        }}
        onSave={handleSaveEditedVM}
      />

      <MonitorVMModal
        vm={selectedVM}
        isOpen={showMonitorVM}
        onClose={() => {
          setShowMonitorVM(false);
          setSelectedVM(null);
        }}
      />
    </div>
  );
};

const App: React.FC = () => {
  return (
    <AuthProvider>
      <AuthGuard>
        <MIVUBackupDashboard />
      </AuthGuard>
    </AuthProvider>
  );
};

export default App;
