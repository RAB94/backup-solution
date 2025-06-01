// Updated App.tsx with VM subtabs, functional backup jobs, and better stats

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
  X,
  Network,
  Edit
} from 'lucide-react';

// Types (keeping existing types...)
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

// API Service (keeping existing APIService...)
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

  // Authentication methods (keeping existing...)
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

  // VM and Platform methods (keeping existing...)
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

  // UPDATED: Backup Jobs methods
  async getBackupJobs(): Promise<BackupJob[]> {
    return this.request('/backup-jobs');
  }

  async createBackupJob(job: any) {
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

  // UPDATED: Get all VMs from database instead of individual platforms
  async getAllVMs(): Promise<VM[]> {
    return this.request('/vms');
  }

  // NEW: Get platform connection status
  async getPlatformStatus() {
    return this.request('/platforms/status');
  }
}

const api = new APIService();

// Authentication Context (keeping existing...)
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

// Login Form Component
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

// NEW: Backup Job Creation Modal
const CreateBackupJobModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  vms: VM[];
  onCreateJob: (jobData: any) => void;
}> = ({ isOpen, onClose, vms, onCreateJob }) => {
  const [jobData, setJobData] = useState({
    name: '',
    description: '',
    vm_id: '',
    platform: 'vmware' as PlatformType,
    backup_type: 'incremental' as 'full' | 'incremental' | 'differential',
    schedule_cron: '0 2 * * *', // Daily at 2 AM
    retention_days: 30,
    compression_enabled: true,
    encryption_enabled: true,
    repository_id: 1 // Default repository
  });

  const [selectedVM, setSelectedVM] = useState<VM | null>(null);

  const handleVMSelect = (vmId: string) => {
    const vm = vms.find(v => v.vm_id === vmId);
    if (vm) {
      setSelectedVM(vm);
      setJobData({
        ...jobData,
        vm_id: vmId,
        platform: vm.platform,
        name: jobData.name || `Backup ${vm.name}`
      });
    }
  };

  const handleSubmit = () => {
    if (!jobData.vm_id || !jobData.name) {
      alert('Please select a VM and enter a job name');
      return;
    }

    onCreateJob(jobData);
    
    // Reset form
    setJobData({
      name: '',
      description: '',
      vm_id: '',
      platform: 'vmware',
      backup_type: 'incremental',
      schedule_cron: '0 2 * * *',
      retention_days: 30,
      compression_enabled: true,
      encryption_enabled: true,
      repository_id: 1
    });
    setSelectedVM(null);
    onClose();
  };

  const schedulePresets = [
    { label: 'Daily at 2 AM', value: '0 2 * * *' },
    { label: 'Every 6 hours', value: '0 */6 * * *' },
    { label: 'Weekly (Sunday)', value: '0 2 * * 0' },
    { label: 'Monthly (1st)', value: '0 2 1 * *' },
  ];

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Backup Job" size="lg">
      <div className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Job Name</label>
            <input
              type="text"
              value={jobData.name}
              onChange={(e) => setJobData({...jobData, name: e.target.value})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              placeholder="e.g., Daily Web Server Backup"
            />
          </div>
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Virtual Machine</label>
            <select
              value={jobData.vm_id}
              onChange={(e) => handleVMSelect(e.target.value)}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white focus:border-blue-500 focus:outline-none transition-colors"
            >
              <option value="">Select a VM...</option>
              {vms.map((vm) => (
                <option key={vm.vm_id} value={vm.vm_id}>
                  {vm.name} ({vm.platform.toUpperCase()})
                </option>
              ))}
            </select>
          </div>
        </div>

        {selectedVM && (
          <div className="bg-slate-700 rounded p-3">
            <h4 className="text-white font-medium mb-2">Selected VM Details</h4>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div className="text-slate-300">Platform: <span className="text-white">{selectedVM.platform.toUpperCase()}</span></div>
              <div className="text-slate-300">OS: <span className="text-white">{selectedVM.operating_system}</span></div>
              <div className="text-slate-300">CPU: <span className="text-white">{selectedVM.cpu_count} cores</span></div>
              <div className="text-slate-300">RAM: <span className="text-white">{Math.round(selectedVM.memory_mb / 1024)} GB</span></div>
            </div>
          </div>
        )}

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Description</label>
          <textarea
            value={jobData.description}
            onChange={(e) => setJobData({...jobData, description: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Optional description for this backup job"
            rows={2}
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Backup Type</label>
            <select
              value={jobData.backup_type}
              onChange={(e) => setJobData({...jobData, backup_type: e.target.value as any})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white focus:border-blue-500 focus:outline-none transition-colors"
            >
              <option value="incremental">Incremental</option>
              <option value="full">Full</option>
              <option value="differential">Differential</option>
            </select>
          </div>
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Retention (Days)</label>
            <input
              type="number"
              value={jobData.retention_days}
              onChange={(e) => setJobData({...jobData, retention_days: parseInt(e.target.value)})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              min="1"
              max="365"
            />
          </div>
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Schedule</label>
          <div className="space-y-2">
            <select
              value={jobData.schedule_cron}
              onChange={(e) => setJobData({...jobData, schedule_cron: e.target.value})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white focus:border-blue-500 focus:outline-none transition-colors"
            >
              {schedulePresets.map((preset) => (
                <option key={preset.value} value={preset.value}>
                  {preset.label}
                </option>
              ))}
            </select>
            <input
              type="text"
              value={jobData.schedule_cron}
              onChange={(e) => setJobData({...jobData, schedule_cron: e.target.value})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors text-sm font-mono"
              placeholder="Cron expression (e.g., 0 2 * * *)"
            />
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center space-x-3">
            <input
              type="checkbox"
              checked={jobData.compression_enabled}
              onChange={(e) => setJobData({...jobData, compression_enabled: e.target.checked})}
              className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
            />
            <label className="text-slate-300 text-sm">Enable compression</label>
          </div>
          <div className="flex items-center space-x-3">
            <input
              type="checkbox"
              checked={jobData.encryption_enabled}
              onChange={(e) => setJobData({...jobData, encryption_enabled: e.target.checked})}
              className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
            />
            <label className="text-slate-300 text-sm">Enable encryption</label>
          </div>
        </div>

        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary">
            Cancel
          </Button>
          <Button 
            onClick={handleSubmit} 
            variant="primary"
            disabled={!jobData.vm_id || !jobData.name}
          >
            <Shield size={16} className="mr-2" />
            Create Backup Job
          </Button>
        </div>
      </div>
    </Modal>
  );
};

// VM Card component (keeping existing but updated...)
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

// Platform Connector component (keeping existing...)
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
    port: platform === 'vmware' ? 443 : 
          platform === 'proxmox' ? 8006 : 
          platform === 'xcpng' ? 22 : 
          22, // ubuntu
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

// Main Dashboard Component
const MIVUBackupDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'vms' | 'jobs' | 'platforms'>('dashboard');
  const [vmSubTab, setVmSubTab] = useState<'all' | 'vmware' | 'proxmox' | 'xcpng' | 'ubuntu'>('all');
  const [stats, setStats] = useState<DashboardStats>({
    total_backup_jobs: 0,
    running_jobs: 0,
    total_vms_protected: 0,
    total_backups_size: '0 GB',
    last_24h_jobs: 0,
    success_rate: '0%'
  });
  const [vms, setVMs] = useState<VM[]>([]);
  const [backupJobs, setBackupJobs] = useState<BackupJob[]>([]);
  const [showAddVM, setShowAddVM] = useState(false);
  const [showNetworkDiscovery, setShowNetworkDiscovery] = useState(false);
  const [showEditVM, setShowEditVM] = useState(false);
  const [showMonitorVM, setShowMonitorVM] = useState(false);
  const [showCreateBackupJob, setShowCreateBackupJob] = useState(false);
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
    loadPlatformStatus();
  }, []);

  const loadInitialData = async () => {
    setLoading(true);
    try {
      // Load stats, VMs, and backup jobs
      const [statsData, allVMs, jobs] = await Promise.all([
        api.getStatistics().catch(() => ({
          total_backup_jobs: 0,
          running_jobs: 0,
          total_vms_protected: 0,
          total_backups_size: '0 GB',
          last_24h_jobs: 0,
          success_rate: '0%'
        })),
        api.getAllVMs().catch(() => []),
        api.getBackupJobs().catch(() => [])
      ]);

      setStats(statsData);
      setVMs(allVMs);
      setBackupJobs(jobs);
      
    } catch (error) {
      console.error('Failed to load initial data:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadPlatformStatus = async () => {
    try {
      const status = await api.getPlatformStatus();
      setPlatformStatus(status);
      console.log('Loaded platform status:', status);
    } catch (error) {
      console.error('Failed to load platform status:', error);
    }
  };

  const refreshAllVMs = async () => {
    try {
      const allVMs = await api.getAllVMs();
      setVMs(allVMs);
      
      // Reload platform status and stats
      await loadPlatformStatus();
      const updatedStats = await api.getStatistics();
      setStats(updatedStats);
      
    } catch (error) {
      console.error('Failed to refresh VMs:', error);
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
      
      alert(`✅ Successfully connected to ${platform.toUpperCase()}!`);
      
      // Refresh all data after successful connection
      await Promise.all([
        refreshAllVMs(),
        loadPlatformStatus()
      ]);
      
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

  const handleCreateBackupJob = async (jobData: any) => {
    try {
      await api.createBackupJob(jobData);
      
      // Refresh backup jobs list and stats
      const [jobs, updatedStats] = await Promise.all([
        api.getBackupJobs(),
        api.getStatistics()
      ]);
      
      setBackupJobs(jobs);
      setStats(updatedStats);
      
      alert(`✅ Backup job "${jobData.name}" created successfully!`);
      
    } catch (error) {
      console.error('Failed to create backup job:', error);
      alert(`❌ Failed to create backup job: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const handleRunBackupJob = async (jobId: number) => {
    try {
      await api.runBackupJob(jobId);
      
      // Refresh jobs and stats to get updated status
      const [jobs, updatedStats] = await Promise.all([
        api.getBackupJobs(),
        api.getStatistics()
      ]);
      
      setBackupJobs(jobs);
      setStats(updatedStats);
      
      alert(`✅ Backup job started successfully!`);
      
    } catch (error) {
      console.error('Failed to run backup job:', error);
      alert(`❌ Failed to start backup job: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const handleDeleteBackupJob = async (jobId: number) => {
    if (!window.confirm('Are you sure you want to delete this backup job?')) {
      return;
    }
    
    try {
      await api.deleteBackupJob(jobId);
      
      // Refresh jobs list and stats
      const [jobs, updatedStats] = await Promise.all([
        api.getBackupJobs(),
        api.getStatistics()
      ]);
      
      setBackupJobs(jobs);
      setStats(updatedStats);
      
      alert(`✅ Backup job deleted successfully!`);
      
    } catch (error) {
      console.error('Failed to delete backup job:', error);
      alert(`❌ Failed to delete backup job: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  // Filter VMs by selected subtab
  const getFilteredVMs = () => {
    if (vmSubTab === 'all') {
      return vms;
    }
    return vms.filter(vm => vm.platform === vmSubTab);
  };

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: <Terminal size={20} /> },
    { id: 'vms', label: 'Virtual Machines', icon: <Server size={20} /> },
    { id: 'jobs', label: 'Backup Jobs', icon: <Shield size={20} /> },
    { id: 'platforms', label: 'Platforms', icon: <Settings size={20} /> },
  ];

  const vmSubTabs = [
    { id: 'all', label: 'All VMs', count: vms.length },
    { id: 'vmware', label: 'VMware', count: vms.filter(vm => vm.platform === 'vmware').length },
    { id: 'proxmox', label: 'Proxmox', count: vms.filter(vm => vm.platform === 'proxmox').length },
    { id: 'xcpng', label: 'XCP-NG', count: vms.filter(vm => vm.platform === 'xcpng').length },
    { id: 'ubuntu', label: 'Ubuntu', count: vms.filter(vm => vm.platform === 'ubuntu').length },
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
                value={backupJobs.length.toString()}
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
                      <span className="text-slate-300 capitalize">{platform} ({vms.filter(vm => vm.platform === platform).length} VMs)</span>
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

            {/* VM Subtabs */}
            <div className="border-b border-slate-700">
              <div className="flex space-x-8">
                {vmSubTabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setVmSubTab(tab.id as any)}
                    className={`flex items-center space-x-2 py-3 px-1 border-b-2 font-medium text-sm transition-all duration-200 ${
                      vmSubTab === tab.id
                        ? 'border-blue-400 text-blue-400'
                        : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-500'
                    }`}
                  >
                    <span>{tab.label}</span>
                    <span className={`px-2 py-1 rounded-full text-xs ${
                      vmSubTab === tab.id 
                        ? 'bg-blue-400 text-slate-900' 
                        : 'bg-slate-700 text-slate-300'
                    }`}>
                      {tab.count}
                    </span>
                  </button>
                ))}
              </div>
            </div>
            
            {getFilteredVMs().length === 0 ? (
              <Card>
                <div className="text-center py-12">
                  <Server className="text-blue-400 mx-auto mb-4" size={48} />
                  <h3 className="text-white text-lg font-medium mb-2">
                    {vmSubTab === 'all' ? 'No Virtual Machines' : `No ${vmSubTab.toUpperCase()} VMs`}
                  </h3>
                  <p className="text-slate-400 mb-4">
                    {vmSubTab === 'all' 
                      ? 'Connect to platforms first, then add VMs manually or use network discovery'
                      : `No VMs found for ${vmSubTab.toUpperCase()} platform`
                    }
                  </p>
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
                {getFilteredVMs().map((vm) => (
                  <VMCard 
                    key={`${vm.platform}-${vm.vm_id}`} 
                    vm={vm} 
                    onBackup={() => setShowCreateBackupJob(true)}
                    onEdit={(vm) => {
                      setSelectedVM(vm);
                      setShowEditVM(true);
                    }}
                    onMonitor={(vm) => {
                      setSelectedVM(vm);
                      setShowMonitorVM(true);
                    }}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'jobs' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Backup Jobs ({backupJobs.length})</h2>
              <Button 
                variant="primary" 
                onClick={() => setShowCreateBackupJob(true)}
                disabled={vms.length === 0}
              >
                <Plus size={16} className="mr-2" />
                New Job
              </Button>
            </div>

            {backupJobs.length === 0 ? (
              <Card>
                <div className="text-center py-12">
                  <Shield className="text-blue-400 mx-auto mb-4" size={48} />
                  <h3 className="text-white text-lg font-medium mb-2">No Backup Jobs</h3>
                  <p className="text-slate-400 mb-4">
                    {vms.length === 0 
                      ? 'Connect to platforms and discover VMs first'
                      : 'Create your first backup job to get started'
                    }
                  </p>
                  {vms.length > 0 ? (
                    <Button variant="primary" onClick={() => setShowCreateBackupJob(true)}>
                      <Plus size={16} className="mr-2" />
                      Create Backup Job
                    </Button>
                  ) : (
                    <Button variant="primary" onClick={() => setActiveTab('platforms')}>
                      <Settings size={16} className="mr-2" />
                      Connect Platforms
                    </Button>
                  )}
                </div>
              </Card>
            ) : (
              <div className="space-y-4">
                {backupJobs.map((job) => (
                  <Card key={job.id}>
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <h3 className="text-white font-semibold">{job.name}</h3>
                          <StatusIndicator status={job.status} />
                          <span className="text-slate-400 text-sm">
                            {job.platform.toUpperCase()}
                          </span>
                        </div>
                        {job.description && (
                          <p className="text-slate-400 text-sm mb-2">{job.description}</p>
                        )}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          <div>
                            <span className="text-slate-400">VM:</span>
                            <span className="text-white ml-2">{job.vm_id}</span>
                          </div>
                          <div>
                            <span className="text-slate-400">Type:</span>
                            <span className="text-white ml-2">{job.backup_type}</span>
                          </div>
                          <div>
                            <span className="text-slate-400">Last Run:</span>
                            <span className="text-white ml-2">
                              {job.last_run ? new Date(job.last_run).toLocaleDateString() : 'Never'}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-400">Next Run:</span>
                            <span className="text-white ml-2">
                              {job.next_run ? new Date(job.next_run).toLocaleDateString() : 'Not scheduled'}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex space-x-2 ml-4">
                        <Button 
                          size="sm" 
                          variant="primary"
                          onClick={() => handleRunBackupJob(job.id)}
                          disabled={job.status === 'running'}
                        >
                          <Shield size={14} className="mr-1" />
                          {job.status === 'running' ? 'Running...' : 'Run Now'}
                        </Button>
                        <Button 
                          size="sm" 
                          variant="danger"
                          onClick={() => handleDeleteBackupJob(job.id)}
                        >
                          <X size={14} className="mr-1" />
                          Delete
                        </Button>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            )}
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

      {/* Modals */}
      <CreateBackupJobModal
        isOpen={showCreateBackupJob}
        onClose={() => setShowCreateBackupJob(false)}
        vms={vms}
        onCreateJob={handleCreateBackupJob}
      />

      {showAddVM && (
        <Modal isOpen={true} onClose={() => setShowAddVM(false)} title="Add Virtual Machine">
          <div className="text-center py-8">
            <h3 className="text-white font-medium mb-4">Add VM functionality coming soon!</h3>
            <p className="text-slate-400 mb-4">For now, connect to platforms to automatically discover VMs.</p>
            <Button onClick={() => setShowAddVM(false)} variant="primary">
              Close
            </Button>
          </div>
        </Modal>
      )}

      {showNetworkDiscovery && (
        <Modal isOpen={true} onClose={() => setShowNetworkDiscovery(false)} title="Network Discovery">
          <div className="text-center py-8">
            <h3 className="text-white font-medium mb-4">Network Discovery functionality coming soon!</h3>
            <p className="text-slate-400 mb-4">For now, connect to platforms directly to discover VMs.</p>
            <Button onClick={() => setShowNetworkDiscovery(false)} variant="primary">
              Close
            </Button>
          </div>
        </Modal>
      )}

      {showEditVM && selectedVM && (
        <Modal isOpen={true} onClose={() => { setShowEditVM(false); setSelectedVM(null); }} title={`Edit VM: ${selectedVM.name}`}>
          <div className="text-center py-8">
            <h3 className="text-white font-medium mb-4">VM editing functionality coming soon!</h3>
            <p className="text-slate-400 mb-4">VM details are automatically synced from the platform.</p>
            <Button onClick={() => { setShowEditVM(false); setSelectedVM(null); }} variant="primary">
              Close
            </Button>
          </div>
        </Modal>
      )}

      {showMonitorVM && selectedVM && (
        <Modal isOpen={true} onClose={() => { setShowMonitorVM(false); setSelectedVM(null); }} title={`Monitor: ${selectedVM.name}`} size="lg">
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-300">Status:</span>
                  <StatusIndicator status={selectedVM.power_state} />
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-300">Platform:</span>
                  <span className="text-white font-mono">{selectedVM.platform.toUpperCase()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-300">IP Address:</span>
                  <span className="text-white font-mono">{selectedVM.ip_address || selectedVM.host}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-300">OS:</span>
                  <span className="text-white">{selectedVM.operating_system}</span>
                </div>
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-300">CPU:</span>
                  <span className="text-white">{selectedVM.cpu_count} cores</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-300">Memory:</span>
                  <span className="text-white">{Math.round(selectedVM.memory_mb / 1024)} GB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-300">Storage:</span>
                  <span className="text-white">{selectedVM.disk_size_gb} GB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-300">Created:</span>
                  <span className="text-white">{new Date(selectedVM.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            </div>

            <div className="bg-blue-900 bg-opacity-30 border border-blue-500 rounded p-3">
              <p className="text-blue-300 text-sm">
                Real-time monitoring features coming soon! This will include CPU usage, memory consumption, network activity, and more.
              </p>
            </div>

            <div className="flex justify-end space-x-3">
              <Button onClick={() => { setShowMonitorVM(false); setSelectedVM(null); }} variant="secondary">
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

// Auth Guard and App component (keeping existing...)
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

        {showLogin && (
          <LoginForm onClose={() => setShowLogin(false)} />
        )}
      </div>
    );
  }

  return <>{children}</>;
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
