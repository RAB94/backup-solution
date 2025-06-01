import React, { useState, useEffect, createContext, useContext } from 'react';
import { 
  Server, 
  HardDrive, 
  Shield, 
  Database,
  Cloud,
  RefreshCw,
  Play,
  Trash2,
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
  UserPlus,
  Wifi,
  Search,
  AlertCircle,
  X
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

const Modal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}> = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-slate-800 border border-slate-700 rounded-lg w-96 max-w-full mx-4">
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

const ConfirmationModal: React.FC<{
  isOpen: boolean;
  title: string;
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}> = ({ isOpen, title, message, onConfirm, onCancel }) => (
  <Modal isOpen={isOpen} onClose={onCancel} title={title}>
    <div className="space-y-4">
      <p className="text-slate-300">{message}</p>
      <div className="flex justify-end space-x-3">
        <Button onClick={onCancel} variant="secondary">
          Cancel
        </Button>
        <Button onClick={onConfirm} variant="danger">
          Confirm
        </Button>
      </div>
    </div>
  </Modal>
);

const LoginForm: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async () => {
    console.log('Login form submitted:', { username, password: '***' });
    setLoading(true);
    setError('');
    
    if (!username || !password) {
      setError('Please enter both username and password');
      setLoading(false);
      return;
    }
    
    try {
      console.log('Calling login API...');
      const success = await login(username, password);
      console.log('Login API result:', success);
      
      if (success) {
        console.log('Login successful, closing modal');
        onClose();
      } else {
        setError('Invalid credentials');
      }
    } catch (err: any) {
      console.error('Login error:', err);
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
          <label className="block text-slate-300 text-sm font-medium mb-2">
            Username
          </label>
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
          <label className="block text-slate-300 text-sm font-medium mb-2">
            Password
          </label>
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

const RegisterForm: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    confirm_password: '',
    role: 'viewer' as const
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { register } = useAuth();

  const handleSubmit = async () => {
    console.log('Registration form submitted:', formData);
    setLoading(true);
    setError('');
    
    if (formData.password !== formData.confirm_password) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    if (!formData.username || !formData.email || !formData.full_name || !formData.password) {
      setError('Please fill in all required fields');
      setLoading(false);
      return;
    }

    try {
      console.log('Calling register API...');
      const success = await register(formData);
      console.log('Register API result:', success);
      
      if (success) {
        alert('Registration successful! Please login.');
        onClose();
      } else {
        setError('Registration failed. Please try again.');
      }
    } catch (err: any) {
      console.error('Registration error:', err);
      setError(err.message || 'Registration failed. Please check your connection.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal isOpen={true} onClose={onClose} title="Register">
      <div className="space-y-4 max-h-80 overflow-y-auto">
        {error && (
          <div className="p-3 bg-red-900 bg-opacity-50 border border-red-500 rounded text-red-300 text-sm">
            {error}
          </div>
        )}

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Username</label>
          <input
            type="text"
            value={formData.username}
            onChange={(e) => setFormData({...formData, username: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Choose username"
            disabled={loading}
          />
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Email</label>
          <input
            type="email"
            value={formData.email}
            onChange={(e) => setFormData({...formData, email: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="email@company.com"
            disabled={loading}
          />
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Full Name</label>
          <input
            type="text"
            value={formData.full_name}
            onChange={(e) => setFormData({...formData, full_name: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="John Doe"
            disabled={loading}
          />
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Password</label>
          <input
            type="password"
            value={formData.password}
            onChange={(e) => setFormData({...formData, password: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Enter password"
            disabled={loading}
          />
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Confirm Password</label>
          <input
            type="password"
            value={formData.confirm_password}
            onChange={(e) => setFormData({...formData, confirm_password: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Confirm password"
            disabled={loading}
          />
        </div>

        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary" disabled={loading}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} variant="primary" disabled={loading}>
            {loading ? <RefreshCw size={16} className="mr-2 animate-spin" /> : <UserPlus size={16} className="mr-2" />}
            {loading ? 'Creating...' : 'Register'}
          </Button>
        </div>
      </div>
    </Modal>
  );
};

const AuthGuard: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  const [showLogin, setShowLogin] = useState(false);
  const [showRegister, setShowRegister] = useState(false);

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
                VM Backup Solution
              </h1>
              <p className="text-slate-400 text-sm mt-2">Please login to continue</p>
            </div>
            <div className="flex space-x-3 justify-center">
              <Button onClick={() => setShowLogin(true)} variant="primary">
                <LogIn size={16} className="mr-2" />
                Login
              </Button>
              <Button onClick={() => setShowRegister(true)} variant="secondary">
                <UserPlus size={16} className="mr-2" />
                Register
              </Button>
            </div>
          </div>
        </Card>

        {showLogin && <LoginForm onClose={() => setShowLogin(false)} />}
        {showRegister && <RegisterForm onClose={() => setShowRegister(false)} />}
      </div>
    );
  }

  return <>{children}</>;
};

const AddVMModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  availableVMs: VM[];
  onAddVM: (vm: VM) => void;
}> = ({ isOpen, onClose, availableVMs, onAddVM }) => {
  const [selectedVM, setSelectedVM] = useState<VM | null>(null);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Add Virtual Machine">
      <div className="space-y-4">
        <p className="text-slate-300 text-sm">
          Select a virtual machine from connected platforms to add to backup monitoring:
        </p>
        
        {availableVMs.length === 0 ? (
          <div className="text-center py-8">
            <AlertCircle className="text-amber-400 mx-auto mb-2" size={32} />
            <p className="text-slate-300">No VMs available</p>
            <p className="text-slate-400 text-sm">Connect to platforms first to discover VMs</p>
          </div>
        ) : (
          <div className="max-h-60 overflow-y-auto space-y-2">
            {availableVMs.map((vm) => (
              <div
                key={`${vm.platform}-${vm.vm_id}`}
                className={`p-3 border rounded cursor-pointer transition-colors ${
                  selectedVM?.vm_id === vm.vm_id
                    ? 'border-blue-500 bg-blue-500 bg-opacity-10'
                    : 'border-slate-600 hover:border-slate-500'
                }`}
                onClick={() => setSelectedVM(vm)}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white font-medium">{vm.name}</p>
                    <p className="text-slate-400 text-sm">{vm.vm_id} • {vm.platform}</p>
                  </div>
                  <StatusIndicator status={vm.power_state} showLabel={false} />
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary">
            Cancel
          </Button>
          <Button
            onClick={() => {
              if (selectedVM) {
                onAddVM(selectedVM);
                onClose();
              }
            }}
            variant="primary"
            disabled={!selectedVM}
          >
            Add VM
          </Button>
        </div>
      </div>
    </Modal>
  );
};

const UbuntuDiscovery: React.FC<{
  onMachineConnect: (machine: any) => void;
}> = ({ onMachineConnect }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [discoveredMachines, setDiscoveredMachines] = useState<any[]>([]);
  const [networkRange, setNetworkRange] = useState('192.168.1.0/24');

  const handleScan = async () => {
    setIsScanning(true);
    try {
      const result = await api.discoverUbuntuMachines(networkRange);
      setDiscoveredMachines(result.machines || []);
    } catch (error) {
      console.error('Network scan failed:', error);
      alert('Network scan failed');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <Card>
      <div className="space-y-4">
        <h3 className="text-white text-lg font-medium">Ubuntu Network Discovery</h3>

        <div className="flex space-x-3">
          <input
            type="text"
            value={networkRange}
            onChange={(e) => setNetworkRange(e.target.value)}
            className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="192.168.1.0/24"
          />
          <Button onClick={handleScan} disabled={isScanning} variant="primary">
            {isScanning ? <RefreshCw size={16} className="mr-2 animate-spin" /> : <Search size={16} className="mr-2" />}
            {isScanning ? 'Scanning...' : 'Scan Network'}
          </Button>
        </div>

        {discoveredMachines.length > 0 && (
          <div className="space-y-3">
            <h4 className="text-white font-medium">Discovered Machines:</h4>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {discoveredMachines.map((machine, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-slate-700 rounded border border-slate-600">
                  <div>
                    <div className="text-white font-medium">{machine.hostname}</div>
                    <div className="text-slate-400 text-sm">{machine.ip} - {machine.os_type}</div>
                  </div>
                  <Button 
                    onClick={() => onMachineConnect(machine)} 
                    size="sm" 
                    variant="primary"
                  >
                    <Wifi size={14} className="mr-1" />
                    Connect
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
};

const UbuntuConnectionModal: React.FC<{
  machine: any;
  onClose: () => void;
  onConnect: (connectionData: any) => void;
}> = ({ machine, onClose, onConnect }) => {
  const [connectionData, setConnectionData] = useState({
    ip: machine?.ip || '',
    username: '',
    password: '',
    ssh_key_path: '',
    port: 22,
    use_key: false
  });

  const handleConnect = () => {
    onConnect(connectionData);
    onClose();
  };

  return (
    <Modal isOpen={true} onClose={onClose} title={`Connect to ${machine?.hostname}`}>
      <div className="space-y-4">
        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Username</label>
          <input
            type="text"
            value={connectionData.username}
            onChange={(e) => setConnectionData({...connectionData, username: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="ubuntu"
          />
        </div>

        <div className="flex items-center space-x-3">
          <input
            type="checkbox"
            checked={connectionData.use_key}
            onChange={(e) => setConnectionData({...connectionData, use_key: e.target.checked})}
            className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
          />
          <label className="text-slate-300 text-sm">Use SSH Key</label>
        </div>

        {connectionData.use_key ? (
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
              placeholder="Enter password"
            />
          </div>
        )}

        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary">Cancel</Button>
          <Button onClick={handleConnect} variant="primary">
            <Zap size={16} className="mr-2" />
            Connect
          </Button>
        </div>
      </div>
    </Modal>
  );
};

const handleInstallAgent = async (vm: VM) => {
  try {
    await api.installUbuntuAgent(vm.vm_id);
    alert('Backup agent installation started');
  } catch (error) {
    console.error('Failed to install agent:', error);
    alert('Failed to install agent');
  }
};

const VMCard: React.FC<{ vm: VM; onBackup: (vm: VM) => void }> = ({ vm, onBackup }) => {
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
          <Button size="sm" variant="secondary">
            <Eye size={14} className="mr-1" />
            Monitor
          </Button>
          {vm.platform === 'ubuntu' && (
            <Button 
              size="sm" 
              variant="secondary"
              onClick={() => handleInstallAgent(vm)}
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

const BackupJobTable: React.FC<{
  jobs: BackupJob[];
  onRun: (id: number) => void;
  onDelete: (id: number) => void;
}> = ({ jobs, onRun, onDelete }) => {
  const [showConfirmDelete, setShowConfirmDelete] = useState(false);
  const [jobToDelete, setJobToDelete] = useState<number | null>(null);

  const handleDeleteClick = (jobId: number) => {
    setJobToDelete(jobId);
    setShowConfirmDelete(true);
  };

  const handleConfirmDelete = () => {
    if (jobToDelete) {
      onDelete(jobToDelete);
      setJobToDelete(null);
    }
    setShowConfirmDelete(false);
  };

  const handleCancelDelete = () => {
    setJobToDelete(null);
    setShowConfirmDelete(false);
  };

  if (jobs.length === 0) {
    return (
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
    );
  }

  return (
    <>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 text-slate-300 font-medium text-sm">Job Name</th>
                <th className="text-left py-3 text-slate-300 font-medium text-sm">VM Target</th>
                <th className="text-left py-3 text-slate-300 font-medium text-sm">Type</th>
                <th className="text-left py-3 text-slate-300 font-medium text-sm">Status</th>
                <th className="text-left py-3 text-slate-300 font-medium text-sm">Last Run</th>
                <th className="text-left py-3 text-slate-300 font-medium text-sm">Next Run</th>
                <th className="text-center py-3 text-slate-300 font-medium text-sm">Actions</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job, index) => (
                <tr 
                  key={job.id} 
                  className={`border-b border-slate-700 hover:bg-slate-700 hover:bg-opacity-50 transition-colors ${
                    index % 2 === 0 ? 'bg-slate-800 bg-opacity-30' : ''
                  }`}
                >
                  <td className="py-4">
                    <div>
                      <div className="text-white font-medium">{job.name}</div>
                      <div className="text-slate-400 text-sm">{job.description}</div>
                    </div>
                  </td>
                  <td className="py-4">
                    <span className="text-blue-300 font-mono">{job.vm_id}</span>
                  </td>
                  <td className="py-4">
                    <span className="px-2 py-1 bg-slate-700 border border-slate-600 rounded text-blue-400 text-xs font-mono uppercase">
                      {job.backup_type}
                    </span>
                  </td>
                  <td className="py-4">
                    <StatusIndicator status={job.status} />
                  </td>
                  <td className="py-4">
                    <span className="text-slate-300 font-mono text-sm">
                      {job.last_run ? new Date(job.last_run).toLocaleString() : 'Never'}
                    </span>
                  </td>
                  <td className="py-4">
                    <span className="text-slate-300 font-mono text-sm">
                      {job.next_run ? new Date(job.next_run).toLocaleString() : 'Not scheduled'}
                    </span>
                  </td>
                  <td className="py-4">
                    <div className="flex justify-center space-x-2">
                      <button
                        onClick={() => onRun(job.id)}
                        className="p-2 text-emerald-400 hover:bg-emerald-400 hover:bg-opacity-20 rounded transition-colors"
                        title="Run Now"
                      >
                        <Play size={16} />
                      </button>
                      <button
                        onClick={() => handleDeleteClick(job.id)}
                        className="p-2 text-red-400 hover:bg-red-400 hover:bg-opacity-20 rounded transition-colors"
                        title="Delete"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <ConfirmationModal
        isOpen={showConfirmDelete}
        title="Delete Backup Job"
        message="Are you sure you want to delete this backup job? This action cannot be undone."
        onConfirm={handleConfirmDelete}
        onCancel={handleCancelDelete}
      />
    </>
  );
};

const PlatformConnector: React.FC<{
  platform: string;
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

      <Modal isOpen={isOpen} onClose={() => setIsOpen(false)} title={`Connect to ${platform}`}>
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
              placeholder={platform === 'ubuntu' ? '192.168.1.100' : 'your-server.domain.com'}
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
                platform === 'ubuntu' ? 'ubuntu' : 'root'
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
              <label className="text-slate-300 text-sm">Use SSH Key</label>
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

          <div className="flex justify-end space-x-3">
            <Button onClick={() => setIsOpen(false)} variant="secondary">
              Cancel
            </Button>
            <Button 
              onClick={() => {
                onConnect(platform, connectionData);
                setIsOpen(false);
              }}
              variant="primary"
            >
              <Zap size={16} className="mr-2" />
              Connect
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
};

const VMBackupDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'vms' | 'ubuntu' | 'jobs' | 'platforms'>('dashboard');
  const [stats, setStats] = useState<DashboardStats>({
    total_backup_jobs: 0,
    running_jobs: 0,
    total_vms_protected: 0,
    total_backups_size: '0 GB',
    last_24h_jobs: 0,
    success_rate: '0%'
  });
  const [vms, setVMs] = useState<VM[]>([]);
  const [ubuntuMachines, setUbuntuMachines] = useState<VM[]>([]);
  const [backupJobs, setBackupJobs] = useState<BackupJob[]>([]);
  const [selectedMachine, setSelectedMachine] = useState<any>(null);
  const [showUbuntuConnection, setShowUbuntuConnection] = useState(false);
  const [showAddVM, setShowAddVM] = useState(false);
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
      // Load real data from API
      const [statsData, jobsData] = await Promise.all([
        api.getStatistics().catch(() => ({
          total_backup_jobs: 0,
          running_jobs: 0,
          total_vms_protected: 0,
          total_backups_size: '0 GB',
          last_24h_jobs: 0,
          success_rate: '0%'
        })),
        api.getBackupJobs().catch(() => [])
      ]);

      setStats(statsData);
      setBackupJobs(jobsData);

      // Load VMs from connected platforms - this will be empty initially
      setVMs([]);
      setUbuntuMachines([]);
    } catch (error) {
      console.error('Failed to load initial data:', error);
    } finally {
      setLoading(false);
    }
  };

  const refreshVMsForPlatform = async (platform: string) => {
    try {
      const platformVMs = await api.getVMs(platform);
      if (platform === 'ubuntu') {
        // Replace instead of appending to avoid duplicates
        setUbuntuMachines(platformVMs);
      } else {
        // Merge with existing VMs from other platforms, avoiding duplicates
        setVMs(prev => {
          const filtered = prev.filter(vm => vm.platform !== platform);
          return [...filtered, ...platformVMs];
        });
      }
    } catch (error) {
      console.error(`Failed to load VMs for ${platform}:`, error);
    }
  };

  const handleConnectPlatform = async (platform: string, connectionData: any) => {
    try {
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
      
      alert(`Successfully connected to ${platform}`);
      
      // Refresh VMs for this platform
      await refreshVMsForPlatform(platform);
    } catch (error) {
      console.error('Failed to connect:', error);
      alert(`Failed to connect to ${platform}: ${error}`);
    }
  };

  const handleScanNetworks = async () => {
    try {
      // Only scan platforms that are connected
      const connectedPlatforms = Object.entries(platformStatus)
        .filter(([_, connected]) => connected)
        .map(([platform, _]) => platform);

      if (connectedPlatforms.length === 0) {
        alert('No platforms connected. Please connect to platforms first.');
        return;
      }

      // Refresh all connected platforms
      await Promise.all(
        connectedPlatforms.map(platform => 
          refreshVMsForPlatform(platform).catch(() => {})
        )
      );
      
      alert('Network scan completed');
    } catch (error) {
      console.error('Network scan failed:', error);
      alert('Network scan failed');
    }
  };

  const handleAddVM = (vm: VM) => {
    // Add VM to monitoring (in real implementation, this would save to backend)
    alert(`Added ${vm.name} to backup monitoring`);
  };

  const handleBackupVM = (vm: VM) => {
    if (vm.platform === 'ubuntu') {
      api.backupUbuntuMachine(vm.vm_id, {});
      alert(`Starting Ubuntu machine backup for: ${vm.name}`);
    } else {
      alert(`Starting backup for VM: ${vm.name}`);
    }
  };

  const handleRunBackupJob = async (jobId: number) => {
    try {
      await api.runBackupJob(jobId);
      const jobs = await api.getBackupJobs();
      setBackupJobs(jobs);
      alert('Backup job started successfully');
    } catch (error) {
      console.error('Failed to run backup job:', error);
      alert('Failed to start backup job');
    }
  };

  const handleDeleteBackupJob = async (jobId: number) => {
    try {
      await api.deleteBackupJob(jobId);
      setBackupJobs(prev => prev.filter(job => job.id !== jobId));
      alert('Backup job deleted successfully');
    } catch (error) {
      console.error('Failed to delete backup job:', error);
      alert('Failed to delete backup job');
    }
  };

  const handleUbuntuMachineConnect = (machine: any) => {
    setSelectedMachine(machine);
    setShowUbuntuConnection(true);
  };

  const getAllVMs = () => [...vms, ...ubuntuMachines];

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: <Terminal size={20} /> },
    { id: 'vms', label: 'Virtual Machines', icon: <Server size={20} /> },
    { id: 'ubuntu', label: 'Ubuntu Machines', icon: <Monitor size={20} /> },
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
                  <h1 className="text-xl font-bold text-white">VM Backup Solution</h1>
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
                value={stats.total_vms_protected.toString()}
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
                    <span className="text-slate-300">Scheduler Service</span>
                    <StatusIndicator status="online" />
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-300">API Service</span>
                    <StatusIndicator status="online" />
                  </div>
                </div>
              </Card>

              <Card>
                <h3 className="text-white text-lg font-medium mb-4">Recent Activity</h3>
                <div className="space-y-3">
                  {backupJobs.length === 0 ? (
                    <div className="text-center py-8">
                      <p className="text-slate-400">No recent activity</p>
                      <p className="text-slate-500 text-sm">Create backup jobs to see activity here</p>
                    </div>
                  ) : (
                    backupJobs.slice(0, 3).map((job) => (
                      <div key={job.id} className="flex items-start space-x-3">
                        <CheckCircle className="text-emerald-400 mt-1" size={16} />
                        <div>
                          <p className="text-white text-sm">{job.name}</p>
                          <p className="text-slate-400 text-xs">
                            {job.last_run ? new Date(job.last_run).toLocaleString() : 'Not run yet'}
                          </p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </Card>
            </div>
          </div>
        )}

        {activeTab === 'vms' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Virtual Machines</h2>
              <div className="flex space-x-3">
                <Button onClick={handleScanNetworks} variant="secondary">
                  <RefreshCw size={16} className="mr-2" />
                  Scan Networks
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
                  <p className="text-slate-400 mb-4">Connect to platforms to discover VMs</p>
                  <Button variant="primary" onClick={() => setActiveTab('platforms')}>
                    <Settings size={16} className="mr-2" />
                    Connect Platforms
                  </Button>
                </div>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {vms.map((vm) => (
                  <VMCard key={`${vm.platform}-${vm.vm_id}`} vm={vm} onBackup={handleBackupVM} />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'ubuntu' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Ubuntu Machines</h2>
              <div className="flex space-x-3">
                <Button variant="secondary">
                  <RefreshCw size={16} className="mr-2" />
                  Refresh
                </Button>
                <Button variant="primary">
                  <Search size={16} className="mr-2" />
                  Discover
                </Button>
              </div>
            </div>

            <UbuntuDiscovery onMachineConnect={handleUbuntuMachineConnect} />
            
            {ubuntuMachines.length === 0 ? (
              <Card>
                <div className="text-center py-12">
                  <Monitor className="text-blue-400 mx-auto mb-4" size={48} />
                  <h3 className="text-white text-lg font-medium mb-2">No Ubuntu Machines</h3>
                  <p className="text-slate-400 mb-4">Use network discovery to find Ubuntu machines</p>
                </div>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {ubuntuMachines.map((machine) => (
                  <VMCard key={`${machine.platform}-${machine.vm_id}`} vm={machine} onBackup={handleBackupVM} />
                ))}
              </div>
            )}

            {showUbuntuConnection && selectedMachine && (
              <UbuntuConnectionModal
                machine={selectedMachine}
                onClose={() => setShowUbuntuConnection(false)}
                onConnect={(connectionData) => handleConnectPlatform('ubuntu', connectionData)}
              />
            )}
          </div>
        )}

        {activeTab === 'jobs' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Backup Jobs</h2>
              <div className="flex space-x-3">
                <Button variant="secondary" onClick={loadInitialData}>
                  <RefreshCw size={16} className="mr-2" />
                  Refresh
                </Button>
                <Button variant="primary">
                  <Plus size={16} className="mr-2" />
                  New Job
                </Button>
              </div>
            </div>

            <BackupJobTable 
              jobs={backupJobs}
              onRun={handleRunBackupJob}
              onDelete={handleDeleteBackupJob}
            />
          </div>
        )}

        {activeTab === 'platforms' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Platform Connections</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <PlatformConnector 
                platform="vmware" 
                onConnect={handleConnectPlatform} 
                isConnected={platformStatus.vmware}
              />
              <PlatformConnector 
                platform="proxmox" 
                onConnect={handleConnectPlatform} 
                isConnected={platformStatus.proxmox}
              />
              <PlatformConnector 
                platform="xcpng" 
                onConnect={handleConnectPlatform} 
                isConnected={platformStatus.xcpng}
              />
              <PlatformConnector 
                platform="ubuntu" 
                onConnect={handleConnectPlatform} 
                isConnected={platformStatus.ubuntu}
              />
            </div>
          </div>
        )}
      </main>

      <AddVMModal
        isOpen={showAddVM}
        onClose={() => setShowAddVM(false)}
        availableVMs={getAllVMs()}
        onAddVM={handleAddVM}
      />
    </div>
  );
};

// Main App Component
const App: React.FC = () => {
  return (
    <AuthProvider>
      <AuthGuard>
        <VMBackupDashboard />
      </AuthGuard>
    </AuthProvider>
  );
};

export default App;
