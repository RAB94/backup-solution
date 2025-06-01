import React, { useState, useEffect, createContext, useContext } from 'react';
import { 
  Server, 
  HardDrive, 
  Shield, 
  Activity, 
  Database,
  Cloud,
  RefreshCw,
  Play,
  Pause,
  Trash2,
  Download,
  Upload,
  Settings,
  AlertTriangle,
  CheckCircle,
  Clock,
  Plus,
  BarChart3,
  Monitor,
  Cpu,
  MemoryStick,
  Zap,
  Eye,
  Terminal,
  LogIn,
  LogOut,
  UserPlus,
  Users,
  Lock,
  Wifi,
  Search
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

// API Service
class APIService {
  private baseURL = 'http://localhost:8000/api/v1';
  private authToken: string | null = null;

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

    const response = await fetch(`${this.baseURL}${endpoint}`, {
      headers,
      ...options,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(errorData.detail || `API Error: ${response.statusText}`);
    }

    return response.json();
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
    try {
      await api.register(userData);
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
const FuturisticCard: React.FC<{
  children: React.ReactNode;
  className?: string;
  glowColor?: string;
}> = ({ children, className = '', glowColor = 'cyan' }) => (
  <div className={`
    bg-gray-900 bg-opacity-80 border border-cyan-500 border-opacity-30 
    rounded-lg backdrop-blur-sm relative overflow-hidden
    before:absolute before:inset-0 before:bg-gradient-to-r before:from-transparent before:via-cyan-500 before:via-opacity-5 before:to-transparent
    hover:border-opacity-60 transition-all duration-300
    ${className}
  `}>
    <div className="relative z-10 p-6">
      {children}
    </div>
  </div>
);

const GlowButton: React.FC<{
  children: React.ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
}> = ({ children, onClick, variant = 'primary', size = 'md', disabled = false }) => {
  const variants = {
    primary: 'bg-cyan-600 hover:bg-cyan-500 border-cyan-400 text-white shadow-cyan-500/50',
    secondary: 'bg-gray-700 hover:bg-gray-600 border-gray-500 text-cyan-100 shadow-gray-500/30',
    danger: 'bg-red-600 hover:bg-red-500 border-red-400 text-white shadow-red-500/50'
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
        hover:shadow-lg disabled:opacity-50 disabled:cursor-not-allowed
        focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-opacity-50
      `}
    >
      {children}
    </button>
  );
};

const MetricDisplay: React.FC<{
  title: string;
  value: string;
  icon: React.ReactNode;
  trend?: string;
  trendDirection?: 'up' | 'down' | 'stable';
}> = ({ title, value, icon, trend, trendDirection }) => (
  <FuturisticCard className="text-center">
    <div className="flex flex-col items-center space-y-3">
      <div className="text-cyan-400 text-3xl">{icon}</div>
      <div>
        <p className="text-gray-400 text-sm uppercase tracking-wider">{title}</p>
        <p className="text-white text-2xl font-bold font-mono">{value}</p>
        {trend && (
          <p className={`text-sm mt-1 ${
            trendDirection === 'up' ? 'text-green-400' : 
            trendDirection === 'down' ? 'text-red-400' : 'text-gray-400'
          }`}>
            {trendDirection === 'up' ? '↗' : trendDirection === 'down' ? '↘' : '→'} {trend}
          </p>
        )}
      </div>
    </div>
  </FuturisticCard>
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
        return { color: 'text-green-400', bg: 'bg-green-400', label: 'ONLINE' };
      case 'in progress':
        return { color: 'text-cyan-400', bg: 'bg-cyan-400', label: 'ACTIVE' };
      case 'failed':
      case 'error':
        return { color: 'text-red-400', bg: 'bg-red-400', label: 'ERROR' };
      case 'pending':
      case 'scheduled':
        return { color: 'text-yellow-400', bg: 'bg-yellow-400', label: 'PENDING' };
      case 'paused':
      case 'stopped':
        return { color: 'text-gray-400', bg: 'bg-gray-400', label: 'OFFLINE' };
      default:
        return { color: 'text-gray-400', bg: 'bg-gray-400', label: 'UNKNOWN' };
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

const LoginForm: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async () => {
    setLoading(true);
    setError('');
    
    try {
      const success = await login(username, password);
      if (success) {
        onClose();
      } else {
        setError('Invalid credentials');
      }
    } catch (err) {
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 backdrop-blur-sm">
      <FuturisticCard className="w-96 max-w-full mx-4">
        <div className="space-y-6">
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <Shield className="text-cyan-400" size={48} />
            </div>
            <h2 className="text-xl font-semibold text-white uppercase tracking-wider">
              ACCESS TERMINAL
            </h2>
            <p className="text-gray-400 text-sm mt-2">Enter your credentials</p>
          </div>

          {error && (
            <div className="p-3 bg-red-900 bg-opacity-50 border border-red-500 rounded text-red-300 text-sm">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                placeholder="Enter username"
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                placeholder="Enter password"
                disabled={loading}
                onKeyPress={(e) => e.key === 'Enter' && handleSubmit()}
              />
            </div>
          </div>

          <div className="flex justify-end space-x-3">
            <GlowButton onClick={onClose} variant="secondary" disabled={loading}>
              Cancel
            </GlowButton>
            <GlowButton onClick={handleSubmit} variant="primary" disabled={loading}>
              {loading ? <RefreshCw size={16} className="mr-2 animate-spin" /> : <LogIn size={16} className="mr-2" />}
              {loading ? 'Accessing...' : 'Login'}
            </GlowButton>
          </div>
        </div>
      </FuturisticCard>
    </div>
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
    setLoading(true);
    setError('');
    
    if (formData.password !== formData.confirm_password) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const success = await register(formData);
      if (success) {
        alert('Registration successful! Please login.');
        onClose();
      }
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 backdrop-blur-sm">
      <FuturisticCard className="w-96 max-w-full mx-4">
        <div className="space-y-6">
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <UserPlus className="text-cyan-400" size={48} />
            </div>
            <h2 className="text-xl font-semibold text-white uppercase tracking-wider">
              CREATE ACCOUNT
            </h2>
            <p className="text-gray-400 text-sm mt-2">Register new user</p>
          </div>

          {error && (
            <div className="p-3 bg-red-900 bg-opacity-50 border border-red-500 rounded text-red-300 text-sm">
              {error}
            </div>
          )}

          <div className="space-y-4 max-h-80 overflow-y-auto">
            <div>
              <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                Username
              </label>
              <input
                type="text"
                value={formData.username}
                onChange={(e) => setFormData({...formData, username: e.target.value})}
                className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                placeholder="Choose username"
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                Email
              </label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({...formData, email: e.target.value})}
                className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                placeholder="email@company.com"
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                Full Name
              </label>
              <input
                type="text"
                value={formData.full_name}
                onChange={(e) => setFormData({...formData, full_name: e.target.value})}
                className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                placeholder="John Doe"
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                Password
              </label>
              <input
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
                className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                placeholder="Enter password"
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                Confirm Password
              </label>
              <input
                type="password"
                value={formData.confirm_password}
                onChange={(e) => setFormData({...formData, confirm_password: e.target.value})}
                className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                placeholder="Confirm password"
                disabled={loading}
              />
            </div>
          </div>

          <div className="flex justify-end space-x-3">
            <GlowButton onClick={onClose} variant="secondary" disabled={loading}>
              Cancel
            </GlowButton>
            <GlowButton onClick={handleSubmit} variant="primary" disabled={loading}>
              {loading ? <RefreshCw size={16} className="mr-2 animate-spin" /> : <UserPlus size={16} className="mr-2" />}
              {loading ? 'Creating...' : 'Register'}
            </GlowButton>
          </div>
        </div>
      </FuturisticCard>
    </div>
  );
};

const AuthGuard: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  const [showLogin, setShowLogin] = useState(false);
  const [showRegister, setShowRegister] = useState(false);

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 flex items-center justify-center">
        <FuturisticCard className="text-center">
          <div className="space-y-6">
            <div className="flex justify-center">
              <Shield className="text-cyan-400" size={64} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white uppercase tracking-wider">
                VM BACKUP SOLUTION
              </h1>
              <p className="text-cyan-400 text-sm mt-2">SECURE ACCESS REQUIRED</p>
            </div>
            <div className="flex space-x-3 justify-center">
              <GlowButton onClick={() => setShowLogin(true)} variant="primary">
                <LogIn size={16} className="mr-2" />
                Login
              </GlowButton>
              <GlowButton onClick={() => setShowRegister(true)} variant="secondary">
                <UserPlus size={16} className="mr-2" />
                Register
              </GlowButton>
            </div>
          </div>
        </FuturisticCard>

        {showLogin && <LoginForm onClose={() => setShowLogin(false)} />}
        {showRegister && <RegisterForm onClose={() => setShowRegister(false)} />}
      </div>
    );
  }

  return <>{children}</>;
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
    <FuturisticCard>
      <div className="space-y-6">
        <h3 className="text-cyan-400 font-mono uppercase tracking-wider text-lg">
          UBUNTU NETWORK DISCOVERY
        </h3>

        <div className="flex space-x-3">
          <input
            type="text"
            value={networkRange}
            onChange={(e) => setNetworkRange(e.target.value)}
            className="flex-1 px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
            placeholder="192.168.1.0/24"
          />
          <GlowButton onClick={handleScan} disabled={isScanning} variant="primary">
            {isScanning ? <RefreshCw size={16} className="mr-2 animate-spin" /> : <Search size={16} className="mr-2" />}
            {isScanning ? 'Scanning...' : 'Scan Network'}
          </GlowButton>
        </div>

        {discoveredMachines.length > 0 && (
          <div className="space-y-3">
            <h4 className="text-white font-medium">Discovered Machines:</h4>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {discoveredMachines.map((machine, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-800 bg-opacity-50 rounded border border-cyan-500 border-opacity-20">
                  <div>
                    <div className="text-white font-medium">{machine.hostname}</div>
                    <div className="text-gray-400 text-sm">{machine.ip} - {machine.os_type}</div>
                  </div>
                  <GlowButton 
                    onClick={() => onMachineConnect(machine)} 
                    size="sm" 
                    variant="primary"
                  >
                    <Wifi size={14} className="mr-1" />
                    Connect
                  </GlowButton>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </FuturisticCard>
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
    <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 backdrop-blur-sm">
      <FuturisticCard className="w-96 max-w-full mx-4">
        <div className="space-y-6">
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <Monitor className="text-cyan-400" size={32} />
            </div>
            <h2 className="text-xl font-semibold text-white uppercase tracking-wider">
              Connect Ubuntu Machine
            </h2>
            <p className="text-gray-400 text-sm mt-2">{machine?.hostname} ({machine?.ip})</p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                Username
              </label>
              <input
                type="text"
                value={connectionData.username}
                onChange={(e) => setConnectionData({...connectionData, username: e.target.value})}
                className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                placeholder="ubuntu"
              />
            </div>

            <div className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={connectionData.use_key}
                onChange={(e) => setConnectionData({...connectionData, use_key: e.target.checked})}
                className="w-4 h-4 text-cyan-600 bg-gray-800 border-gray-600 rounded focus:ring-cyan-500"
              />
              <label className="text-cyan-400 text-sm font-mono uppercase tracking-wider">
                Use SSH Key
              </label>
            </div>

            {connectionData.use_key ? (
              <div>
                <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                  SSH Key Path
                </label>
                <input
                  type="text"
                  value={connectionData.ssh_key_path}
                  onChange={(e) => setConnectionData({...connectionData, ssh_key_path: e.target.value})}
                  className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                  placeholder="/path/to/private/key"
                />
              </div>
            ) : (
              <div>
                <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                  Password
                </label>
                <input
                  type="password"
                  value={connectionData.password}
                  onChange={(e) => setConnectionData({...connectionData, password: e.target.value})}
                  className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                  placeholder="Enter password"
                />
              </div>
            )}
          </div>

          <div className="flex justify-end space-x-3">
            <GlowButton onClick={onClose} variant="secondary">
              Cancel
            </GlowButton>
            <GlowButton onClick={handleConnect} variant="primary">
              <Zap size={16} className="mr-2" />
              Connect
            </GlowButton>
          </div>
        </div>
      </FuturisticCard>
    </div>
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
      case 'xcpng': return <Cloud className="text-green-400" />;
      case 'ubuntu': return <Monitor className="text-orange-400" />;
      default: return <Server className="text-gray-400" />;
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
    <FuturisticCard className="hover:scale-105 transition-transform duration-200">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {getPlatformIcon(vm.platform)}
            <div>
              <h3 className="text-white font-semibold">{vm.name}</h3>
              <p className="text-gray-400 text-sm font-mono">{vm.vm_id}</p>
            </div>
          </div>
          <StatusIndicator status={vm.power_state} showLabel={false} />
        </div>

        <div className="flex justify-between items-center">
          <span 
            className="px-2 py-1 bg-gray-800 border border-opacity-30 rounded text-xs font-mono uppercase"
            style={{ 
              borderColor: getPlatformColor(vm.platform),
              color: getPlatformColor(vm.platform)
            }}
          >
            {vm.platform}
          </span>
          <span className="text-gray-400 text-xs">
            {vm.ip_address || vm.host}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="flex items-center space-x-2">
            <Cpu className="text-cyan-400" size={16} />
            <span className="text-white text-sm">{vm.cpu_count} cores</span>
          </div>
          <div className="flex items-center space-x-2">
            <MemoryStick className="text-cyan-400" size={16} />
            <span className="text-white text-sm">{Math.round(vm.memory_mb / 1024)} GB</span>
          </div>
          <div className="flex items-center space-x-2">
            <HardDrive className="text-cyan-400" size={16} />
            <span className="text-white text-sm">{vm.disk_size_gb} GB</span>
          </div>
          <div className="flex items-center space-x-2">
            <Monitor className="text-cyan-400" size={16} />
            <span className="text-white text-sm truncate">{vm.operating_system}</span>
          </div>
        </div>

        <div className="flex space-x-2">
          <GlowButton 
            onClick={() => onBackup(vm)} 
            size="sm"
            variant="primary"
          >
            <Shield size={14} className="mr-1" />
            Backup
          </GlowButton>
          <GlowButton size="sm" variant="secondary">
            <Eye size={14} className="mr-1" />
            Monitor
          </GlowButton>
          {vm.platform === 'ubuntu' && (
            <GlowButton 
              size="sm" 
              variant="secondary"
              onClick={() => handleInstallAgent(vm)}
            >
              <Download size={14} className="mr-1" />
              Agent
            </GlowButton>
          )}
        </div>
      </div>
    </FuturisticCard>
  );
};

const BackupJobTable: React.FC<{
  jobs: BackupJob[];
  onRun: (id: number) => void;
  onDelete: (id: number) => void;
}> = ({ jobs, onRun, onDelete }) => (
  <FuturisticCard>
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-cyan-500 border-opacity-30">
            <th className="text-left py-3 text-cyan-400 font-mono uppercase tracking-wider text-sm">Job Name</th>
            <th className="text-left py-3 text-cyan-400 font-mono uppercase tracking-wider text-sm">VM Target</th>
            <th className="text-left py-3 text-cyan-400 font-mono uppercase tracking-wider text-sm">Type</th>
            <th className="text-left py-3 text-cyan-400 font-mono uppercase tracking-wider text-sm">Status</th>
            <th className="text-left py-3 text-cyan-400 font-mono uppercase tracking-wider text-sm">Last Run</th>
            <th className="text-left py-3 text-cyan-400 font-mono uppercase tracking-wider text-sm">Next Run</th>
            <th className="text-center py-3 text-cyan-400 font-mono uppercase tracking-wider text-sm">Actions</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job, index) => (
            <tr 
              key={job.id} 
              className={`border-b border-gray-700 border-opacity-50 hover:bg-cyan-500 hover:bg-opacity-5 transition-colors ${
                index % 2 === 0 ? 'bg-gray-800 bg-opacity-30' : ''
              }`}
            >
              <td className="py-4">
                <div>
                  <div className="text-white font-medium">{job.name}</div>
                  <div className="text-gray-400 text-sm">{job.description}</div>
                </div>
              </td>
              <td className="py-4">
                <span className="text-cyan-300 font-mono">{job.vm_id}</span>
              </td>
              <td className="py-4">
                <span className="px-2 py-1 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-cyan-400 text-xs font-mono uppercase">
                  {job.backup_type}
                </span>
              </td>
              <td className="py-4">
                <StatusIndicator status={job.status} />
              </td>
              <td className="py-4">
                <span className="text-gray-300 font-mono text-sm">
                  {job.last_run ? new Date(job.last_run).toLocaleString() : 'Never'}
                </span>
              </td>
              <td className="py-4">
                <span className="text-gray-300 font-mono text-sm">
                  {job.next_run ? new Date(job.next_run).toLocaleString() : 'Not scheduled'}
                </span>
              </td>
              <td className="py-4">
                <div className="flex justify-center space-x-2">
                  <button
                    onClick={() => onRun(job.id)}
                    className="p-2 text-green-400 hover:bg-green-400 hover:bg-opacity-20 rounded transition-colors"
                    title="Run Now"
                  >
                    <Play size={16} />
                  </button>
                  <button
                    onClick={() => onDelete(job.id)}
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
  </FuturisticCard>
);

const PlatformConnector: React.FC<{
  platform: string;
  onConnect: (platform: string, data: any) => void;
}> = ({ platform, onConnect }) => {
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
      case 'xcpng': return <Cloud className="text-green-400" size={32} />;
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
      <FuturisticCard className="text-center hover:scale-105 transition-transform duration-200">
        <div className="space-y-4">
          <div className="flex justify-center">{getPlatformIcon()}</div>
          <div>
            <h3 className="text-white font-semibold text-lg uppercase tracking-wider">{platform}</h3>
            <p className="text-gray-400 text-sm">{getPlatformDescription()}</p>
          </div>
          <GlowButton onClick={() => setIsOpen(true)} variant="primary">
            <Zap size={16} className="mr-2" />
            Connect
          </GlowButton>
        </div>
      </FuturisticCard>

      {isOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 backdrop-blur-sm">
          <FuturisticCard className="w-96 max-w-full mx-4">
            <div className="space-y-6">
              <div className="text-center">
                <div className="flex justify-center mb-4">{getPlatformIcon()}</div>
                <h2 className="text-xl font-semibold text-white uppercase tracking-wider">
                  Connect to {platform}
                </h2>
                <p className="text-gray-400 text-sm mt-2">Enter connection credentials</p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                    {platform === 'ubuntu' ? 'IP Address' : 'Host Address'}
                  </label>
                  <input
                    type="text"
                    value={connectionData.host}
                    onChange={(e) => setConnectionData({...connectionData, host: e.target.value})}
                    className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                    placeholder={platform === 'ubuntu' ? '192.168.1.100' : 'your-server.domain.com'}
                  />
                </div>

                <div>
                  <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                    Username
                  </label>
                  <input
                    type="text"
                    value={connectionData.username}
                    onChange={(e) => setConnectionData({...connectionData, username: e.target.value})}
                    className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
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
                      className="w-4 h-4 text-cyan-600 bg-gray-800 border-gray-600 rounded focus:ring-cyan-500"
                    />
                    <label className="text-cyan-400 text-sm font-mono uppercase tracking-wider">
                      Use SSH Key
                    </label>
                  </div>
                )}

                {platform === 'ubuntu' && connectionData.use_key ? (
                  <div>
                    <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                      SSH Key Path
                    </label>
                    <input
                      type="text"
                      value={connectionData.ssh_key_path}
                      onChange={(e) => setConnectionData({...connectionData, ssh_key_path: e.target.value})}
                      className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                      placeholder="/path/to/private/key"
                    />
                  </div>
                ) : (
                  <div>
                    <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                      Password
                    </label>
                    <input
                      type="password"
                      value={connectionData.password}
                      onChange={(e) => setConnectionData({...connectionData, password: e.target.value})}
                      className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                      placeholder="••••••••"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-cyan-400 text-sm font-mono uppercase tracking-wider mb-2">
                    Port
                  </label>
                  <input
                    type="number"
                    value={connectionData.port}
                    onChange={(e) => setConnectionData({...connectionData, port: parseInt(e.target.value)})}
                    className="w-full px-4 py-2 bg-gray-800 border border-cyan-500 border-opacity-30 rounded text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3">
                <GlowButton 
                  onClick={() => setIsOpen(false)}
                  variant="secondary"
                >
                  Cancel
                </GlowButton>
                <GlowButton 
                  onClick={() => {
                    onConnect(platform, connectionData);
                    setIsOpen(false);
                  }}
                  variant="primary"
                >
                  <Zap size={16} className="mr-2" />
                  Connect
                </GlowButton>
              </div>
            </div>
          </FuturisticCard>
        </div>
      )}
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
  const [loading, setLoading] = useState(false);
  const [selectedMachine, setSelectedMachine] = useState<any>(null);
  const [showUbuntuConnection, setShowUbuntuConnection] = useState(false);

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setStats({
      total_backup_jobs: 12,
      running_jobs: 2,
      total_vms_protected: 45,
      total_backups_size: '2.4 TB',
      last_24h_jobs: 8,
      success_rate: '99.2%'
    });

    setVMs([
      {
        id: 1,
        vm_id: 'vm-001',
        name: 'web-server-01',
        platform: 'vmware',
        host: 'esxi-host-01.local',
        cpu_count: 4,
        memory_mb: 8192,
        disk_size_gb: 100,
        operating_system: 'Ubuntu 20.04 LTS',
        power_state: 'poweredOn',
        created_at: '2024-01-15T10:30:00Z'
      },
      {
        id: 2,
        vm_id: '100',
        name: 'mail-server',
        platform: 'proxmox',
        host: 'pve-node-01',
        cpu_count: 2,
        memory_mb: 4096,
        disk_size_gb: 50,
        operating_system: 'Debian 11',
        power_state: 'running',
        created_at: '2024-01-10T14:20:00Z'
      },
      {
        id: 3,
        vm_id: 'xen-vm-001',
        name: 'dev-server',
        platform: 'xcpng',
        host: 'xcpng-host-01',
        cpu_count: 2,
        memory_mb: 4096,
        disk_size_gb: 80,
        operating_system: 'CentOS 8',
        power_state: 'Running',
        created_at: '2024-01-12T09:15:00Z'
      }
    ]);

    setUbuntuMachines([
      {
        id: 4,
        vm_id: 'ubuntu-192.168.1.101',
        name: 'laptop-dev-01',
        platform: 'ubuntu',
        host: '192.168.1.101',
        cpu_count: 4,
        memory_mb: 16384,
        disk_size_gb: 512,
        operating_system: 'Ubuntu 22.04.3 LTS',
        power_state: 'running',
        created_at: '2024-01-18T11:45:00Z',
        ip_address: '192.168.1.101'
      },
      {
        id: 5,
        vm_id: 'ubuntu-192.168.1.102',
        name: 'workstation-design',
        platform: 'ubuntu',
        host: '192.168.1.102',
        cpu_count: 8,
        memory_mb: 32768,
        disk_size_gb: 1024,
        operating_system: 'Ubuntu 23.04',
        power_state: 'running',
        created_at: '2024-01-19T14:20:00Z',
        ip_address: '192.168.1.102'
      }
    ]);

    setBackupJobs([
      {
        id: 1,
        name: 'Daily Web Server Backup',
        description: 'Automated daily backup of web server',
        vm_id: 'vm-001',
        platform: 'vmware',
        backup_type: 'incremental',
        schedule_cron: '0 2 * * *',
        status: 'completed',
        last_run: '2024-01-20T02:00:00Z',
        next_run: '2024-01-21T02:00:00Z',
        created_at: '2024-01-15T10:30:00Z'
      },
      {
        id: 2,
        name: 'Weekly Mail Server Backup',
        description: 'Weekly full backup of mail server',
        vm_id: '100',
        platform: 'proxmox',
        backup_type: 'full',
        schedule_cron: '0 3 * * 0',
        status: 'running',
        last_run: '2024-01-14T03:00:00Z',
        next_run: '2024-01-21T03:00:00Z',
        created_at: '2024-01-10T14:20:00Z'
      },
      {
        id: 3,
        name: 'Ubuntu Laptop Sync',
        description: 'Daily sync of development laptop',
        vm_id: 'ubuntu-192.168.1.101',
        platform: 'ubuntu',
        backup_type: 'incremental',
        schedule_cron: '0 1 * * *',
        status: 'pending',
        last_run: '2024-01-19T01:00:00Z',
        next_run: '2024-01-21T01:00:00Z',
        created_at: '2024-01-18T11:45:00Z'
      }
    ]);
  };

  const handleConnectPlatform = async (platform: string, connectionData: any) => {
    setLoading(true);
    try {
      if (platform === 'ubuntu') {
        await api.connectUbuntuMachine(connectionData);
      } else {
        await api.connectPlatform(platform, connectionData);
      }
      
      if (platform === 'ubuntu') {
        const machines = await api.getVMs('ubuntu');
        setUbuntuMachines(prev => [...prev, ...machines]);
      } else {
        const platformVMs = await api.getVMs(platform);
        setVMs(prev => [...prev, ...platformVMs]);
      }
      
      alert(`Successfully connected to ${platform}`);
    } catch (error) {
      console.error('Failed to connect:', error);
      alert(`Failed to connect to ${platform}`);
    } finally {
      setLoading(false);
    }
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
    if (confirm('Are you sure you want to delete this backup job?')) {
      try {
        await api.deleteBackupJob(jobId);
        setBackupJobs(prev => prev.filter(job => job.id !== jobId));
        alert('Backup job deleted successfully');
      } catch (error) {
        console.error('Failed to delete backup job:', error);
        alert('Failed to delete backup job');
      }
    }
  };

  const handleUbuntuMachineConnect = (machine: any) => {
    setSelectedMachine(machine);
    setShowUbuntuConnection(true);
  };

  const tabs = [
    { id: 'dashboard', label: 'COMMAND CENTER', icon: <Terminal size={20} /> },
    { id: 'vms', label: 'VIRTUAL MACHINES', icon: <Server size={20} /> },
    { id: 'ubuntu', label: 'UBUNTU MACHINES', icon: <Monitor size={20} /> },
    { id: 'jobs', label: 'BACKUP OPERATIONS', icon: <Shield size={20} /> },
    { id: 'platforms', label: 'PLATFORM CONTROL', icon: <Settings size={20} /> },
  ];

  return (
    <AuthProvider>
      <AuthGuard>
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900">
          <div className="fixed inset-0 opacity-10">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(6,182,212,0.1),transparent_70%)]"></div>
            <div className="absolute inset-0 bg-[conic-gradient(from_0deg_at_50%_50%,transparent_0deg,rgba(6,182,212,0.05)_60deg,transparent_120deg)]"></div>
          </div>

          <div className="relative z-10">
            <header className="border-b border-cyan-500 border-opacity-30 bg-gray-900 bg-opacity-80 backdrop-blur-sm">
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between items-center h-16">
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-3">
                      <Shield className="text-cyan-400" size={32} />
                      <div>
                        <h1 className="text-xl font-bold text-white uppercase tracking-wider">VM BACKUP SOLUTION</h1>
                        <p className="text-cyan-400 text-xs font-mono">ENTERPRISE PROTECTION SYSTEM</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-6">
                    <div className="flex items-center space-x-3">
                      <StatusIndicator status="online" />
                      <span className="text-cyan-400 text-sm font-mono">SYSTEM ONLINE</span>
                    </div>
                    <div className="text-cyan-400 font-mono text-sm">
                      {new Date().toLocaleTimeString()}
                    </div>
                    {user && (
                      <div className="flex items-center space-x-3">
                        <div className="text-right">
                          <div className="text-white text-sm font-medium">{user.full_name}</div>
                          <div className="text-cyan-400 text-xs uppercase">{user.role}</div>
                        </div>
                        <GlowButton onClick={logout} size="sm" variant="secondary">
                          <LogOut size={16} />
                        </GlowButton>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </header>

            <nav className="bg-gray-900 bg-opacity-60 border-b border-cyan-500 border-opacity-20">
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex space-x-8">
                  {tabs.map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id as any)}
                      className={`flex items-center space-x-2 py-4 px-2 border-b-2 font-mono text-sm uppercase tracking-wider transition-all duration-200 ${
                        activeTab === tab.id
                          ? 'border-cyan-400 text-cyan-400 bg-cyan-400 bg-opacity-10'
                          : 'border-transparent text-gray-400 hover:text-cyan-300 hover:border-cyan-500 hover:border-opacity-50'
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
                    <MetricDisplay
                      title="Protected VMs"
                      value={stats.total_vms_protected.toString()}
                      icon={<Server />}
                      trend="+3 this week"
                      trendDirection="up"
                    />
                    <MetricDisplay
                      title="Active Jobs"
                      value={stats.total_backup_jobs.toString()}
                      icon={<Shield />}
                      trend="2 running"
                      trendDirection="stable"
                    />
                    <MetricDisplay
                      title="Storage Used"
                      value={stats.total_backups_size}
                      icon={<HardDrive />}
                      trend="+120GB today"
                      trendDirection="up"
                    />
                    <MetricDisplay
                      title="Success Rate"
                      value={stats.success_rate}
                      icon={<CheckCircle />}
                      trend="99.2% uptime"
                      trendDirection="up"
                    />
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <FuturisticCard>
                      <h3 className="text-cyan-400 font-mono uppercase tracking-wider text-lg mb-4">SYSTEM STATUS</h3>
                      <div className="space-y-3">
                        <div className="flex justify-between items-center">
                          <span className="text-gray-300">Backup Engine</span>
                          <StatusIndicator status="online" />
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-gray-300">Database Connection</span>
                          <StatusIndicator status="online" />
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-gray-300">Scheduler Service</span>
                          <StatusIndicator status="online" />
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-gray-300">Ubuntu Connector</span>
                          <StatusIndicator status="online" />
                        </div>
                      </div>
                    </FuturisticCard>

                    <FuturisticCard>
                      <h3 className="text-cyan-400 font-mono uppercase tracking-wider text-lg mb-4">RECENT ACTIVITY</h3>
                      <div className="space-y-3">
                        <div className="flex items-start space-x-3">
                          <CheckCircle className="text-green-400 mt-1" size={16} />
                          <div>
                            <p className="text-white text-sm">web-server-01 backup completed</p>
                            <p className="text-gray-400 text-xs font-mono">2 hours ago</p>
                          </div>
                        </div>
                        <div className="flex items-start space-x-3">
                          <RefreshCw className="text-cyan-400 mt-1 animate-spin" size={16} />
                          <div>
                            <p className="text-white text-sm">mail-server backup in progress</p>
                            <p className="text-gray-400 text-xs font-mono">Running</p>
                          </div>
                        </div>
                        <div className="flex items-start space-x-3">
                          <Monitor className="text-orange-400 mt-1" size={16} />
                          <div>
                            <p className="text-white text-sm">Ubuntu laptop sync scheduled</p>
                            <p className="text-gray-400 text-xs font-mono">In 3 hours</p>
                          </div>
                        </div>
                      </div>
                    </FuturisticCard>
                  </div>
                </div>
              )}

              {activeTab === 'vms' && (
                <div className="space-y-6">
                  <div className="flex justify-between items-center">
                    <h2 className="text-2xl font-bold text-white uppercase tracking-wider font-mono">
                      VIRTUAL MACHINES
                    </h2>
                    <div className="flex space-x-3">
                      <GlowButton variant="secondary">
                        <RefreshCw size={16} className="mr-2" />
                        Scan Networks
                      </GlowButton>
                      <GlowButton variant="primary">
                        <Plus size={16} className="mr-2" />
                        Add VM
                      </GlowButton>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {vms.map((vm) => (
                      <VMCard key={vm.id} vm={vm} onBackup={handleBackupVM} />
                    ))}
                  </div>
                </div>
              )}

              {activeTab === 'ubuntu' && (
                <div className="space-y-6">
                  <div className="flex justify-between items-center">
                    <h2 className="text-2xl font-bold text-white uppercase tracking-wider font-mono">
                      UBUNTU MACHINES
                    </h2>
                    <div className="flex space-x-3">
                      <GlowButton variant="secondary">
                        <RefreshCw size={16} className="mr-2" />
                        Refresh
                      </GlowButton>
                      <GlowButton variant="primary">
                        <Search size={16} className="mr-2" />
                        Discover
                      </GlowButton>
                    </div>
                  </div>

                  <UbuntuDiscovery onMachineConnect={handleUbuntuMachineConnect} />
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {ubuntuMachines.map((machine) => (
                      <VMCard key={machine.id} vm={machine} onBackup={handleBackupVM} />
                    ))}
                  </div>

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
                    <h2 className="text-2xl font-bold text-white uppercase tracking-wider font-mono">
                      BACKUP OPERATIONS
                    </h2>
                    <div className="flex space-x-3">
                      <GlowButton variant="secondary">
                        <RefreshCw size={16} className="mr-2" />
                        Refresh
                      </GlowButton>
                      <GlowButton variant="primary">
                        <Plus size={16} className="mr-2" />
                        New Operation
                      </GlowButton>
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
                  <h2 className="text-2xl font-bold text-white uppercase tracking-wider font-mono">
                    PLATFORM CONTROL
                  </h2>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <PlatformConnector platform="vmware" onConnect={handleConnectPlatform} />
                    <PlatformConnector platform="proxmox" onConnect={handleConnectPlatform} />
                    <PlatformConnector platform="xcpng" onConnect={handleConnectPlatform} />
                    <PlatformConnector platform="ubuntu" onConnect={handleConnectPlatform} />
                  </div>
                </div>
              )}
            </main>
          </div>
        </div>
      </AuthGuard>
    </AuthProvider>
  );
};

export default VMBackupDashboard;
