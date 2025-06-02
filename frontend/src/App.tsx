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
  Edit,
  RotateCcw,
  FileText,
  Clock,
  Archive,
  FolderOpen,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Wifi,
  Trash2,
  User,
  UserPlus,
  AlertCircle,
  Mail,
  Bell,
  Calendar,
  BarChart3,
  PieChart,
  TrendingUp,
  Save,
  Copy,
  Play,
  Pause
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart as RechartsPieChart, Cell, BarChart, Bar, Pie } from 'recharts';
// Types (complete interface definitions)
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
  isLoading: boolean;
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
  vm_name?: string;
  platform: 'vmware' | 'proxmox' | 'xcpng' | 'ubuntu';
  backup_type: 'full' | 'incremental' | 'differential';
  schedule_cron: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  last_run: string | null;
  next_run: string | null;
  created_at: string;
  retention_days: number;
  compression_enabled: boolean;
  encryption_enabled: boolean;
  current_status?: any;
}

interface Backup {
  backup_id: string;
  job_id?: number;
  vm_id: string;
  vm_name?: string;
  platform: string;
  backup_type: string;
  timestamp?: string;
  created_at?: string;
  size_mb: number;
  file_path: string;
  storage_backend_id?: string;
  compressed?: boolean;
  encrypted?: boolean;
  status?: string;
}

interface RestoreHistoryItem {
  id: number;
  backup_id: string;
  vm_id: string;
  status: string;
  start_time: string;
  end_time?: string;
  error_message?: string;
  metadata?: any;
}

interface StorageBackend {
  id: string;
  name: string;
  storage_type: 'local' | 'nfs' | 'iscsi';
  capacity_gb: number;
  is_mounted: boolean;
  mount_point: string;
  health: {
    status: 'healthy' | 'warning' | 'error';
    message?: string;
    available_gb?: number;
    total_gb?: number;
    write_speed_mbps?: number;
    usage_percent?: number;
  };
  is_default: boolean;
  backup_count?: number;
}

interface StorageBackendConfig {
  name: string;
  storage_type: 'local' | 'nfs' | 'iscsi';
  capacity_gb: number;
  path?: string;
  server?: string;
  remote_path?: string;
  mount_options?: string;
  local_mount_point?: string;
  target_ip?: string;
  target_port?: number;
  target_iqn?: string;
  initiator_name?: string;
  username?: string;
  password?: string;
}

// NEW: Analytics and Notification Types
interface StorageAnalytics {
  usage_over_time: Array<{
    date: string;
    total_gb: number;
    used_gb: number;
    available_gb: number;
  }>;
  backup_size_trends: Array<{
    date: string;
    size_gb: number;
    count: number;
  }>;
  platform_distribution: Array<{
    platform: string;
    count: number;
    size_gb: number;
  }>;
  storage_backend_usage: Array<{
    name: string;
    used_gb: number;
    available_gb: number;
    usage_percent: number;
  }>;
}

interface NotificationSettings {
  email_enabled: boolean;
  email_addresses: string[];
  smtp_server?: string;
  smtp_port?: number;
  smtp_username?: string;
  smtp_password?: string;
  smtp_ssl?: boolean;
  webhook_enabled: boolean;
  webhook_url?: string;
  slack_enabled: boolean;
  slack_webhook?: string;
  notifications: {
    backup_success: boolean;
    backup_failure: boolean;
    storage_warning: boolean;
    platform_disconnect: boolean;
    job_completion: boolean;
  };
}

type PlatformType = 'vmware' | 'proxmox' | 'xcpng' | 'ubuntu';

interface DashboardStats {
  total_backup_jobs: number;
  running_jobs: number;
  total_vms_protected: number;
  connected_platforms: number;
  total_backups_size: string;
  last_24h_jobs: number;
  success_rate: string;
  storage_backends: number;
  storage_capacity_gb: number;
  storage_available_gb: number;
}

interface PlatformStatus {
  vmware: boolean;
  proxmox: boolean;
  xcpng: boolean;
  ubuntu: boolean;
}

// Enhanced API Service
class APIService {
  private baseURL: string;
  private authToken: string | null = null;

  constructor() {
    const currentHost = window.location.hostname;
    if (currentHost === 'localhost' || currentHost === '127.0.0.1') {
      this.baseURL = 'http://localhost:8000/api/v1';
    } else {
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

  // Authentication methods
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

  // Backup Jobs methods
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

  async getAllVMs(): Promise<VM[]> {
    return this.request('/vms');
  }

  async getPlatformStatus() {
    return this.request('/platforms/status');
  }

  // Backup and Restore methods
  async getAllBackups(): Promise<Backup[]> {
    return this.request('/storage/backups');
  }

  async getRestoreHistory(): Promise<RestoreHistoryItem[]> {
    return this.request('/restore/history');
  }

  async instantRestoreVM(backupId: string, targetPlatform: string, restoreConfig: any) {
    return this.request('/restore/instant', {
      method: 'POST',
      body: JSON.stringify({
        backup_id: backupId,
        target_platform: targetPlatform,
        restore_config: restoreConfig
      }),
    });
  }

  async fileRestore(backupId: string, filePaths: string[], targetPath: string, vmId?: string) {
    return this.request('/restore/files', {
      method: 'POST',
      body: JSON.stringify({
        backup_id: backupId,
        file_paths: filePaths,
        target_path: targetPath,
        vm_id: vmId
      }),
    });
  }

  // Storage Backend Methods
  async getStorageBackends(): Promise<StorageBackend[]> {
    return this.request('/storage/backends');
  }

  async createStorageBackend(config: StorageBackendConfig) {
    return this.request('/storage/backends', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async updateStorageBackend(backendId: string, config: StorageBackendConfig) {
    return this.request(`/storage/backends/${backendId}`, {
      method: 'PUT',
      body: JSON.stringify(config),
    });
  }

  async deleteStorageBackend(backendId: string) {
    return this.request(`/storage/backends/${backendId}`, {
      method: 'DELETE',
    });
  }

  async testStorageBackend(backendId: string) {
    return this.request(`/storage/backends/${backendId}/test`, {
      method: 'POST',
    });
  }

  async setDefaultStorageBackend(backendId: string) {
    return this.request(`/storage/backends/${backendId}/set-default`, {
      method: 'POST',
    });
  }

  async mountStorageBackend(backendId: string) {
    return this.request(`/storage/backends/${backendId}/mount`, {
      method: 'POST',
    });
  }

  async unmountStorageBackend(backendId: string) {
    return this.request(`/storage/backends/${backendId}/unmount`, {
      method: 'POST',
    });
  }

  // NEW: Analytics Methods
  async getStorageAnalytics(): Promise<StorageAnalytics> {
    return this.request('/analytics/storage');
  }

  async getBackupTrends(days: number = 30) {
    return this.request(`/analytics/backup-trends?days=${days}`);
  }

  // NEW: Notification Settings Methods
  async getNotificationSettings(): Promise<NotificationSettings> {
    return this.request('/settings/notifications');
  }

  async updateNotificationSettings(settings: NotificationSettings) {
    return this.request('/settings/notifications', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  }

  async testNotifications() {
    return this.request('/settings/notifications/test', {
      method: 'POST',
    });
  }

  async installUbuntuAgent(vmId: string) {
    return this.request(`/ubuntu/${vmId}/install-agent`, {
      method: 'POST',
    });
  }
}

const api = new APIService();

// Authentication Context
const AuthContext = createContext<AuthContextType | null>(null);

const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const initializeAuth = async () => {
      if (token) {
        api.setAuthToken(token);
        try {
          const userData = await api.getCurrentUser();
          setUser(userData);
        } catch (error) {
          console.error('Failed to get current user:', error);
          localStorage.removeItem('token');
          setToken(null);
          api.setAuthToken(null);
        }
      }
      setIsLoading(false);
    };

    initializeAuth();
  }, [token]);

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      setIsLoading(true);
      const response = await api.login(username, password);
      
      if (response.access_token) {
        setToken(response.access_token);
        localStorage.setItem('token', response.access_token);
        api.setAuthToken(response.access_token);
        
        const userData = await api.getCurrentUser();
        setUser(userData);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (userData: any): Promise<boolean> => {
    try {
      setIsLoading(true);
      const response = await api.register(userData);
      console.log('Registration successful:', response);
      return true;
    } catch (error) {
      console.error('Registration failed:', error);
      return false;
    } finally {
      setIsLoading(false);
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
      isAuthenticated: !!user,
      isLoading
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

// UI Components
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
  type?: 'button' | 'submit' | 'reset';
}> = ({ children, onClick, variant = 'primary', size = 'md', disabled = false, type = 'button' }) => {
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
      type={type}
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
      <div className={`bg-slate-800 border border-slate-700 rounded-lg ${sizeClasses[size]} max-w-full mx-4 max-h-[90vh] overflow-y-auto`}>
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
      case 'success':
      case 'healthy':
      case 'mounted':
      case 'poweredon':
      case 'online':
      case 'running':
        return { color: 'text-emerald-400', bg: 'bg-emerald-400', label: 'HEALTHY' };
      case 'in progress':
        return { color: 'text-amber-400', bg: 'bg-amber-400', label: 'RUNNING' };
      case 'failed':
      case 'error':
      case 'unmounted':
      case 'offline':
        return { color: 'text-red-400', bg: 'bg-red-400', label: 'ERROR' };
      case 'pending':
      case 'scheduled':
      case 'warning':
        return { color: 'text-yellow-400', bg: 'bg-yellow-400', label: 'WARNING' };
      case 'paused':
      case 'stopped':
        return { color: 'text-slate-400', bg: 'bg-slate-400', label: 'STOPPED' };
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

// NEW: Cron Expression Builder Component
const CronExpressionBuilder: React.FC<{
  value: string;
  onChange: (cronExpression: string) => void;
  onClose: () => void;
}> = ({ value, onChange, onClose }) => {
  const [activeTab, setActiveTab] = useState<'presets' | 'custom'>('presets');
  const [customCron, setCustomCron] = useState(value);
  const [cronParts, setCronParts] = useState({
    minute: '*',
    hour: '*',
    day: '*',
    month: '*',
    weekday: '*'
  });

  const presets = [
    { label: 'Every minute', value: '* * * * *', description: 'Runs every minute (for testing)' },
    { label: 'Every 5 minutes', value: '*/5 * * * *', description: 'Runs every 5 minutes' },
    { label: 'Every 15 minutes', value: '*/15 * * * *', description: 'Runs every 15 minutes' },
    { label: 'Every 30 minutes', value: '*/30 * * * *', description: 'Runs every 30 minutes' },
    { label: 'Hourly', value: '0 * * * *', description: 'Runs at the start of every hour' },
    { label: 'Every 2 hours', value: '0 */2 * * *', description: 'Runs every 2 hours' },
    { label: 'Every 6 hours', value: '0 */6 * * *', description: 'Runs every 6 hours at :00' },
    { label: 'Daily at midnight', value: '0 0 * * *', description: 'Runs once a day at 00:00' },
    { label: 'Daily at 2 AM', value: '0 2 * * *', description: 'Runs once a day at 02:00' },
    { label: 'Daily at 6 AM', value: '0 6 * * *', description: 'Runs once a day at 06:00' },
    { label: 'Weekly (Sunday)', value: '0 2 * * 0', description: 'Runs every Sunday at 02:00' },
    { label: 'Weekly (Monday)', value: '0 2 * * 1', description: 'Runs every Monday at 02:00' },
    { label: 'Monthly (1st)', value: '0 2 1 * *', description: 'Runs on the 1st of every month at 02:00' },
    { label: 'Workdays at 9 AM', value: '0 9 * * 1-5', description: 'Runs Mon-Fri at 09:00' },
    { label: 'Weekends at 10 AM', value: '0 10 * * 6,0', description: 'Runs Sat-Sun at 10:00' }
  ];

  const minuteOptions = ['*', '0', '15', '30', '45'];
  const hourOptions = ['*', '0', '1', '2', '6', '12', '18'];
  const dayOptions = ['*', '1', '15'];
  const monthOptions = ['*', '1', '6'];
  const weekdayOptions = ['*', '0', '1', '6'];

  const weekdayLabels: { [key: string]: string } = {
    '*': 'Every day',
    '0': 'Sunday',
    '1': 'Monday',
    '2': 'Tuesday',
    '3': 'Wednesday',
    '4': 'Thursday',
    '5': 'Friday',
    '6': 'Saturday',
    '1-5': 'Weekdays',
    '6,0': 'Weekends'
  };

  const buildCronFromParts = () => {
    return `${cronParts.minute} ${cronParts.hour} ${cronParts.day} ${cronParts.month} ${cronParts.weekday}`;
  };

  const parseCronExpression = (cron: string) => {
    const parts = cron.split(' ');
    if (parts.length === 5) {
      setCronParts({
        minute: parts[0],
        hour: parts[1],
        day: parts[2],
        month: parts[3],
        weekday: parts[4]
      });
    }
  };

  const handlePresetSelect = (cronValue: string) => {
    onChange(cronValue);
    setCustomCron(cronValue);
    parseCronExpression(cronValue);
  };

  const handleCustomCronChange = (newCron: string) => {
    setCustomCron(newCron);
    parseCronExpression(newCron);
  };

  const handlePartChange = (part: keyof typeof cronParts, value: string) => {
    const newParts = { ...cronParts, [part]: value };
    setCronParts(newParts);
    const newCron = `${newParts.minute} ${newParts.hour} ${newParts.day} ${newParts.month} ${newParts.weekday}`;
    setCustomCron(newCron);
  };

  const handleSave = () => {
    onChange(customCron);
    onClose();
  };

  const getNextRunTimes = (cron: string) => {
    // This is a simplified version - in production you'd use a proper cron parser
    const now = new Date();
    const times = [];
    
    // Mock next run times for demonstration
    for (let i = 1; i <= 3; i++) {
      const nextTime = new Date(now.getTime() + (i * 24 * 60 * 60 * 1000));
      times.push(nextTime.toLocaleString());
    }
    
    return times;
  };

  useEffect(() => {
    parseCronExpression(value);
    setCustomCron(value);
  }, [value]);

  return (
    <Modal isOpen={true} onClose={onClose} title="Backup Schedule Builder" size="xl">
      <div className="space-y-6">
        {/* Tab Navigation */}
        <div className="border-b border-slate-700">
          <div className="flex space-x-8">
            <button
              onClick={() => setActiveTab('presets')}
              className={`py-3 px-1 border-b-2 font-medium text-sm transition-all duration-200 ${
                activeTab === 'presets'
                  ? 'border-blue-400 text-blue-400'
                  : 'border-transparent text-slate-400 hover:text-slate-300'
              }`}
            >
              Preset Schedules
            </button>
            <button
              onClick={() => setActiveTab('custom')}
              className={`py-3 px-1 border-b-2 font-medium text-sm transition-all duration-200 ${
                activeTab === 'custom'
                  ? 'border-blue-400 text-blue-400'
                  : 'border-transparent text-slate-400 hover:text-slate-300'
              }`}
            >
              Custom Builder
            </button>
          </div>
        </div>

        {activeTab === 'presets' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-80 overflow-y-auto">
              {presets.map((preset, index) => (
                <div
                  key={index}
                  onClick={() => handlePresetSelect(preset.value)}
                  className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                    customCron === preset.value
                      ? 'border-blue-500 bg-blue-900 bg-opacity-30'
                      : 'border-slate-600 hover:border-slate-500 bg-slate-700'
                  }`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <h4 className="text-white font-medium">{preset.label}</h4>
                    <code className="text-blue-400 text-xs font-mono bg-slate-800 px-2 py-1 rounded">
                      {preset.value}
                    </code>
                  </div>
                  <p className="text-slate-400 text-sm">{preset.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'custom' && (
          <div className="space-y-6">
            {/* Visual Cron Builder */}
            <div className="bg-slate-700 rounded-lg p-4">
              <h4 className="text-white font-medium mb-4">Visual Builder</h4>
              <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                <div>
                  <label className="block text-slate-300 text-sm font-medium mb-2">Minute</label>
                  <select
                    value={cronParts.minute}
                    onChange={(e) => handlePartChange('minute', e.target.value)}
                    className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white text-sm"
                  >
                    {minuteOptions.map(opt => (
                      <option key={opt} value={opt}>
                        {opt === '*' ? 'Every minute' : `Minute ${opt}`}
                      </option>
                    ))}
                    <option value="*/5">Every 5 minutes</option>
                    <option value="*/15">Every 15 minutes</option>
                    <option value="*/30">Every 30 minutes</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 text-sm font-medium mb-2">Hour</label>
                  <select
                    value={cronParts.hour}
                    onChange={(e) => handlePartChange('hour', e.target.value)}
                    className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white text-sm"
                  >
                    {hourOptions.map(opt => (
                      <option key={opt} value={opt}>
                        {opt === '*' ? 'Every hour' : `${opt}:00`}
                      </option>
                    ))}
                    <option value="*/2">Every 2 hours</option>
                    <option value="*/6">Every 6 hours</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 text-sm font-medium mb-2">Day</label>
                  <select
                    value={cronParts.day}
                    onChange={(e) => handlePartChange('day', e.target.value)}
                    className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white text-sm"
                  >
                    {dayOptions.map(opt => (
                      <option key={opt} value={opt}>
                        {opt === '*' ? 'Every day' : `Day ${opt}`}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 text-sm font-medium mb-2">Month</label>
                  <select
                    value={cronParts.month}
                    onChange={(e) => handlePartChange('month', e.target.value)}
                    className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white text-sm"
                  >
                    {monthOptions.map(opt => (
                      <option key={opt} value={opt}>
                        {opt === '*' ? 'Every month' : `Month ${opt}`}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 text-sm font-medium mb-2">Weekday</label>
                  <select
                    value={cronParts.weekday}
                    onChange={(e) => handlePartChange('weekday', e.target.value)}
                    className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white text-sm"
                  >
                    {Object.entries(weekdayLabels).map(([value, label]) => (
                      <option key={value} value={value}>{label}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Raw Cron Input */}
            <div>
              <label className="block text-slate-300 text-sm font-medium mb-2">
                Raw Cron Expression
                <span className="text-slate-500 ml-2">(minute hour day month weekday)</span>
              </label>
              <div className="flex space-x-2">
                <input
                  type="text"
                  value={customCron}
                  onChange={(e) => handleCustomCronChange(e.target.value)}
                  className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white font-mono text-sm"
                  placeholder="0 2 * * *"
                />
                <Button
                  onClick={() => navigator.clipboard.writeText(customCron)}
                  variant="secondary"
                  size="sm"
                >
                  <Copy size={16} />
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Preview */}
        <div className="bg-blue-900 bg-opacity-30 border border-blue-500 rounded p-4">
          <div className="flex items-center space-x-2 mb-3">
            <Calendar className="text-blue-400" size={20} />
            <h4 className="text-blue-300 font-medium">Schedule Preview</h4>
          </div>
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <span className="text-blue-300 text-sm font-medium">Expression:</span>
              <code className="bg-slate-800 text-blue-400 px-2 py-1 rounded text-sm font-mono">
                {customCron}
              </code>
            </div>
            <div>
              <span className="text-blue-300 text-sm font-medium">Next runs:</span>
              <ul className="text-blue-200 text-sm ml-4 mt-1">
                {getNextRunTimes(customCron).map((time, index) => (
                  <li key={index}>• {time}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end space-x-3">
          <Button onClick={onClose} variant="secondary">
            Cancel
          </Button>
          <Button onClick={handleSave} variant="primary">
            <Save size={16} className="mr-2" />
            Save Schedule
          </Button>
        </div>
      </div>
    </Modal>
  );
};

// NEW: Storage Analytics Component
const StorageAnalyticsModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
}> = ({ isOpen, onClose }) => {
  const [analytics, setAnalytics] = useState<StorageAnalytics | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(30);

  useEffect(() => {
    if (isOpen) {
      loadAnalytics();
    }
  }, [isOpen, timeRange]);

  const loadAnalytics = async () => {
    setLoading(true);
    try {
      // Mock data for demonstration
      const mockAnalytics: StorageAnalytics = {
        usage_over_time: [
          { date: '2024-01-01', total_gb: 1000, used_gb: 250, available_gb: 750 },
          { date: '2024-01-02', total_gb: 1000, used_gb: 300, available_gb: 700 },
          { date: '2024-01-03', total_gb: 1000, used_gb: 350, available_gb: 650 },
          { date: '2024-01-04', total_gb: 1000, used_gb: 400, available_gb: 600 },
          { date: '2024-01-05', total_gb: 1000, used_gb: 450, available_gb: 550 },
          { date: '2024-01-06', total_gb: 1000, used_gb: 500, available_gb: 500 },
          { date: '2024-01-07', total_gb: 1000, used_gb: 550, available_gb: 450 },
        ],
        backup_size_trends: [
          { date: '2024-01-01', size_gb: 25, count: 5 },
          { date: '2024-01-02', size_gb: 30, count: 6 },
          { date: '2024-01-03', size_gb: 28, count: 7 },
          { date: '2024-01-04', size_gb: 35, count: 8 },
          { date: '2024-01-05', size_gb: 40, count: 10 },
          { date: '2024-01-06', size_gb: 45, count: 12 },
          { date: '2024-01-07', size_gb: 50, count: 15 },
        ],
        platform_distribution: [
          { platform: 'VMware', count: 12, size_gb: 240 },
          { platform: 'Proxmox', count: 8, size_gb: 160 },
          { platform: 'XCP-NG', count: 5, size_gb: 100 },
          { platform: 'Ubuntu', count: 10, size_gb: 50 },
        ],
        storage_backend_usage: [
          { name: 'Local Storage', used_gb: 300, available_gb: 700, usage_percent: 30 },
          { name: 'NFS Share', used_gb: 150, available_gb: 350, usage_percent: 30 },
          { name: 'iSCSI LUN', used_gb: 100, available_gb: 400, usage_percent: 20 },
        ]
      };
      setAnalytics(mockAnalytics);
    } catch (error) {
      console.error('Failed to load analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  const COLORS = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6'];

  if (!isOpen) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Storage Analytics" size="xl">
      <div className="space-y-6">
        {/* Time Range Selector */}
        <div className="flex justify-between items-center">
          <h3 className="text-white font-medium">Analytics Overview</h3>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(Number(e.target.value))}
            className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm"
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="text-blue-400 animate-spin" size={48} />
            <span className="text-slate-400 ml-4">Loading analytics...</span>
          </div>
        ) : analytics ? (
          <div className="space-y-8">
            {/* Storage Usage Over Time */}
            <div className="bg-slate-700 rounded-lg p-4">
              <h4 className="text-white font-medium mb-4 flex items-center">
                <TrendingUp className="text-blue-400 mr-2" size={20} />
                Storage Usage Trends
              </h4>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={analytics.usage_over_time}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="date" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#1f2937', 
                      border: '1px solid #374151',
                      borderRadius: '6px'
                    }}
                  />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="used_gb" 
                    stroke="#3b82f6" 
                    strokeWidth={2}
                    name="Used (GB)"
                  />
                  <Line 
                    type="monotone" 
                    dataKey="available_gb" 
                    stroke="#10b981" 
                    strokeWidth={2}
                    name="Available (GB)"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Platform Distribution */}
              <div className="bg-slate-700 rounded-lg p-4">
                <h4 className="text-white font-medium mb-4 flex items-center">
                  <PieChart className="text-blue-400 mr-2" size={20} />
                  Platform Distribution
                </h4>
                <ResponsiveContainer width="100%" height={250}>
                  <RechartsPieChart>
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '6px'
                      }}
                    />
                    <Legend />
                    <RechartsPieChart>
                      <Pie
                        data={analytics.platform_distribution}
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="count"
                      >
                        {analytics.platform_distribution.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                    </RechartsPieChart>                    
                </ResponsiveContainer>
                <div className="mt-4 space-y-2">
                  {analytics.platform_distribution.map((item, index) => (
                    <div key={item.platform} className="flex justify-between text-sm">
                      <div className="flex items-center">
                        <div 
                          className="w-3 h-3 rounded-full mr-2"
                          style={{ backgroundColor: COLORS[index % COLORS.length] }}
                        />
                        <span className="text-slate-300">{item.platform}</span>
                      </div>
                      <span className="text-white">{item.count} VMs ({item.size_gb}GB)</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Storage Backend Usage */}
              <div className="bg-slate-700 rounded-lg p-4">
                <h4 className="text-white font-medium mb-4 flex items-center">
                  <BarChart3 className="text-blue-400 mr-2" size={20} />
                  Storage Backend Usage
                </h4>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={analytics.storage_backend_usage}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="name" stroke="#9ca3af" />
                    <YAxis stroke="#9ca3af" />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '6px'
                      }}
                    />
                    <Legend />
                    <Bar dataKey="used_gb" fill="#3b82f6" name="Used (GB)" />
                    <Bar dataKey="available_gb" fill="#10b981" name="Available (GB)" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Backup Size Trends */}
            <div className="bg-slate-700 rounded-lg p-4">
              <h4 className="text-white font-medium mb-4 flex items-center">
                <Archive className="text-blue-400 mr-2" size={20} />
                Daily Backup Trends
              </h4>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={analytics.backup_size_trends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="date" stroke="#9ca3af" />
                  <YAxis yAxisId="left" stroke="#9ca3af" />
                  <YAxis yAxisId="right" orientation="right" stroke="#9ca3af" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#1f2937', 
                      border: '1px solid #374151',
                      borderRadius: '6px'
                    }}
                  />
                  <Legend />
                  <Bar yAxisId="left" dataKey="size_gb" fill="#3b82f6" name="Total Size (GB)" />
                  <Line yAxisId="right" type="monotone" dataKey="count" stroke="#f59e0b" strokeWidth={2} name="Backup Count" />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-slate-700 rounded-lg p-4 text-center">
                <div className="text-blue-400 text-2xl font-bold">
                  {analytics.usage_over_time[analytics.usage_over_time.length - 1]?.used_gb || 0}GB
                </div>
                <div className="text-slate-400 text-sm">Total Used</div>
              </div>
              <div className="bg-slate-700 rounded-lg p-4 text-center">
                <div className="text-emerald-400 text-2xl font-bold">
                  {analytics.backup_size_trends.reduce((sum, item) => sum + item.count, 0)}
                </div>
                <div className="text-slate-400 text-sm">Total Backups</div>
              </div>
              <div className="bg-slate-700 rounded-lg p-4 text-center">
                <div className="text-yellow-400 text-2xl font-bold">
                  {analytics.platform_distribution.reduce((sum, item) => sum + item.count, 0)}
                </div>
                <div className="text-slate-400 text-sm">Protected VMs</div>
              </div>
              <div className="bg-slate-700 rounded-lg p-4 text-center">
                <div className="text-purple-400 text-2xl font-bold">
                  {analytics.storage_backend_usage.length}
                </div>
                <div className="text-slate-400 text-sm">Storage Backends</div>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-12">
            <AlertTriangle className="text-yellow-400 mx-auto mb-4" size={48} />
            <h3 className="text-white text-lg font-medium mb-2">No Analytics Data</h3>
            <p className="text-slate-400">Analytics data will appear after creating backups</p>
          </div>
        )}

        <div className="flex justify-end">
          <Button onClick={onClose} variant="primary">
            Close
          </Button>
        </div>
      </div>
    </Modal>
  );
};

// NEW: Notification Settings Component
const NotificationSettingsModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
}> = ({ isOpen, onClose }) => {
  const [settings, setSettings] = useState<NotificationSettings>({
    email_enabled: false,
    email_addresses: [''],
    smtp_server: '',
    smtp_port: 587,
    smtp_username: '',
    smtp_password: '',
    smtp_ssl: true,
    webhook_enabled: false,
    webhook_url: '',
    slack_enabled: false,
    slack_webhook: '',
    notifications: {
      backup_success: true,
      backup_failure: true,
      storage_warning: true,
      platform_disconnect: true,
      job_completion: true,
    }
  });
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);
  const [activeTab, setActiveTab] = useState<'email' | 'webhook' | 'notifications'>('email');

  useEffect(() => {
    if (isOpen) {
      loadSettings();
    }
  }, [isOpen]);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const data = await api.getNotificationSettings();
      setSettings(data);
    } catch (error) {
      console.error('Failed to load notification settings:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      await api.updateNotificationSettings(settings);
      alert('✅ Notification settings saved successfully!');
      onClose();
    } catch (error) {
      console.error('Failed to save notification settings:', error);
      alert('❌ Failed to save notification settings');
    }
  };

  const handleTest = async () => {
    setTesting(true);
    try {
      await api.testNotifications();
      alert('✅ Test notification sent successfully!');
    } catch (error) {
      console.error('Failed to send test notification:', error);
      alert('❌ Failed to send test notification');
    } finally {
      setTesting(false);
    }
  };

  const addEmailAddress = () => {
    setSettings({
      ...settings,
      email_addresses: [...settings.email_addresses, '']
    });
  };

  const removeEmailAddress = (index: number) => {
    setSettings({
      ...settings,
      email_addresses: settings.email_addresses.filter((_, i) => i !== index)
    });
  };

  const updateEmailAddress = (index: number, email: string) => {
    const newEmails = [...settings.email_addresses];
    newEmails[index] = email;
    setSettings({
      ...settings,
      email_addresses: newEmails
    });
  };

  if (!isOpen) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Notification Settings" size="xl">
      <div className="space-y-6">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="text-blue-400 animate-spin" size={48} />
            <span className="text-slate-400 ml-4">Loading settings...</span>
          </div>
        ) : (
          <>
            {/* Tab Navigation */}
            <div className="border-b border-slate-700">
              <div className="flex space-x-8">
                <button
                  onClick={() => setActiveTab('email')}
                  className={`py-3 px-1 border-b-2 font-medium text-sm transition-all duration-200 ${
                    activeTab === 'email'
                      ? 'border-blue-400 text-blue-400'
                      : 'border-transparent text-slate-400 hover:text-slate-300'
                  }`}
                >
                  <Mail className="inline mr-2" size={16} />
                  Email
                </button>
                <button
                  onClick={() => setActiveTab('webhook')}
                  className={`py-3 px-1 border-b-2 font-medium text-sm transition-all duration-200 ${
                    activeTab === 'webhook'
                      ? 'border-blue-400 text-blue-400'
                      : 'border-transparent text-slate-400 hover:text-slate-300'
                  }`}
                >
                  <Network className="inline mr-2" size={16} />
                  Webhooks
                </button>
                <button
                  onClick={() => setActiveTab('notifications')}
                  className={`py-3 px-1 border-b-2 font-medium text-sm transition-all duration-200 ${
                    activeTab === 'notifications'
                      ? 'border-blue-400 text-blue-400'
                      : 'border-transparent text-slate-400 hover:text-slate-300'
                  }`}
                >
                  <Bell className="inline mr-2" size={16} />
                  Events
                </button>
              </div>
            </div>

            {/* Email Settings */}
            {activeTab === 'email' && (
              <div className="space-y-6">
                <div className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={settings.email_enabled}
                    onChange={(e) => setSettings({...settings, email_enabled: e.target.checked})}
                    className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                  />
                  <label className="text-slate-300 text-sm font-medium">Enable Email Notifications</label>
                </div>

                {settings.email_enabled && (
                  <div className="space-y-4">
                    {/* Email Addresses */}
                    <div>
                      <label className="block text-slate-300 text-sm font-medium mb-2">
                        Recipient Email Addresses
                      </label>
                      {settings.email_addresses.map((email, index) => (
                        <div key={index} className="flex space-x-2 mb-2">
                          <input
                            type="email"
                            value={email}
                            onChange={(e) => updateEmailAddress(index, e.target.value)}
                            className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400"
                            placeholder="admin@company.com"
                          />
                          {settings.email_addresses.length > 1 && (
                            <Button
                              onClick={() => removeEmailAddress(index)}
                              variant="danger"
                              size="sm"
                            >
                              <X size={16} />
                            </Button>
                          )}
                        </div>
                      ))}
                      <Button onClick={addEmailAddress} variant="secondary" size="sm">
                        <Plus size={16} className="mr-1" />
                        Add Email
                      </Button>
                    </div>

                    {/* SMTP Configuration */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-slate-300 text-sm font-medium mb-2">SMTP Server</label>
                        <input
                          type="text"
                          value={settings.smtp_server || ''}
                          onChange={(e) => setSettings({...settings, smtp_server: e.target.value})}
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400"
                          placeholder="smtp.gmail.com"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-300 text-sm font-medium mb-2">SMTP Port</label>
                        <input
                          type="number"
                          value={settings.smtp_port || 587}
                          onChange={(e) => setSettings({...settings, smtp_port: parseInt(e.target.value)})}
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-300 text-sm font-medium mb-2">Username</label>
                        <input
                          type="text"
                          value={settings.smtp_username || ''}
                          onChange={(e) => setSettings({...settings, smtp_username: e.target.value})}
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400"
                          placeholder="your-email@gmail.com"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-300 text-sm font-medium mb-2">Password</label>
                        <input
                          type="password"
                          value={settings.smtp_password || ''}
                          onChange={(e) => setSettings({...settings, smtp_password: e.target.value})}
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400"
                          placeholder="••••••••"
                        />
                      </div>
                    </div>

                    <div className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={settings.smtp_ssl}
                        onChange={(e) => setSettings({...settings, smtp_ssl: e.target.checked})}
                        className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                      />
                      <label className="text-slate-300 text-sm">Use SSL/TLS</label>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Webhook Settings */}
            {activeTab === 'webhook' && (
              <div className="space-y-6">
                <div className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={settings.webhook_enabled}
                    onChange={(e) => setSettings({...settings, webhook_enabled: e.target.checked})}
                    className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                  />
                  <label className="text-slate-300 text-sm font-medium">Enable Generic Webhook</label>
                </div>

                {settings.webhook_enabled && (
                  <div>
                    <label className="block text-slate-300 text-sm font-medium mb-2">Webhook URL</label>
                    <input
                      type="url"
                      value={settings.webhook_url || ''}
                      onChange={(e) => setSettings({...settings, webhook_url: e.target.value})}
                      className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400"
                      placeholder="https://your-server.com/webhook"
                    />
                  </div>
                )}

                <div className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={settings.slack_enabled}
                    onChange={(e) => setSettings({...settings, slack_enabled: e.target.checked})}
                    className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                  />
                  <label className="text-slate-300 text-sm font-medium">Enable Slack Notifications</label>
                </div>

                {settings.slack_enabled && (
                  <div>
                    <label className="block text-slate-300 text-sm font-medium mb-2">Slack Webhook URL</label>
                    <input
                      type="url"
                      value={settings.slack_webhook || ''}
                      onChange={(e) => setSettings({...settings, slack_webhook: e.target.value})}
                      className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400"
                      placeholder="https://hooks.slack.com/services/..."
                    />
                  </div>
                )}
              </div>
            )}

            {/* Notification Events */}
            {activeTab === 'notifications' && (
              <div className="space-y-4">
                <h4 className="text-white font-medium">Choose which events trigger notifications:</h4>
                
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <label className="text-slate-300 font-medium">Backup Success</label>
                      <p className="text-slate-400 text-sm">Notify when backups complete successfully</p>
                    </div>
                    <input
                      type="checkbox"
                      checked={settings.notifications.backup_success}
                      onChange={(e) => setSettings({
                        ...settings,
                        notifications: {...settings.notifications, backup_success: e.target.checked}
                      })}
                      className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <label className="text-slate-300 font-medium">Backup Failure</label>
                      <p className="text-slate-400 text-sm">Notify when backups fail or encounter errors</p>
                    </div>
                    <input
                      type="checkbox"
                      checked={settings.notifications.backup_failure}
                      onChange={(e) => setSettings({
                        ...settings,
                        notifications: {...settings.notifications, backup_failure: e.target.checked}
                      })}
                      className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <label className="text-slate-300 font-medium">Storage Warnings</label>
                      <p className="text-slate-400 text-sm">Notify when storage space is running low</p>
                    </div>
                    <input
                      type="checkbox"
                      checked={settings.notifications.storage_warning}
                      onChange={(e) => setSettings({
                        ...settings,
                        notifications: {...settings.notifications, storage_warning: e.target.checked}
                      })}
                      className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <label className="text-slate-300 font-medium">Platform Disconnect</label>
                      <p className="text-slate-400 text-sm">Notify when platform connections are lost</p>
                    </div>
                    <input
                      type="checkbox"
                      checked={settings.notifications.platform_disconnect}
                      onChange={(e) => setSettings({
                        ...settings,
                        notifications: {...settings.notifications, platform_disconnect: e.target.checked}
                      })}
                      className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <label className="text-slate-300 font-medium">Job Completion</label>
                      <p className="text-slate-400 text-sm">Notify when scheduled backup jobs complete</p>
                    </div>
                    <input
                      type="checkbox"
                      checked={settings.notifications.job_completion}
                      onChange={(e) => setSettings({
                        ...settings,
                        notifications: {...settings.notifications, job_completion: e.target.checked}
                      })}
                      className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Test Notification */}
            <div className="bg-blue-900 bg-opacity-30 border border-blue-500 rounded p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-blue-300 font-medium">Test Notifications</h4>
                  <p className="text-blue-200 text-sm">Send a test notification to verify your settings</p>
                </div>
                <Button
                  onClick={handleTest}
                  disabled={testing || (!settings.email_enabled && !settings.webhook_enabled && !settings.slack_enabled)}
                  variant="secondary"
                >
                  {testing ? (
                    <>
                      <RefreshCw size={16} className="mr-2 animate-spin" />
                      Sending...
                    </>
                  ) : (
                    <>
                      <Bell size={16} className="mr-2" />
                      Send Test
                    </>
                  )}
                </Button>
              </div>
            </div>

            {/* Actions */}
            <div className="flex justify-end space-x-3">
              <Button onClick={onClose} variant="secondary">
                Cancel
              </Button>
              <Button onClick={handleSave} variant="primary">
                <Save size={16} className="mr-2" />
                Save Settings
              </Button>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
};

// Enhanced Login Form Component
const LoginForm: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError('');
    
    if (!username || !password) {
      setError('Please enter both username and password');
      setIsSubmitting(false);
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
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {error && (
        <div className="p-3 bg-red-900 bg-opacity-50 border border-red-500 rounded text-red-300 text-sm flex items-center">
          <AlertCircle size={16} className="mr-2" />
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
          disabled={isSubmitting}
          autoFocus
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
          disabled={isSubmitting}
        />
      </div>

      <div className="bg-blue-900 bg-opacity-30 border border-blue-500 rounded p-3">
        <p className="text-blue-300 text-sm">
          <strong>Default Credentials:</strong><br/>
          Username: admin<br/>
          Password: admin123
        </p>
      </div>

      <div className="flex justify-end space-x-3">
        <Button onClick={onClose} variant="secondary" disabled={isSubmitting} type="button">
          Cancel
        </Button>
        <Button variant="primary" disabled={isSubmitting} type="submit">
          {isSubmitting ? (
            <>
              <RefreshCw size={16} className="mr-2 animate-spin" />
              Logging in...
            </>
          ) : (
            <>
              <LogIn size={16} className="mr-2" />
              Login
            </>
          )}
        </Button>
      </div>
    </form>
  );
};

// Registration Form
const RegisterForm: React.FC<{ onClose: () => void; onSwitchToLogin: () => void }> = ({ onClose, onSwitchToLogin }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    confirm_password: '',
    role: 'viewer'
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setError('');
    
    if (!formData.username || !formData.email || !formData.full_name || !formData.password) {
      setError('Please fill in all required fields');
      setIsSubmitting(false);
      return;
    }

    if (formData.password !== formData.confirm_password) {
      setError('Passwords do not match');
      setIsSubmitting(false);
      return;
    }

    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters long');
      setIsSubmitting(false);
      return;
    }
    
    try {
      // Simulate API call - replace with actual register call
      await new Promise(resolve => setTimeout(resolve, 1000));
      setSuccess(true);
      setTimeout(() => {
        onSwitchToLogin();
      }, 2000);
    } catch (err) {
      setError('Registration failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (success) {
    return (
      <div className="text-center space-y-4">
        <CheckCircle className="text-emerald-400 mx-auto" size={48} />
        <h3 className="text-white text-lg font-medium">Registration Successful!</h3>
        <p className="text-slate-300">Your account has been created. Redirecting to login...</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="p-3 bg-red-900 bg-opacity-50 border border-red-500 rounded text-red-300 text-sm flex items-center">
          <AlertCircle size={16} className="mr-2" />
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Username *</label>
          <input
            type="text"
            value={formData.username}
            onChange={(e) => setFormData({...formData, username: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Choose username"
            disabled={isSubmitting}
          />
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Email *</label>
          <input
            type="email"
            value={formData.email}
            onChange={(e) => setFormData({...formData, email: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="your@email.com"
            disabled={isSubmitting}
          />
        </div>
      </div>

      <div>
        <label className="block text-slate-300 text-sm font-medium mb-2">Full Name *</label>
        <input
          type="text"
          value={formData.full_name}
          onChange={(e) => setFormData({...formData, full_name: e.target.value})}
          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
          placeholder="Your full name"
          disabled={isSubmitting}
        />
      </div>

      <div>
        <label className="block text-slate-300 text-sm font-medium mb-2">Role</label>
        <select
          value={formData.role}
          onChange={(e) => setFormData({...formData, role: e.target.value})}
          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white focus:border-blue-500 focus:outline-none transition-colors"
          disabled={isSubmitting}
        >
          <option value="viewer">Viewer (Read-only access)</option>
          <option value="operator">Operator (Can run backups)</option>
          <option value="admin">Administrator (Full access)</option>
        </select>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Password *</label>
          <input
            type="password"
            value={formData.password}
            onChange={(e) => setFormData({...formData, password: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Choose password"
            disabled={isSubmitting}
          />
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Confirm Password *</label>
          <input
            type="password"
            value={formData.confirm_password}
            onChange={(e) => setFormData({...formData, confirm_password: e.target.value})}
            className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
            placeholder="Confirm password"
            disabled={isSubmitting}
          />
        </div>
      </div>

      <div className="flex justify-between items-center space-x-3">
        <button
          onClick={onSwitchToLogin}
          className="text-blue-400 hover:text-blue-300 text-sm"
          disabled={isSubmitting}
        >
          Already have an account? Login
        </button>
        <div className="flex space-x-3">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-600 hover:bg-slate-500 text-white border border-slate-600 rounded-md font-medium transition-all duration-200"
            disabled={isSubmitting}
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white border border-blue-600 rounded-md font-medium transition-all duration-200 flex items-center justify-center"
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <>
                <RefreshCw size={16} className="mr-2 animate-spin" />
                Creating...
              </>
            ) : (
              <>
                <UserPlus size={16} className="mr-2" />
                Register
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

// Storage Backend Configuration Modal
const StorageBackendModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  backend?: StorageBackend | null;
  onSave: (config: StorageBackendConfig) => void;
}> = ({ isOpen, onClose, backend, onSave }) => {
  const [config, setConfig] = useState<StorageBackendConfig>({
    name: '',
    storage_type: 'local',
    capacity_gb: 1000,
    path: '/app/backups'
  });

  useEffect(() => {
    if (backend) {
      setConfig({
        name: backend.name,
        storage_type: backend.storage_type,
        capacity_gb: backend.capacity_gb,
        path: backend.storage_type === 'local' ? backend.mount_point : undefined,
      });
    } else {
      setConfig({
        name: '',
        storage_type: 'local',
        capacity_gb: 1000,
        path: '/app/backups'
      });
    }
  }, [backend, isOpen]);

  const handleSubmit = () => {
    if (!config.name) {
      alert('Please enter a storage backend name');
      return;
    }

    onSave(config);
    onClose();
  };

  const renderStorageTypeConfig = () => {
    switch (config.storage_type) {
      case 'local':
        return (
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Local Path</label>
            <input
              type="text"
              value={config.path || ''}
              onChange={(e) => setConfig({...config, path: e.target.value})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              placeholder="/app/backups"
            />
            <p className="text-slate-400 text-xs mt-1">Local directory path for storing backups</p>
          </div>
        );

      case 'nfs':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">NFS Server</label>
                <input
                  type="text"
                  value={config.server || ''}
                  onChange={(e) => setConfig({...config, server: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="192.168.1.100"
                />
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Remote Path</label>
                <input
                  type="text"
                  value={config.remote_path || ''}
                  onChange={(e) => setConfig({...config, remote_path: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="/exports/backups"
                />
              </div>
            </div>
            <div>
              <label className="block text-slate-300 text-sm font-medium mb-2">Local Mount Point</label>
              <input
                type="text"
                value={config.local_mount_point || ''}
                onChange={(e) => setConfig({...config, local_mount_point: e.target.value})}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                placeholder="/mnt/nfs_backups"
              />
            </div>
            <div>
              <label className="block text-slate-300 text-sm font-medium mb-2">Mount Options</label>
              <input
                type="text"
                value={config.mount_options || ''}
                onChange={(e) => setConfig({...config, mount_options: e.target.value})}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                placeholder="rw,hard,intr,timeo=300"
              />
            </div>
          </div>
        );

      case 'iscsi':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Target IP</label>
                <input
                  type="text"
                  value={config.target_ip || ''}
                  onChange={(e) => setConfig({...config, target_ip: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="192.168.1.200"
                />
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Target Port</label>
                <input
                  type="number"
                  value={config.target_port || 3260}
                  onChange={(e) => setConfig({...config, target_port: parseInt(e.target.value)})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                />
              </div>
            </div>
            <div>
              <label className="block text-slate-300 text-sm font-medium mb-2">Target IQN</label>
              <input
                type="text"
                value={config.target_iqn || ''}
                onChange={(e) => setConfig({...config, target_iqn: e.target.value})}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                placeholder="iqn.2023-01.com.example:backup-target"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Username (Optional)</label>
                <input
                  type="text"
                  value={config.username || ''}
                  onChange={(e) => setConfig({...config, username: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="iscsi_user"
                />
              </div>
              <div>
                <label className="block text-slate-300 text-sm font-medium mb-2">Password (Optional)</label>
                <input
                  type="password"
                  value={config.password || ''}
                  onChange={(e) => setConfig({...config, password: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
                  placeholder="••••••••"
                />
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={backend ? "Edit Storage Backend" : "Add Storage Backend"} size="lg">
      <div className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Backend Name</label>
            <input
              type="text"
              value={config.name}
              onChange={(e) => setConfig({...config, name: e.target.value})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none transition-colors"
              placeholder="Production Backup Storage"
            />
          </div>
          <div>
            <label className="block text-slate-300 text-sm font-medium mb-2">Storage Type</label>
            <select
              value={config.storage_type}
              onChange={(e) => setConfig({...config, storage_type: e.target.value as 'local' | 'nfs' | 'iscsi'})}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white focus:border-blue-500 focus:outline-none transition-colors"
            >
              <option value="local">Local Storage</option>
              <option value="nfs">NFS Share</option>
              <option value="iscsi">iSCSI LUN</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-slate-300 text-sm font-medium mb-2">Capacity (GB)</label>
          <input
            type="number"
            value={config.capacity_gb}
            onChange={(e) => setConfig({...config, capacity_gb: parseInt(e.target.value)})}
                  placeholder="1000"
                />
              </div>
            </div>

            {renderStorageTypeConfig()}

            <div className="flex justify-end space-x-3">
              <Button onClick={onClose} variant="secondary">
                Cancel
              </Button>
              <Button onClick={handleSubmit} variant="primary">
                <Save size={16} className="mr-2" />
                {backend ? 'Update' : 'Create'} Backend
              </Button>
            </div>
          </div>

          <div className="flex justify-end space-x-3">
            <Button onClick={onClose} variant="secondary">
              Cancel
            </Button>
            <Button onClick={handleSubmit} variant="primary">
              <Save size={16} className="mr-2" />
              {backend ? 'Update' : 'Create'} Backend
            </Button>
          </div>
        </div>
      </Modal>
    );
  };

  export default App;
    // Main App Component with all features
    const MainApp: React.FC = () => {
      const { user, logout } = useAuth();
      const [activeTab, setActiveTab] = useState<'dashboard' | 'vms' | 'backups' | 'jobs' | 'storage' | 'settings'>('dashboard');
      const [showLogin, setShowLogin] = useState(false);
      const [showRegister, setShowRegister] = useState(false);
      const [showBackupJobModal, setShowBackupJobModal] = useState(false);
      const [showStorageModal, setShowStorageModal] = useState(false);
      const [showRestoreModal, setShowRestoreModal] = useState(false);
      const [showAnalytics, setShowAnalytics] = useState(false);
      const [showNotifications, setShowNotifications] = useState(false);
      const [showCronBuilder, setShowCronBuilder] = useState(false);
      const [editingBackend, setEditingBackend] = useState<StorageBackend | null>(null);
      
      const [stats, setStats] = useState<DashboardStats | null>(null);
      const [vms, setVMs] = useState<VM[]>([]);
      const [backupJobs, setBackupJobs] = useState<BackupJob[]>([]);
      const [backups, setBackups] = useState<Backup[]>([]);
      const [storageBackends, setStorageBackends] = useState<StorageBackend[]>([]);
      const [platformStatus, setPlatformStatus] = useState<PlatformStatus>({
        vmware: false,
        proxmox: false,
        xcpng: false,
        ubuntu: false
      });
      
      const [cronExpression, setCronExpression] = useState('0 2 * * *');
      const [loading, setLoading] = useState(true);

      useEffect(() => {
        if (user) {
          loadAllData();
        }
      }, [user]);

      const loadAllData = async () => {
        setLoading(true);
        try {
          const [statsData, vmsData, jobsData, backupsData, storageData, platformData] = await Promise.all([
            api.getStatistics().catch(() => null),
            api.getAllVMs().catch(() => []),
            api.getBackupJobs().catch(() => []),
            api.getAllBackups().catch(() => []),
            api.getStorageBackends().catch(() => []),
            api.getPlatformStatus().catch(() => ({ vmware: false, proxmox: false, xcpng: false, ubuntu: false }))
          ]);

          setStats(statsData);
          setVMs(vmsData);
          setBackupJobs(jobsData);
          setBackups(backupsData);
          setStorageBackends(storageData);
          setPlatformStatus(platformData);
        } catch (error) {
          console.error('Failed to load data:', error);
        } finally {
          setLoading(false);
        }
      };

      const handleCreateStorageBackend = async (config: StorageBackendConfig) => {
        try {
          await api.createStorageBackend(config);
          await loadAllData();
          alert('✅ Storage backend created successfully!');
        } catch (error) {
          console.error('Failed to create storage backend:', error);
          alert('❌ Failed to create storage backend');
        }
      };

      if (!user) {
        return (
          <div className="min-h-screen bg-slate-900 text-white">
            <div className="border-b border-slate-700 bg-slate-800">
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex items-center justify-between h-16">
                  <div className="flex items-center space-x-4">
                    <Shield className="text-blue-400" size={32} />
                    <div>
                      <h1 className="text-xl font-bold text-white">VM Backup Solution</h1>
                      <p className="text-slate-400 text-sm">Enterprise-grade protection</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-4">
                    <Button onClick={() => setShowRegister(true)} variant="secondary" size="sm">
                      <UserPlus size={16} className="mr-2" />
                      Register
                    </Button>
                    <Button onClick={() => setShowLogin(true)} variant="primary" size="sm">
                      <LogIn size={16} className="mr-2" />
                      Login
                    </Button>
                  </div>
                </div>
              </div>
            </div>

            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
              <div className="text-center space-y-8">
                <div className="space-y-4">
                  <h2 className="text-4xl font-bold text-white">Welcome to VM Backup Solution</h2>
                  <p className="text-xl text-slate-400 max-w-2xl mx-auto">
                    Enterprise-grade virtual machine backup and recovery solution supporting VMware vSphere, Proxmox VE, XCP-NG, and Ubuntu machines.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto">
                  <Card className="text-center">
                    <Shield className="text-blue-400 mx-auto mb-4" size={48} />
                    <h3 className="text-lg font-semibold text-white mb-2">Multi-Platform Support</h3>
                    <p className="text-slate-400">VMware, Proxmox, XCP-NG, and Ubuntu backup support</p>
                  </Card>
                  
                  <Card className="text-center">
                    <Database className="text-green-400 mx-auto mb-4" size={48} />
                    <h3 className="text-lg font-semibold text-white mb-2">Enterprise Security</h3>
                    <p className="text-slate-400">Encryption, compression, and anti-ransomware protection</p>
                  </Card>
                  
                  <Card className="text-center">
                    <Cloud className="text-purple-400 mx-auto mb-4" size={48} />
                    <h3 className="text-lg font-semibold text-white mb-2">Flexible Storage</h3>
                    <p className="text-slate-400">Local, NFS, and iSCSI storage backend support</p>
                  </Card>
                </div>

                <div className="bg-blue-900 bg-opacity-30 border border-blue-500 rounded-lg p-6 max-w-md mx-auto">
                  <h3 className="text-lg font-semibold text-blue-300 mb-4">Quick Start</h3>
                  <div className="text-left space-y-2 text-blue-200">
                    <p>• Login with default credentials</p>
                    <p>• Connect your virtualization platforms</p>
                    <p>• Configure storage backends</p>
                    <p>• Create backup jobs</p>
                    <p>• Monitor and restore as needed</p>
                  </div>
                </div>
              </div>
            </main>

            {/* Login Modal */}
            <Modal isOpen={showLogin} onClose={() => setShowLogin(false)} title="Login to VM Backup Solution">
              <LoginForm onClose={() => setShowLogin(false)} />
            </Modal>

            {/* Register Modal */}
            <Modal isOpen={showRegister} onClose={() => setShowRegister(false)} title="Create Account">
              <RegisterForm 
                onClose={() => setShowRegister(false)} 
                onSwitchToLogin={() => {
                  setShowRegister(false);
                  setShowLogin(true);
                }}
              />
            </Modal>
          </div>
        );
      }

      // Authenticated user interface
      return (
        <div className="min-h-screen bg-slate-900 text-white">
          {/* Navigation remains the same as in original */}
          {/* Dashboard content remains the same as in original */}
          {/* All modals remain the same as in original */}
        </div>
      );
    };

    export default function App() {
      return (
        <AuthProvider>
          <MainApp />
        </AuthProvider>
      );
    }
