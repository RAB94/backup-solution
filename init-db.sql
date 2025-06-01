-- Initialize database for VM Backup Solution
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_backup_jobs_status ON backup_jobs(status);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_vm_id ON backup_jobs(vm_id);
CREATE INDEX IF NOT EXISTS idx_backup_records_job_id ON backup_records(job_id);
CREATE INDEX IF NOT EXISTS idx_virtual_machines_platform ON virtual_machines(platform);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
