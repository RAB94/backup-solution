#!/usr/bin/env python3
"""
Database Initialization Script for VM Backup Solution

This script initializes the database and creates default admin user.
Run this script once after setting up the database to get started.
"""

import sys
import os
from datetime import datetime
from sqlalchemy.orm import Session

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import SessionLocal, init_db, BackupRepository
from auth import User, get_password_hash
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_default_admin():
    """Create a default admin user if none exists"""
    print("🔧 Initializing VM Backup Solution Database...")
    
    try:
        # Initialize database tables
        init_db()
        print("✅ Database tables initialized successfully")
        
        # Create database session
        db = SessionLocal()
        
        try:
            # Check if any admin user exists
            admin_exists = db.query(User).filter(User.role == "admin").first()
            
            if not admin_exists:
                # Create default admin user
                hashed_password = get_password_hash("admin123")
                admin_user = User(
                    username="admin",
                    email="admin@backup.local",
                    full_name="System Administrator",
                    hashed_password=hashed_password,
                    role="admin",
                    is_active=True,
                    created_at=datetime.now()
                )
                
                db.add(admin_user)
                db.commit()
                db.refresh(admin_user)
                
                print("\n✅ Default admin user created:")
                print("   Username: admin")
                print("   Password: admin123")
                print("   Email: admin@backup.local")
                print("")
                print("⚠️  IMPORTANT: Change the default password after first login!")
            else:
                print("\nℹ️  Admin user already exists. Current admin users:")
                admins = db.query(User).filter(User.role == "admin").all()
                for admin in admins:
                    print(f"   - {admin.username} ({admin.email})")
            
            # Create default backup repository if it doesn't exist
            default_repo = db.query(BackupRepository).filter(BackupRepository.id == 1).first()
            
            if not default_repo:
                default_repo = BackupRepository(
                    id=1,
                    name="Default Local Storage",
                    storage_type="local",
                    connection_string="/app/backups",
                    capacity_gb=1000,
                    used_gb=0,
                    encryption_enabled=True,
                    settings={
                        "compression": True,
                        "path": "/app/backups",
                        "auto_cleanup": True
                    }
                )
                
                db.add(default_repo)
                db.commit()
                db.refresh(default_repo)
                
                print("\n✅ Default backup repository created:")
                print("   Name: Default Local Storage")
                print("   Type: Local Storage")
                print("   Path: /app/backups")
            else:
                print("\nℹ️  Default backup repository already exists")
                
        except Exception as e:
            print(f"❌ Error during database setup: {e}")
            db.rollback()
            return False
        finally:
            db.close()
            
        print("\n🎉 Database initialization completed successfully!")
        print("\n📝 Next steps:")
        print("   1. Start the backend server: uvicorn main:app --reload")
        print("   2. Access the web interface at: http://localhost:3000")
        print("   3. Login with admin/admin123")
        print("   4. Connect to your virtualization platforms")
        print("   5. Create backup jobs for your VMs")
        
        return True
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

def create_sample_data():
    """Create sample data for testing (optional)"""
    print("\n🔧 Creating sample data...")
    
    db = SessionLocal()
    try:
        # Check if we should create sample data
        user_count = db.query(User).count()
        
        if user_count <= 1:  # Only admin exists
            # Create sample operator user
            operator_user = User(
                username="operator",
                email="operator@backup.local", 
                full_name="Backup Operator",
                hashed_password=get_password_hash("operator123"),
                role="operator",
                is_active=True,
                created_at=datetime.now()
            )
            
            # Create sample viewer user
            viewer_user = User(
                username="viewer",
                email="viewer@backup.local",
                full_name="Read Only Viewer", 
                hashed_password=get_password_hash("viewer123"),
                role="viewer",
                is_active=True,
                created_at=datetime.now()
            )
            
            db.add(operator_user)
            db.add(viewer_user)
            db.commit()
            
            print("✅ Sample users created:")
            print("   - operator/operator123 (Operator role)")
            print("   - viewer/viewer123 (Viewer role)")
        else:
            print("ℹ️  Sample data already exists, skipping...")
            
    except Exception as e:
        print(f"❌ Error creating sample data: {e}")
        db.rollback()
    finally:
        db.close()

def check_database_connection():
    """Check if database connection is working"""
    print("🔍 Checking database connection...")
    
    try:
        db = SessionLocal()
        # Simple query to test connection
        user_count = db.query(User).count()
        db.close()
        
        print(f"✅ Database connection successful ({user_count} users found)")
        return True
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("\n🛠️  Troubleshooting tips:")
        print("   - Check if PostgreSQL/SQLite is running")
        print("   - Verify DATABASE_URL environment variable")
        print("   - Check database credentials and permissions")
        return False

def main():
    """Main initialization function"""
    print("=" * 60)
    print("🛡️  VM BACKUP SOLUTION - Database Initialization")
    print("=" * 60)
    
    # Check database connection first
    if not check_database_connection():
        return False
    
    # Initialize database and create admin user
    if not create_default_admin():
        return False
    
    # Ask if user wants sample data
    try:
        create_samples = input("\n❓ Create sample users for testing? (y/N): ").lower().strip()
        if create_samples in ['y', 'yes']:
            create_sample_data()
    except KeyboardInterrupt:
        print("\n\n👋 Initialization interrupted by user")
        return True
    except:
        pass  # Skip if input fails
    
    print("\n" + "=" * 60)
    print("🚀 Ready to start VM Backup Solution!")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

