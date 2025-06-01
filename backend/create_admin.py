# create_admin.py - Run this to create a default admin user
from sqlalchemy.orm import Session
from database import SessionLocal, init_db
from auth import User, get_password_hash
from datetime import datetime

def create_default_admin():
    """Create a default admin user if none exists"""
    init_db()  # Ensure database is initialized
    
    db = SessionLocal()
    try:
        # Check if any admin user exists
        admin_exists = db.query(User).filter(User.role == "admin").first()
        
        if not admin_exists:
            # Create default admin user
            hashed_password = get_password_hash("admin123")
            admin_user = User(
                username="admin",
                email="admin@example.com",
                full_name="System Administrator",
                hashed_password=hashed_password,
                role="admin",
                is_active=True,
                created_at=datetime.now()
            )
            
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            
            print("✅ Default admin user created:")
            print("   Username: admin")
            print("   Password: admin123")
            print("   Email: admin@example.com")
            print("")
            print("⚠️  IMPORTANT: Change the default password after first login!")
        else:
            print("ℹ️  Admin user already exists. Current admin users:")
            admins = db.query(User).filter(User.role == "admin").all()
            for admin in admins:
                print(f"   - {admin.username} ({admin.email})")
                
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_default_admin()
