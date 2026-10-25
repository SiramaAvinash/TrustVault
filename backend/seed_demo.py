"""Demo accounts are intentionally no longer seeded with predefined credentials.
Run `python create_admin.py` to create an administrator using your own credentials.
New users register through POST /api/auth/register and receive the viewer role by default.
"""
from app.db.session import Base, engine

def main():
    Base.metadata.create_all(bind=engine)
    print("TrustVault database tables are ready. No demo users were created.")
    print("Run: python create_admin.py")

if __name__ == "__main__": main()
