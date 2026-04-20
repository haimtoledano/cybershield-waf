import database
import auth
from sqlalchemy import text

def update_password():
    session = database.SessionLocal()
    try:
        new_hash = auth.get_password_hash('ChangeMeNow123!')
        session.execute(text("UPDATE users SET hashed_password = :hp WHERE username = 'superadmin'"), {'hp': new_hash})
        session.commit()
        print("Password updated successfully")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    update_password()
