# from fastapi import FastAPI, HTTPException, Depends
# from typing import List
# from pydantic import BaseModel
# from fastapi.middleware.cors import CORSMiddleware
# from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker, Session
# from auth import create_jwt_token, get_current_user
#
#
# # Database setup
# # DATABASE_URL = "postgresql://postgres:postgres@localhost/claims_management"
# DATABASE_URL="postgresql://claims_management_v687_user:EISKLXFO56eMDftFcT9DDZ2XfgKfYXLR@dpg-culf33lsvqrc73ccr0o0-a/claims_management_v687"
#
# engine = create_engine(DATABASE_URL)
# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# Base = declarative_base()
#
# # Database Models
# class PolicyholderDB(Base):
#     __tablename__ = "policyholders"
#     id = Column(Integer, primary_key=True, index=True)
#     name = Column(String, index=True)
#     age = Column(Integer)
#
# class PolicyDB(Base):
#     __tablename__ = "policies"
#     id = Column(Integer, primary_key=True, index=True)
#     policyholder_id = Column(Integer, ForeignKey("policyholders.id"))
#     type = Column(String)
#     coverage_amount = Column(Float)
#
# class ClaimDB(Base):
#     __tablename__ = "claims"
#     id = Column(Integer, primary_key=True, index=True)
#     policy_id = Column(Integer, ForeignKey("policies.id"))
#     amount_claimed = Column(Float)
#     status = Column(String)
#
# # Create tables
# Base.metadata.create_all(bind=engine)
#
# app = FastAPI()
#
# origins=[
#     "http://localhost:3000",
#     "https://forntend-gcwl.onrender.com"
# ]
#
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,  # Adjust as needed
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
#
# @app.get("/generate-token")
# def generate_token():
#     """
#     Generates a JWT token for testing.
#     """
#     user_id = "test_user"  # Hardcoded user ID (you can change this)
#     token = create_jwt_token(user_id)
#     return {"access_token": token}
#
# # 🔹 2. A secure API endpoint that requires JWT authentication
# @app.get("/secure-endpoint", dependencies=[Depends(get_current_user)])
# def secure_endpoint():
#     """
#     Secure API that requires JWT authentication.
#     """
#     return {"message": "Access granted to secure endpoint"}
#
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()
#
# # Entity Models
# class Policyholder(BaseModel):
#     id: int
#     name: str
#     age: int
#
# class Policy(BaseModel):
#     id: int
#     policyholder_id: int
#     type: str
#     coverage_amount: float
#
# class Claim(BaseModel):
#     id: int
#     policy_id: int
#     amount_claimed: float
#     status: str
#
# # CRUD Operations
# @app.post("/policyholder/",dependencies=[Depends(get_current_user)])
# def create_policyholder(holder: Policyholder, db: Session = Depends(get_db)):
#     db_holder = PolicyholderDB(**holder.dict())
#     db.add(db_holder)
#     db.commit()
#     db.refresh(db_holder)
#     return db_holder
#
# @app.get("/policyholders/",dependencies=[Depends(get_current_user)])
# def get_policyholders(db: Session = Depends(get_db)):
#     return db.query(PolicyholderDB).all()
#
# @app.put("/policyholder/{holder_id}",dependencies=[Depends(get_current_user)])
# def update_policyholder(holder_id: int, holder: Policyholder, db: Session = Depends(get_db)):
#     db_holder = db.query(PolicyholderDB).filter(PolicyholderDB.id == holder_id).first()
#     if not db_holder:
#         raise HTTPException(status_code=404, detail="Policyholder not found")
#     for key, value in holder.dict().items():
#         setattr(db_holder, key, value)
#     db.commit()
#     return db_holder
#
# @app.delete("/policyholder/{holder_id}",dependencies=[Depends(get_current_user)])
# def delete_policyholder(holder_id: int, db: Session = Depends(get_db)):
#     db_holder = db.query(PolicyholderDB).filter(PolicyholderDB.id == holder_id).first()
#     if not db_holder:
#         raise HTTPException(status_code=404, detail="Policyholder not found")
#     db.delete(db_holder)
#     db.commit()
#     return {"message": "Policyholder deleted"}
#
# @app.post("/policy/",dependencies=[Depends(get_current_user)])
# def create_policy(policy: Policy, db: Session = Depends(get_db)):
#     db_policy = PolicyDB(**policy.dict())
#     db.add(db_policy)
#     db.commit()
#     db.refresh(db_policy)
#     return db_policy
#
# @app.get("/policies/",dependencies=[Depends(get_current_user)])
# def get_policies(db: Session = Depends(get_db)):
#     return db.query(PolicyDB).all()
#
# @app.put("/policy/{policy_id}",dependencies=[Depends(get_current_user)])
# def update_policy(policy_id: int, policy: Policy, db: Session = Depends(get_db)):
#     db_policy = db.query(PolicyDB).filter(PolicyDB.id == policy_id).first()
#     if not db_policy:
#         raise HTTPException(status_code=404, detail="Policy not found")
#     for key, value in policy.dict().items():
#         setattr(db_policy, key, value)
#     db.commit()
#     return db_policy
#
# @app.delete("/policy/{policy_id}",dependencies=[Depends(get_current_user)])
# def delete_policy(policy_id: int, db: Session = Depends(get_db)):
#     db_policy = db.query(PolicyDB).filter(PolicyDB.id == policy_id).first()
#     if not db_policy:
#         raise HTTPException(status_code=404, detail="Policy not found")
#     db.delete(db_policy)
#     db.commit()
#     return {"message": "Policy deleted"}
#
# @app.post("/claim/",dependencies=[Depends(get_current_user)])
# def create_claim(claim: Claim, db: Session = Depends(get_db)):
#     policy = db.query(PolicyDB).filter(PolicyDB.id == claim.policy_id).first()
#     if not policy:
#         raise HTTPException(status_code=400, detail="Policy does not exist")
#     if claim.amount_claimed > policy.coverage_amount:
#         raise HTTPException(status_code=400, detail="Claim amount exceeds policy coverage")
#     db_claim = ClaimDB(**claim.dict())
#     db.add(db_claim)
#     db.commit()
#     db.refresh(db_claim)
#     return db_claim
#
# #,dependencies=[Depends(get_current_user)]
# @app.get("/claims/",dependencies=[Depends(get_current_user)])
# def get_claims(db: Session = Depends(get_db)):
#     return db.query(ClaimDB).all()
#
# @app.put("/claim/{claim_id}",dependencies=[Depends(get_current_user)])
# def update_claim(claim_id: int, claim: Claim, db: Session = Depends(get_db)):
#     db_claim = db.query(ClaimDB).filter(ClaimDB.id == claim_id).first()
#     if not db_claim:
#         raise HTTPException(status_code=404, detail="Claim not found")
#     for key, value in claim.dict().items():
#         setattr(db_claim, key, value)
#     db.commit()
#     return db_claim
#
# @app.delete("/claim/{claim_id}",dependencies=[Depends(get_current_user)])
# def delete_claim(claim_id: int, db: Session = Depends(get_db)):
#     db_claim = db.query(ClaimDB).filter(ClaimDB.id == claim_id).first()
#     if not db_claim:
#         raise HTTPException(status_code=404, detail="Claim not found")
#     db.delete(db_claim)
#     db.commit()
#     return {"message": "Claim deleted"}
#
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)

from fastapi import FastAPI, HTTPException, Depends
from typing import List
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import bcrypt
from auth import create_jwt_token, get_current_user
from prometheus_fastapi_instrumentator import Instrumentator
import sentry_sdk

# Database setup
DATABASE_URL = "postgresql://claims_management_v687_user:EISKLXFO56eMDftFcT9DDZ2XfgKfYXLR@dpg-culf33lsvqrc73ccr0o0-a/claims_management_v687"
# DATABASE_URL = "postgresql://postgres:postgres@localhost/claims_management"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Database Models ---
class PolicyholderDB(Base):
    __tablename__ = "policyholders"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    age = Column(Integer)

class PolicyDB(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True, index=True)
    policyholder_id = Column(Integer, ForeignKey("policyholders.id"))
    type = Column(String)
    coverage_amount = Column(Float)

class ClaimDB(Base):
    __tablename__ = "claims"
    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("policies.id"))
    amount_claimed = Column(Float)
    status = Column(String)

# --- New User Model (only user details) ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

# Create tables
Base.metadata.create_all(bind=engine)

from fastapi import FastAPI
import sentry_sdk

sentry_sdk.init(
    dsn="https://2274c8809bb98ddec9f28e605a4d05bb@o4508823165009920.ingest.us.sentry.io/4508823170777088",
    # Add data like request headers and IP for users,
    # see https://docs.sentry.io/platforms/python/data-management/data-collected/ for more info
    send_default_pii=True,
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for tracing.
    traces_sample_rate=1.0,
    _experiments={
        # Set continuous_profiling_auto_start to True
        # to automatically start the profiler on when
        # possible.
        "continuous_profiling_auto_start": True,
    },
)


app = FastAPI()

Instrumentator().instrument(app).expose(app)
origins = [
    "http://localhost:3000",
    "https://forntend-gcwl.onrender.com",
    "https://fornt-end-gamma.vercel.app"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Adjust as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Pydantic Models for Entities ---
class Policyholder(BaseModel):
    id: int
    name: str
    age: int

    class Config:
        orm_mode = True

class Policy(BaseModel):
    id: int
    policyholder_id: int
    type: str
    coverage_amount: float

    class Config:
        orm_mode = True

class Claim(BaseModel):
    id: int
    policy_id: int
    amount_claimed: float
    status: str

    class Config:
        orm_mode = True

# --- Pydantic Models for Authentication ---
class UserSignup(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

# --- Authentication Endpoints ---
@app.post("/signup")
def signup(user: UserSignup, db: Session = Depends(get_db)):
    existing_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = UserDB(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'),
                                           db_user.hashed_password.encode('utf-8')):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    token = create_jwt_token(user.username)
    return {"access_token": token}

# (Optional) Legacy testing endpoint
@app.get("/generate-token")
def generate_token():
    user_id = "test_user"
    token = create_jwt_token(user_id)
    return {"access_token": token}

@app.get("/secure-endpoint", dependencies=[Depends(get_current_user)])
def secure_endpoint():
    return {"message": "Access granted to secure endpoint"}

# --- CRUD Endpoints ---
@app.post("/policyholder/", dependencies=[Depends(get_current_user)])
def create_policyholder(holder: Policyholder, db: Session = Depends(get_db)):
    db_holder = PolicyholderDB(**holder.dict())
    db.add(db_holder)
    db.commit()
    db.refresh(db_holder)
    return db_holder

@app.get("/policyholders/", dependencies=[Depends(get_current_user)])
def get_policyholders(db: Session = Depends(get_db)):
    return db.query(PolicyholderDB).all()

@app.put("/policyholder/{holder_id}", dependencies=[Depends(get_current_user)])
def update_policyholder(holder_id: int, holder: Policyholder, db: Session = Depends(get_db)):
    db_holder = db.query(PolicyholderDB).filter(PolicyholderDB.id == holder_id).first()
    if not db_holder:
        raise HTTPException(status_code=404, detail="Policyholder not found")
    for key, value in holder.dict().items():
        setattr(db_holder, key, value)
    db.commit()
    return db_holder

@app.delete("/policyholder/{holder_id}", dependencies=[Depends(get_current_user)])
def delete_policyholder(holder_id: int, db: Session = Depends(get_db)):
    db_holder = db.query(PolicyholderDB).filter(PolicyholderDB.id == holder_id).first()
    if not db_holder:
        raise HTTPException(status_code=404, detail="Policyholder not found")
    db.delete(db_holder)
    db.commit()
    return {"message": "Policyholder deleted"}

@app.post("/policy/", dependencies=[Depends(get_current_user)])
def create_policy(policy: Policy, db: Session = Depends(get_db)):
    db_policy = PolicyDB(**policy.dict())
    db.add(db_policy)
    db.commit()
    db.refresh(db_policy)
    return db_policy

@app.get("/policies/", dependencies=[Depends(get_current_user)])
def get_policies(db: Session = Depends(get_db)):
    return db.query(PolicyDB).all()

@app.put("/policy/{policy_id}", dependencies=[Depends(get_current_user)])
def update_policy(policy_id: int, policy: Policy, db: Session = Depends(get_db)):
    db_policy = db.query(PolicyDB).filter(PolicyDB.id == policy_id).first()
    if not db_policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    for key, value in policy.dict().items():
        setattr(db_policy, key, value)
    db.commit()
    return db_policy

@app.delete("/policy/{policy_id}", dependencies=[Depends(get_current_user)])
def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    db_policy = db.query(PolicyDB).filter(PolicyDB.id == policy_id).first()
    if not db_policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(db_policy)
    db.commit()
    return {"message": "Policy deleted"}

@app.post("/claim/", dependencies=[Depends(get_current_user)])
def create_claim(claim: Claim, db: Session = Depends(get_db)):
    policy = db.query(PolicyDB).filter(PolicyDB.id == claim.policy_id).first()
    if not policy:
        raise HTTPException(status_code=400, detail="Policy does not exist")
    if claim.amount_claimed > policy.coverage_amount:
        raise HTTPException(status_code=400, detail="Claim amount exceeds policy coverage")
    db_claim = ClaimDB(**claim.dict())
    db.add(db_claim)
    db.commit()
    db.refresh(db_claim)
    return db_claim

@app.get("/claims/", dependencies=[Depends(get_current_user)])
def get_claims(db: Session = Depends(get_db)):
    return db.query(ClaimDB).all()

@app.put("/claim/{claim_id}", dependencies=[Depends(get_current_user)])
def update_claim(claim_id: int, claim: Claim, db: Session = Depends(get_db)):
    db_claim = db.query(ClaimDB).filter(ClaimDB.id == claim_id).first()
    if not db_claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    for key, value in claim.dict().items():
        setattr(db_claim, key, value)
    db.commit()
    return db_claim

@app.delete("/claim/{claim_id}", dependencies=[Depends(get_current_user)])
def delete_claim(claim_id: int, db: Session = Depends(get_db)):
    db_claim = db.query(ClaimDB).filter(ClaimDB.id == claim_id).first()
    if not db_claim:
        raise HTTPException(status_code=404, detail="Claim not found")
    db.delete(db_claim)
    db.commit()
    return {"message": "Claim deleted"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)
