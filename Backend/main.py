from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select

from database import engine, create_db
from models import ScanHistory

app = FastAPI(
    title="SafeBrowse API",
    description="AI-Powered SafeBrowse - URL Threat Detection API",
    version="1.0.0"
)

# Allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://127.0.0.1:5500",
    "http://localhost:5500"
],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    create_db()


def get_session():
    with Session(engine) as session:
        yield session


@app.get("/")
def root():
    return {
        "status": "online",
        "message": "SafeBrowse Backend is running 🚀"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/scan")
def scan_url(
    scan: ScanHistory,
    session: Session = Depends(get_session)
):
    session.add(scan)
    session.commit()
    session.refresh(scan)

    return {
        "message": "Scan saved successfully",
        "data": scan
    }


@app.get("/history")
def get_history(session: Session = Depends(get_session)):
    history = session.exec(
        select(ScanHistory)
    ).all()

    return history