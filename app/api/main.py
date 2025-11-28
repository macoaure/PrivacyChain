"""
Main FastAPI application for PrivacyChain.

This module sets up the FastAPI app with all routes and middleware.
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes.anonymization import router as anonymization_router
from app.api.routes.operations import router as operations_router
from app.api.routes.transactions import router as transactions_router
from app.config.settings import settings

# Create FastAPI app
app = FastAPI(
    title='PrivacyChain',
    description='REST API specification for PrivacyChain (Personal Data Persistence for DLT)',
    version='1.0.0',
    openapi_tags=[
        {"name": "Pure Functions", "description": "Pure functions of functional programming"},
        {"name": "Operations", "description": "Blockchain operations"},
        {"name": "Transactions", "description": "Transaction operations"},
    ]
)

# CORS middleware
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom exception handler
class MyCustomException(Exception):
    """Custom exception for application errors."""
    def __init__(self, message: str):
        self.message = message

@app.exception_handler(MyCustomException)
async def custom_exception_handler(request: Request, exception: MyCustomException):
    """Handle custom exceptions."""
    return JSONResponse(status_code=500, content={"message": exception.message})

# Include routers
app.include_router(anonymization_router)
app.include_router(operations_router)
app.include_router(transactions_router)

# Health check endpoint
@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

# Root endpoint
@app.get("/", tags=["Health"])
def root():
    """Root endpoint."""
    return {"message": "Welcome to PrivacyChain API"}

# Default blockchain and hash method
DEFAULT_BLOCKCHAIN = settings.default_blockchain
DEFAULT_HASH_METHOD = settings.default_hash_method

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
