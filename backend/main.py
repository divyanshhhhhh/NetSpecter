"""
NetSpecter - FastAPI Application Entry Point

Main application module with logging infrastructure,
middleware configuration, and route mounting.
"""

import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings

# =============================================================================
# Logging Configuration
# =============================================================================


def configure_logging() -> None:
    """Configure structured logging with structlog."""
    import logging
    
    # Map log level string to logging module level
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    
    # Determine processors based on log format
    if settings.log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


# Configure logging on module load
configure_logging()

# Get logger for this module
logger = structlog.get_logger(__name__)


# =============================================================================
# Application Lifespan
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan handler.

    Handles startup and shutdown events.
    """
    # Startup
    logger.info(
        "netspecter_starting",
        version="0.1.0",
        host=settings.host,
        port=settings.port,
        debug=settings.debug,
    )

    # Log API key status
    logger.info(
        "api_keys_status",
        openrouter=settings.has_openrouter,
        virustotal=settings.has_virustotal,
        abuseipdb=settings.has_abuseipdb,
        otx=settings.has_otx,
    )

    # Ensure temp directory exists
    settings.ensure_temp_dir()
    logger.info("temp_dir_ready", path=str(settings.temp_dir))

    yield

    # Shutdown
    logger.info("netspecter_shutdown")


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="NetSpecter",
    description="Network Packet Analysis Tool for Cybersecurity Investigation",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# =============================================================================
# Middleware
# =============================================================================

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Health Check
# =============================================================================


@app.get("/health")
async def health_check() -> dict:
    """
    Health check endpoint.

    Returns service status and configuration info.
    """
    return {
        "status": "healthy",
        "service": "netspecter",
        "version": "0.1.0",
        "api_keys": {
            "openrouter": settings.has_openrouter,
            "virustotal": settings.has_virustotal,
            "abuseipdb": settings.has_abuseipdb,
            "otx": settings.has_otx,
        },
    }


# =============================================================================
# API Routes
# =============================================================================

# Import and include API routes
from backend.api.routes import router as api_router

app.include_router(api_router, prefix="/api")


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
