"""Celery application configuration."""

from celery import Celery

from config import settings

# Create Celery app
celery_app = Celery(
    "beacon",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

# Configure Celery
celery_app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # Task routing - all scan tasks go to the "scans" queue
    task_routes={
        "worker.tasks.*": {"queue": "scans"},
    },

    # Task execution settings
    task_acks_late=True,  # Acknowledge after task completes (safer)
    task_reject_on_worker_lost=True,  # Requeue if worker dies
    worker_prefetch_multiplier=1,  # One task at a time (scans are heavy)

    # Result expiration (24 hours)
    result_expires=86400,

    # Retry settings for broker connection
    broker_connection_retry_on_startup=True,
)

# Auto-discover tasks from the worker.tasks module
celery_app.autodiscover_tasks(["worker"])
