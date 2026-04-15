"""Celery app configuration for Wire_Ghost."""
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'wireghost_web.settings')

app = Celery('wireghost_web')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Route scan tasks to dedicated queue
app.conf.task_routes = {
    'scanner.tasks.run_scan': {'queue': 'scans'},
    'scanner.tasks.generate_report': {'queue': 'reports'},
}

# Celery Beat — periodic tasks
app.conf.beat_schedule = {
    'check-scheduled-scans': {
        'task': 'scanner.tasks.check_scheduled_scans',
        'schedule': 60.0,  # every 60 seconds
    },
}
