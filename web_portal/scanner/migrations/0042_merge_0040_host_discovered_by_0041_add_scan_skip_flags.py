# Merge migration: reconciles two parallel branches from 0038
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0040_host_discovered_by"),
        ("scanner", "0041_add_scan_skip_flags"),
    ]

    operations = []
