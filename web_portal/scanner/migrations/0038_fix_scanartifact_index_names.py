# Generated manually — MySQL 30-char index name limit
# scanner_scanartifact_scan_tool_idx (36 chars) is too long

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0037_scan_artifact'),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name='scanartifact',
            name='scanner_scanartifact_scan_tool_idx',
        ),
        migrations.RemoveIndex(
            model_name='scanartifact',
            name='scanner_scanartifact_host_idx',
        ),
        migrations.AddIndex(
            model_name='scanartifact',
            index=models.Index(fields=['scan', 'tool'], name='scan_artifact_scan_tool_idx'),
        ),
        migrations.AddIndex(
            model_name='scanartifact',
            index=models.Index(fields=['host'], name='scan_artifact_host_idx'),
        ),
    ]
