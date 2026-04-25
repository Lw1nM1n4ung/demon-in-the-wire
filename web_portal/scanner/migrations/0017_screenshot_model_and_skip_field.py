from django.db import migrations, models
import django.db.models.deletion


def generate_uuid7():
    """Placeholder for the model default — not called during migration."""
    import uuid
    return uuid.uuid4()


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0016_viewer_read_permissions'),
    ]

    operations = [
        migrations.CreateModel(
            name='Screenshot',
            fields=[
                ('id', models.UUIDField(default=generate_uuid7, editable=False, primary_key=True, serialize=False)),
                ('url', models.CharField(max_length=500)),
                ('filename', models.CharField(max_length=500)),
                ('title', models.CharField(blank=True, max_length=500)),
                ('status_code', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='screenshots', to='scanner.host')),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='screenshots', to='scanner.scan')),
            ],
            options={
                'ordering': ['url'],
                'indexes': [models.Index(fields=['scan'], name='scanner_scr_scan_id_idx')],
            },
        ),
        migrations.AddField(
            model_name='scan',
            name='skip_screenshots',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='scanpolicy',
            name='skip_screenshots',
            field=models.BooleanField(default=False),
        ),
    ]
