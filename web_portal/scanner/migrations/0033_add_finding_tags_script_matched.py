# Add tags, script_id, matched_at to Finding model

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0032_add_port_service_source"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="matched_at",
            field=models.CharField(blank=True, default="", max_length=500),
        ),
        migrations.AddField(
            model_name="finding",
            name="script_id",
            field=models.CharField(blank=True, default="", max_length=200),
        ),
        migrations.AddField(
            model_name="finding",
            name="tags",
            field=models.TextField(blank=True, default=""),
        ),
    ]
