# Add port_range to Scan model

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0039_add_host_discovery_method"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="port_range",
            field=models.CharField(max_length=500, default="1-65535"),
        ),
    ]
