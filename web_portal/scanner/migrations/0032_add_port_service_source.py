# Add service_source to Port to distinguish nmap vs fingerprintx identification

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0031_host_current_phase"),
    ]

    operations = [
        migrations.AddField(
            model_name="port",
            name="service_source",
            field=models.CharField(blank=True, default="", max_length=50),
        ),
    ]
