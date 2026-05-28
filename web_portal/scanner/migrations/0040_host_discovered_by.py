# Generated migration — add discovered_by JSONField to Host model
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0039_phaserun_and_phase_based"),
    ]

    operations = [
        migrations.AddField(
            model_name="host",
            name="discovered_by",
            field=models.JSONField(default=list, blank=True),
        ),
    ]
