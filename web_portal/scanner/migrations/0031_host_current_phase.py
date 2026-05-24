# Add current_phase to Host for per-host progress tracking

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0030_add_phase_progress"),
    ]

    operations = [
        migrations.AddField(
            model_name="host",
            name="current_phase",
            field=models.CharField(default="discovery", max_length=20),
        ),
    ]
