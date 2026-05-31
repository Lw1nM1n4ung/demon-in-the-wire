# Generated migration: add discovery_method to Host

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0038_fix_scanartifact_index_names"),
    ]

    operations = [
        migrations.AddField(
            model_name="host",
            name="discovery_method",
            field=models.CharField(max_length=30, blank=True, default=""),
        ),
    ]
