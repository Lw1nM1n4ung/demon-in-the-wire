from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0052_scan_network_overwatch_targets"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="skip_brute_force",
            field=models.BooleanField(default=False),
        ),
    ]
