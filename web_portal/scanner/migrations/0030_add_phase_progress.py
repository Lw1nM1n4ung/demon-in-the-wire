# Generated migration — add current_phase, hosts_scanned, hosts_total to Scan

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0029_ad_recon_models"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="current_phase",
            field=models.CharField(default="pending", max_length=20),
        ),
        migrations.AddField(
            model_name="scan",
            name="hosts_scanned",
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name="scan",
            name="hosts_total",
            field=models.IntegerField(default=0),
        ),
    ]
