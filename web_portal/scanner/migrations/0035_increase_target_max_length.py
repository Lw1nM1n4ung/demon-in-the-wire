# Generated migration: increase target max_length from 500 to 2000
# for large multi-CIDR bug bounty scopes

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0034_add_host_web_endpoints_titles'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scan',
            name='target',
            field=models.CharField(max_length=2000),
        ),
        migrations.AlterField(
            model_name='scheduledscan',
            name='target',
            field=models.CharField(max_length=2000),
        ),
    ]
