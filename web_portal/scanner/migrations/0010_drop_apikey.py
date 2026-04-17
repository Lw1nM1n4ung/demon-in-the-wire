"""Drop the unused ApiKey table — the feature was never wired to an auth class."""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0009_backfill_assets'),
    ]

    operations = [
        migrations.DeleteModel(name='ApiKey'),
    ]
