from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0020_mfa_models'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='enum4linux',
            field=models.BooleanField(default=True),
        ),
    ]
