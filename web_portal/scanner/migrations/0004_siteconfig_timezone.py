from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0003_add_nuclei_templates'),
    ]

    operations = [
        migrations.AddField(
            model_name='siteconfig',
            name='schedule_timezone',
            field=models.CharField(default='UTC', max_length=64),
        ),
    ]
