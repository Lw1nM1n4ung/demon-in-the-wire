from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0026_add_skip_netexec'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='scan',
            name='skip_openvas',
        ),
    ]
