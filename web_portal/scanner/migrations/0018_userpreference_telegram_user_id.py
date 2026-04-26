from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0017_screenshot_model_and_skip_field'),
    ]

    operations = [
        migrations.AddField(
            model_name='userpreference',
            name='telegram_user_id',
            field=models.BigIntegerField(
                blank=True,
                help_text='Telegram integer user ID for auth resolution',
                null=True,
                unique=True,
            ),
        ),
    ]
