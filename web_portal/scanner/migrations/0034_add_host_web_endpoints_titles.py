# Add web_endpoints and web_titles to Host model

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0033_add_finding_tags_script_matched"),
    ]

    operations = [
        migrations.AddField(
            model_name="host",
            name="web_endpoints",
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name="host",
            name="web_titles",
            field=models.JSONField(default=dict),
        ),
    ]
