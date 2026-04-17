from django.db import migrations, models


def backfill_roles(apps, schema_editor):
    """Classify existing users into owner/engineer/viewer based on current flags."""
    User = apps.get_model('scanner', 'User')
    owner_assigned = False
    for user in User.objects.all().order_by('date_joined'):
        if user.is_superuser and not owner_assigned:
            user.role = 'owner'
            owner_assigned = True
        elif user.is_staff:
            user.role = 'engineer'
        else:
            user.role = 'viewer'
        # Re-mirror flags to match role so the two stay consistent after the migration.
        user.is_superuser = (user.role == 'owner')
        user.is_staff = user.role in ('owner', 'engineer')
        user.save(update_fields=['role', 'is_superuser', 'is_staff'])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0004_siteconfig_timezone'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(
                choices=[('owner', 'Owner'), ('engineer', 'Engineer'), ('viewer', 'Viewer')],
                default='viewer',
                max_length=16,
            ),
        ),
        migrations.RunPython(backfill_roles, noop),
    ]
