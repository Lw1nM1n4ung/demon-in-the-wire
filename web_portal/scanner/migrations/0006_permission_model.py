import uuid

from django.db import migrations, models

from scanner.models import generate_uuid7


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0005_user_role'),
    ]

    operations = [
        migrations.CreateModel(
            name='Permission',
            fields=[
                ('id', models.UUIDField(default=generate_uuid7, editable=False, primary_key=True, serialize=False)),
                ('code', models.CharField(max_length=64, unique=True)),
                ('name', models.CharField(blank=True, max_length=255)),
                ('description', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['code'],
            },
        ),
        migrations.CreateModel(
            name='RolePermission',
            fields=[
                ('id', models.UUIDField(default=generate_uuid7, editable=False, primary_key=True, serialize=False)),
                ('role', models.CharField(choices=[('owner', 'Owner'), ('engineer', 'Engineer'), ('viewer', 'Viewer')], max_length=16)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('permission', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='role_assignments', to='scanner.permission')),
            ],
            options={
                'ordering': ['role', 'permission__code'],
                'indexes': [models.Index(fields=['role'], name='scanner_rol_role_idx')],
                'unique_together': {('role', 'permission')},
            },
        ),
    ]
