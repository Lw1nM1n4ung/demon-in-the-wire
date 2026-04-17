from django.db import migrations, models

from scanner.models import generate_uuid7


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0007_seed_permissions'),
    ]

    operations = [
        migrations.CreateModel(
            name='Asset',
            fields=[
                ('id', models.UUIDField(default=generate_uuid7, editable=False, primary_key=True, serialize=False)),
                ('ip', models.CharField(max_length=45)),
                ('port', models.IntegerField(blank=True, null=True)),
                ('protocol', models.CharField(default='tcp', max_length=8)),
                ('hostname', models.CharField(blank=True, max_length=255)),
                ('os', models.CharField(blank=True, max_length=128)),
                ('service_name', models.CharField(blank=True, max_length=64)),
                ('service_product', models.CharField(blank=True, max_length=128)),
                ('service_version', models.CharField(blank=True, max_length=64)),
                ('first_seen', models.DateTimeField()),
                ('last_seen', models.DateTimeField()),
                ('status', models.CharField(choices=[('open', 'Open'), ('closed', 'Closed'), ('filtered', 'Filtered'), ('inactive', 'Inactive')], default='open', max_length=16)),
                ('risk_score', models.IntegerField(default=0)),
                ('findings_count', models.IntegerField(default=0)),
                ('critical_count', models.IntegerField(default=0)),
                ('high_count', models.IntegerField(default=0)),
                ('last_scan', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name='assets_last_scanned', to='scanner.scan')),
            ],
            options={
                'ordering': ['-risk_score', '-last_seen'],
                'indexes': [
                    models.Index(fields=['last_seen'], name='scanner_ass_last_se_idx'),
                    models.Index(fields=['first_seen'], name='scanner_ass_first_s_idx'),
                    models.Index(fields=['status'], name='scanner_ass_status_idx'),
                    models.Index(fields=['risk_score'], name='scanner_ass_risk_sc_idx'),
                    models.Index(fields=['ip'], name='scanner_ass_ip_idx'),
                ],
                'unique_together': {('ip', 'port', 'protocol')},
            },
        ),
    ]
