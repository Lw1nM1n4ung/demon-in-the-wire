# Add skip_tls_audit, skip_snmp_enum, skip_nfs_enum, skip_ldap_enum, skip_web_crawl to Scan

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0040_add_scan_port_range"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="skip_tls_audit",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="scan",
            name="skip_snmp_enum",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="scan",
            name="skip_nfs_enum",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="scan",
            name="skip_ldap_enum",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="scan",
            name="skip_web_crawl",
            field=models.BooleanField(default=False),
        ),
    ]
