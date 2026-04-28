from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model


class Command(BaseCommand):
    help = 'Disable MFA for a user (emergency recovery)'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str)

    def handle(self, *args, **options):
        User = get_user_model()
        try:
            user = User.objects.get(username=options['username'])
        except User.DoesNotExist:
            raise CommandError(f'User "{options["username"]}" not found')

        from scanner.models import UserMfaConfig, MfaBackupCode
        updated = UserMfaConfig.objects.filter(user=user).update(enabled=False)
        deleted, _ = MfaBackupCode.objects.filter(user=user).delete()

        if updated:
            self.stdout.write(self.style.SUCCESS(f'MFA disabled for {user.username} ({deleted} backup codes removed)'))
        else:
            self.stdout.write(self.style.WARNING(f'MFA was not enabled for {user.username}'))
