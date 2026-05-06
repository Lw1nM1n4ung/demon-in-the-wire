"""Export OpenAPI 3.0 spec to a file — offline, no URL endpoint exposed."""
import json
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Export OpenAPI 3.0 spec to a JSON/YAML file'

    def add_arguments(self, parser):
        parser.add_argument('--output', '-o', default='openapi.json')
        parser.add_argument('--format', choices=['json', 'yaml'], default='json')

    def handle(self, *args, **options):
        from drf_spectacular.generators import SchemaGenerator

        generator = SchemaGenerator()
        schema = generator.get_schema(request=None, public=True)
        path = options['output']

        with open(path, 'w') as f:
            if options['format'] == 'yaml':
                import yaml
                yaml.dump(schema, f, default_flow_style=False, sort_keys=False)
            else:
                json.dump(schema, f, indent=2, default=str)

        self.stdout.write(self.style.SUCCESS(f'OpenAPI spec → {path}'))
