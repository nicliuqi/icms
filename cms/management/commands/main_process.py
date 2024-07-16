from django.core.management import BaseCommand
from cms.utils.projects import collect_projects
from cms.utils.send_attention import send_message_with_enclosure
from cms.utils.vulnerabilities import match_aqua_vulnerabilities


class Command(BaseCommand):
    def handle(self, *args, **options):
        projects = collect_projects()
        match_aqua_vulnerabilities(projects)
        send_message_with_enclosure()
