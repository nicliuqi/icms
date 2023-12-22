from django.core.management import BaseCommand
from cms.utils.packages import packages_map
from cms.utils.projects import collect_projects_v2
from cms.utils.send_attention import receivers_statistics
from cms.utils.vulnerabilities import match_vtopia_vulnerabilities, match_aqua_vulnerabilities


class Command(BaseCommand):
    def handle(self, *args, **options):
        projects = collect_projects_v2()
        packages = packages_map()
        match_aqua_vulnerabilities(projects)
        match_vtopia_vulnerabilities(projects, packages)
        receivers_statistics()
