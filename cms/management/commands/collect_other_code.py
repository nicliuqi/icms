from django.core.management import BaseCommand
from cms.utils.packages import collect_other_repos
from cms.utils.projects import collect_projects


class Command(BaseCommand):
    def handle(self, *args, **options):
        projects = collect_projects()
        collect_other_repos(projects)
