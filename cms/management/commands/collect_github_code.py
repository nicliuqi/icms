from django.core.management import BaseCommand
from cms.utils.packages import collect_github_repos
from cms.utils.projects import collect_projects_v2


class Command(BaseCommand):
    def handle(self, *args, **options):
        projects = collect_projects_v2()
        collect_github_repos(projects)
