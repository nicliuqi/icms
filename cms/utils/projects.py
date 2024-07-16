import logging
from cms.models import Service
from cms.utils.packages import wrap_project

logger = logging.Logger('log')


def collect_projects():
    """get all projects through database"""
    logger.info('Start to collect projects')
    services = Service.objects.all()
    res = []
    for service in services:
        url = service.repository
        branch = service.branch
        maintainer = service.maintainer
        data = {
            'url': url,
            'branch': branch,
            'maintainer': maintainer
        }
        res.append(data)
    logger.info('All infrastructure projects have been collected: total {}'.format(len(res)))
    return res


def get_projects_map(projects):
    projects_map = {}
    for project in projects:
        url = project.get('url')
        branch = project.get('branch')
        if not branch:
            continue
        _, target = wrap_project(url, branch)
        if target not in projects_map.keys():
            projects_map[target] = project
    return projects_map


def get_project_maintainer(projects_map, project_url, project_branch):
    _, target = wrap_project(project_url, project_branch)
    if target in projects_map.keys():
        project = projects_map[target]
        maintainer = project.get('maintainer')
        return maintainer
    return ''
