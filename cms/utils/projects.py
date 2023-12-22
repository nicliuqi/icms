import logging
import requests
import yaml
from django.conf import settings
from urllib.parse import urlparse
from cms.models import Access, Service
from cms.utils.packages import wrap_project

logger = logging.Logger('log')


def collect_projects():
    """get all projects by OPS api"""
    logger.info('Start to collect projects')
    url = settings.OPS_SOURCE_URL
    token = Access.objects.get(id=1).token
    headers = {'Authorization': 'Bearer {}'.format(token)}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        logger.error('Fail to update projects.')
        return
    res = []
    projects = r.json().get('data')
    for project in projects:
        url = project.get('repository')
        if url.endswith('.git'):
            url = url[:-4]
        if not is_valid_project(url):
            continue
        branch = project.get('branch')
        maintainer = project.get('developer')
        email = project.get('email')
        data = {
            'url': url,
            'branch': branch,
            'maintainer': maintainer,
            'email': email
        }
        res.append(data)
    logger.info('All infrastructure projects have been collected: total {}'.format(len(res)))
    return res


def collect_projects_v2():
    """get all projects through database"""
    logger.info('Start to collect projects')
    services = Service.objects.all()
    res = []
    for service in services:
        url = service.repository
        branch = service.branch
        maintainer = service.maintainer
        email = service.email
        data = {
            'url': url,
            'branch': branch,
            'maintainer': maintainer,
            'email': email
        }
        res.append(data)
    logger.info('All infrastructure projects have been collected: total {}'.format(len(res)))
    return res


def is_valid_project(url):
    """check validation of a project by its url"""
    valid_projects_conf = settings.VALID_PROJECTS_CONF
    with open(valid_projects_conf, 'r') as f:
        valid_projects = yaml.safe_load(f)
    valid_domains = valid_projects.get('valid_domains')
    valid_organizations = valid_projects.get('valid_organizations')
    parser = urlparse(url)
    domain = parser.netloc
    if domain not in valid_domains:
        return False
    organization = parser.path.split('/')[1]
    if organization in valid_organizations:
        return True
    else:
        return False


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
        email = project.get('email')
        return maintainer, email
    return '', ''
