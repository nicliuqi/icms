import logging
import subprocess
from django.conf import settings
from urllib.parse import urlparse

logger = logging.getLogger('log')


def collect_github_repos(projects):
    """pull code of github projects"""
    for project in projects:
        url = project.get('url')
        branch = project.get('branch')
        if not branch:
            continue
        domain, json_file = wrap_project(url, branch)
        if domain != 'github.com':
            continue
        target_url = auth_url(url)
        script_path = settings.COLLECT_GITHUB_CODE_SCRIPT
        subprocess.call('./{} {} {} {}'.format(script_path, target_url, branch, json_file).split())


def collect_other_repos(projects):
    """pull code of projects expect github"""
    for project in projects:
        url = project.get('url')
        branch = project.get('branch')
        if not branch:
            continue
        domain, json_file = wrap_project(url, branch)
        if domain == 'github.com':
            continue
        target_url = auth_url(url)
        script_path = settings.COLLECT_OTHER_CODE_SCRIPT
        subprocess.call('./{} {} {} {}'.format(script_path, target_url, branch, json_file).split())


def auth_url(url):
    """authentication url for skipping interaction"""
    parser = urlparse(url)
    if parser.netloc == 'github.com':
        res = parser.scheme + '://' + settings.GITHUB_TOKEN + parser.netloc + parser.path
    else:
        res = parser.scheme + '://' + settings.GIT_TOKEN + parser.netloc + parser.path
    return res


def wrap_project(url, branch):
    """return netloc and a wrapped filename through url and branch"""
    branch = branch.replace('/', '%2F')
    parser = urlparse(url)
    netloc = parser.netloc
    _, owner, repo = parser.path.split('/')
    json_file = ':'.join([netloc, owner, repo, branch])
    return netloc, json_file


def unwrap_project(name):
    """return project address and project branch"""
    separate_mark = name.rfind(':')
    url, branch = name[:separate_mark], name[separate_mark + 1:]
    project_url = ''.join(['https://', url.replace(':', '/')])
    project_branch = branch.replace('%2F', '/')
    return project_url, project_branch
