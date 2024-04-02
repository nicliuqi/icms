import json
import logging
import os
import requests
from datetime import datetime
from django.conf import settings
from cms.models import Vulnerability
from cms.utils.packages import unwrap_project
from cms.utils.projects import get_project_maintainer, get_projects_map

logger = logging.getLogger('log')


def collect_vtopia_vulnerabilities():
    """get all known vulnerabilities"""
    logger.info('Start to collect all vulnerabilities by vtopia')
    res = []
    page = 1
    while True:
        url = settings.CVE_SOURCE_URL
        params = {
            'page_num': page,
            'count_per_page': 100
        }
        r = requests.get(url, params=params)
        if r.status_code != 200:
            logger.error('Fail to get vulnerabilities data of page {}'.format(page))
            continue
        logger.info('Get vtopia vulnerabilities data of page {}'.format(page))
        vul_list = r.json().get('body').get('list')
        if not vul_list:
            break
        for i in vul_list:
            res.append(i)
        page += 1
    logger.info('All Vtopia vulnerabilities have been collected: total {}'.format(len(res)))
    return res


def match_vtopia_vulnerabilities(projects, packages):
    Vulnerability.objects.filter(source='vtopia', status=1).update(status=3)
    now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info('Start to match all vulnerabilities by vtopia')
    vulnerabilities = collect_vtopia_vulnerabilities()
    vul_maps = {}
    for vul in vulnerabilities:
        cve_num = vul.get('cveNum')
        vul_maps[cve_num] = vul
    pack_names = []
    pkg_vul_maps = {}
    for vul in vulnerabilities:
        cve_num = vul.get('cveNum')
        pack_name = vul.get('packName')
        for pack in pack_name:
            if pack not in pack_names:
                pack_names.append(pack)
            if pack not in pkg_vul_maps.keys():
                pkg_vul_maps[pack] = []
            if cve_num not in pkg_vul_maps[pack]:
                pkg_vul_maps[pack].append(cve_num)
    projects_map = get_projects_map(projects)
    for package in packages:
        if package not in pack_names:
            continue
        projects = packages[package]
        match_cve_nums = pkg_vul_maps[package]
        logger.info('match_package: {}, match_cv_nums: {}'.format(package, match_cve_nums))
        pkg_name, pkg_version = package.split('==')
        for project in projects:
            if project not in projects_map.keys():
                continue
            match_project = projects_map[project]
            url = match_project.get('url')
            branch = match_project.get('branch')
            maintainer = match_project.get('maintainer')
            email = match_project.get('email')
            for i in match_cve_nums:
                cve = vul_maps[i]
                cve_num = cve.get('cveNum')
                title = cve.get('title')
                description = cve.get('description').get('en')
                severity = cve.get('vulStatus')
                publish_time = cve.get('publishedDate')
                if not Vulnerability.objects.filter(cve_num=cve_num,
                                                    project_url=url,
                                                    project_branch=branch,
                                                    package=pkg_name,
                                                    version=pkg_version,
                                                    maintainer=maintainer,
                                                    email=email,
                                                    title=title,
                                                    description=description,
                                                    severity=severity,
                                                    publish_time=publish_time,
                                                    source='vtopia',
                                                    status__in=[1, 3, 4, 5]):
                    Vulnerability.objects.create(cve_num=cve_num,
                                                 project_url=url,
                                                 project_branch=branch,
                                                 package=pkg_name,
                                                 version=pkg_version,
                                                 maintainer=maintainer,
                                                 email=email,
                                                 title=title,
                                                 description=description,
                                                 severity=severity,
                                                 publish_time=publish_time,
                                                 create_time=now_time,
                                                 source='vtopia')
                    logger.info('Create vtopia vulnerability {}'.format(cve_num))
                else:
                    Vulnerability.objects.filter(cve_num=cve_num,
                                                 project_url=url,
                                                 project_branch=branch,
                                                 package=pkg_name,
                                                 version=pkg_version,
                                                 maintainer=maintainer,
                                                 email=email,
                                                 title=title,
                                                 description=description,
                                                 severity=severity,
                                                 publish_time=publish_time,
                                                 source='vtopia',
                                                 status=3).update(status=1)
                    logger.info('Update vtopia vulnerability {}'.format(cve_num))
    Vulnerability.objects.filter(source='vtopia', status=3).update(solve_time=now_time, status=2)
    logger.info('Match vulnerabilities by vtopia')


def match_aqua_vulnerabilities(projects):
    Vulnerability.objects.filter(source='aqua', status=1).update(status=3)
    now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info('Start to match all vulnerabilities by aqua')
    projects_map = get_projects_map(projects)
    json_files_path = settings.JSON_FILES_PATH
    if not os.path.exists(json_files_path):
        logger.info('Waiting scanning projects.')
        return
    json_files = os.listdir(json_files_path)
    if not json_files:
        logger.info('No reports to get vulnerabilities')
        return
    for json_file in json_files:
        if os.path.getsize(os.path.join(json_files_path, json_file)) == 0:
            logger.info('WARNING! File {} is empty.'.format(json_file))
            continue
        with open(os.path.join(json_files_path, json_file), 'r') as fp:
            content = json.loads(fp.read())
        if 'Results' not in content.keys():
            continue
        results = content.get('Results')
        logger.info('Parse report of {}'.format(json_file))
        for result in results:
            if 'Vulnerabilities' not in result.keys():
                logger.info('There is no vulnerability in {}, continue'.format(json_file))
                continue
            target = result.get('target')
            vuls = result.get('Vulnerabilities')
            for vul in vuls:
                cve_num = vul.get('VulnerabilityID')
                if not cve_num.startswith('CVE'):
                    continue
                cve_detail = vul.get('PrimaryURL')
                package = vul.get('PkgName')
                version = vul.get('InstalledVersion')
                fixed_version = vul.get('FixedVersion')
                title = vul.get('Title')
                description = vul.get('Description')
                severity = vul.get('Severity')
                publish_time = vul.get('PublishedDate')
                if publish_time:
                    publish_time = datetime.strptime(publish_time[:19], '%Y-%m-%dT%H:%M:%S').strftime(
                        '%Y-%m-%d %H:%M:%S')
                project_url, project_branch = unwrap_project(json_file)
                maintainer, email = get_project_maintainer(projects_map, project_url, project_branch)
                if not maintainer or not email:
                    logger.info('Cannot find maintainer or email of vulnerability {}, continue'.format(cve_num))
                    continue
                if not Vulnerability.objects.filter(cve_num=cve_num,
                                                    project_url=project_url,
                                                    project_branch=project_branch,
                                                    package=package,
                                                    version=version,
                                                    fixed_version=fixed_version,
                                                    title=title,
                                                    description=description,
                                                    severity=severity,
                                                    publish_time=publish_time,
                                                    maintainer=maintainer,
                                                    email=email,
                                                    source='aqua',
                                                    status__in=[1, 3, 4, 5]):
                    Vulnerability.objects.create(cve_num=cve_num,
                                                 cve_detail=cve_detail,
                                                 project_url=project_url,
                                                 project_branch=project_branch,
                                                 target=target,
                                                 package=package,
                                                 version=version,
                                                 fixed_version=fixed_version,
                                                 title=title,
                                                 description=description,
                                                 severity=severity,
                                                 publish_time=publish_time,
                                                 create_time=now_time,
                                                 maintainer=maintainer,
                                                 email=email,
                                                 source='aqua')
                    logger.info('Create aqua vulnerability {}'.format(cve_num))
                else:
                    Vulnerability.objects.filter(cve_num=cve_num,
                                                 project_url=project_url,
                                                 project_branch=project_branch,
                                                 package=package,
                                                 version=version,
                                                 fixed_version=fixed_version,
                                                 title=title,
                                                 description=description,
                                                 severity=severity,
                                                 publish_time=publish_time,
                                                 maintainer=maintainer,
                                                 email=email,
                                                 source='aqua',
                                                 status=3).update(status=1)
                    logger.info('Update aqua vulnerability {}'.format(cve_num))
    Vulnerability.objects.filter(source='aqua', status=3).update(solve_time=now_time, status=2)
    logger.info('Match vulnerabilities by aqua')
