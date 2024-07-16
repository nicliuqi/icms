import json
import logging
import os
from datetime import datetime
from django.conf import settings
from cms.models import Vulnerability
from cms.utils.packages import unwrap_project
from cms.utils.projects import get_project_maintainer, get_projects_map

logger = logging.getLogger('log')


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
                maintainer = get_project_maintainer(projects_map, project_url, project_branch)
                if not maintainer:
                    logger.info('Cannot find maintainer of vulnerability {}, continue'.format(cve_num))
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
                                                 source='aqua',
                                                 status=3).update(status=1)
                    logger.info('Update aqua vulnerability {}'.format(cve_num))
    Vulnerability.objects.filter(source='aqua', status=3).update(solve_time=now_time, status=2)
    logger.info('Match vulnerabilities by aqua')
