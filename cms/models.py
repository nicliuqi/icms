from django.db import models


class Vulnerability(models.Model):
    cve_num = models.CharField(verbose_name='CVE number', max_length=20)
    cve_detail = models.CharField(verbose_name='CVE detail', max_length=60, null=True, blank=True)
    title = models.CharField(verbose_name='CVE title', max_length=255, null=True, blank=True)
    description = models.TextField(verbose_name='CVE description', null=True, blank=True)
    severity = models.CharField(verbose_name='CVE severity', max_length=20, null=True, blank=True)
    target = models.TextField(verbose_name='target scan file', max_length=255, null=True, blank=True)
    project_url = models.CharField(verbose_name='project address', max_length=200)
    project_branch = models.CharField(verbose_name='project branch', max_length=50)
    package = models.CharField(verbose_name='package', max_length=100)
    version = models.CharField(verbose_name='package version', max_length=50)
    fixed_version = models.CharField(verbose_name='suggest version', max_length=255, null=True, blank=True)
    maintainer = models.CharField(verbose_name='maintainer', max_length=100)
    email = models.CharField(verbose_name='maintainer email', max_length=100)
    status = models.IntegerField(verbose_name='CVE status of ICMS', choices=((1, 'unsolved'), (2, 'solved'),
                               (3, 'waiting'), (4, 'ignored'), (5, 'misreport')), default=1)
    source = models.CharField(verbose_name='source platform', max_length=20, default='vtopia')
    publish_time = models.CharField(verbose_name='publish time', max_length=20, null=True, blank=True)
    create_time = models.CharField(verbose_name='create time', max_length=20, null=True, blank=True)
    solve_time = models.CharField(verbose_name='solve time', max_length=20, null=True, blank=True)


class Access(models.Model):
    token = models.CharField(verbose_name='OPS access token', max_length=255)


class Service(models.Model):
    repository = models.CharField(verbose_name='repo address', max_length=255)
    branch = models.CharField(verbose_name='repo branch', max_length=100)
    maintainer = models.CharField(verbose_name='project maintainer', max_length=100)
    email = models.CharField(verbose_name='maintainer email', max_length=100)
