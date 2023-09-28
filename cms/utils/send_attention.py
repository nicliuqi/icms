import logging
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings
from cms.models import Vulnerability

logger = logging.getLogger('log')


def attention(receiver, maintainer, cve_info):
    """send attention message to person responsible"""
    smtp_host = settings.SMTP_HOST
    smtp_port = settings.SMTP_PORT
    smtp_username = settings.SMTP_USERNAME
    smtp_password = settings.SMTP_PASSWORD
    sender = settings.SMTP_SENDER
    if not all([smtp_host, smtp_port, smtp_username, smtp_password, sender]):
        logger.error('Lack of SMTP parameters, please CHECK!')
        sys.exit(1)
    cve_table = ''
    table_start_tag = '<table border=1>'
    th = """
    <tr>
        <th>Package</th>
        <th>Version</th>
        <th>Fixed Version</th>
        <th>Project</th>
        <th>Branch</th>
        <th>CVE</th>
        <th>Severity</th>
        <th>Source</th>
    </tr>
    """
    table_end_tag = '</table>'
    cve_table += table_start_tag + th
    for cve in cve_info:
        package = cve.package
        version = cve.version
        fixed_version = cve.fixed_version
        project = cve.project_url
        branch = cve.project_branch
        number = cve.cve_num
        severity = cve.severity
        source = cve.source
        cve_detail = cve.cve_detail
        if not cve_detail:
            cve_detail = '/'.join([settings.VUL_DETAIL_PREFIX, number])
        a_tag = '<a href="{0}/{1}">{1}</a>'.format(cve_detail, number)
        cve_item = """
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
        </tr>
        """.format(package, version, fixed_version, project, branch, a_tag, severity, source)
        cve_table += cve_item
    cve_table += table_end_tag
    msg = MIMEMultipart()
    with open(settings.ATTENTION_EMAIL_TEMPLATE, 'r') as f:
        content = f.read()
    text_body = content.replace('{{receiver}}', maintainer).replace('{{cve_table}}', cve_table)
    text = MIMEText(text_body, 'html', 'utf-8')
    msg.attach(text)

    msg['From'] = sender
    msg['To'] = receiver
    msg['Subject'] = settings.ATTENTION_EMAIL_SUBJECT
    try:
        if int(smtp_port) == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port)
            server.ehlo()
            server.login(smtp_username, smtp_password)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.ehlo()
            server.starttls()
            server.login(smtp_username, smtp_password)
        server.sendmail(sender, [receiver], msg.as_string())
        logger.info('Send attention to {}, email: {}.'.format(maintainer, receiver))
    except smtplib.SMTPException as e:
        logger.error(e)


def receivers_statistics():
    """take turns sending messages"""
    receivers = list(set(Vulnerability.objects.filter(status=1).values_list('email', flat=True)))
    for receiver in receivers:
        maintainer = Vulnerability.objects.filter(email=receiver).values()[0].get('maintainer')
        cve_info = list(Vulnerability.objects.filter(email=receiver, status=1))
        attention(receiver, maintainer, cve_info)
