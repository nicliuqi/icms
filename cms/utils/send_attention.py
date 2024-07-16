import logging
import json
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.header import Header
from django.conf import settings
from cms.models import Vulnerability

logger = logging.getLogger('log')


def send_message_with_enclosure():
    """push message with a enclosure in JSON format"""
    cve_info = Vulnerability.objects.filter(status=1).values()
    data = []
    for i in cve_info:
        data.append({
            'package': i['package'],
            'version': i['version'],
            'fixed_version': i['fixed_version'],
            'project': i['project_url'],
            'branch': i['project_branch'],
            'cve_num': i['cve_num'],
            'cve_detail': i['cve_detail'],
            'title': i['title'],
            'description': i['description'],
            'severity': i['severity'],
            'source': i['source'],
            'maintainer': i['maintainer'],
            'create_time': i['create_time'],
            'publish_time': i['publish_time']
        })
    filename = datetime.strftime(datetime.today(), '%Y%m%d') + '.json'
    with open(filename, 'w') as f:
        f.write(json.dumps(data))

    msg = MIMEMultipart('mixed')
    msg['Subject'] = 'infra_cves_' + datetime.strftime(datetime.today(), '%Y%m%d')
    msg['From'] = settings.SMTP_SENDER
    msg['To'] = settings.SMTP_RECEIVER

    enclosure = MIMEApplication(open(filename, 'r').read())
    enclosure.add_header('Content-Disposition', 'attachment', filename=Header(filename, 'utf-8').encode())
    msg.attach(enclosure)

    try:
        if int(settings.SMTP_PORT) == 465:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT)
            server.ehlo()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
            server.ehlo()
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_SENDER, [settings.SMTP_RECEIVER], msg.as_string())
        logger.info('Send attention to email: {}.'.format(settings.SMTP_RECEIVER))
    except smtplib.SMTPException as e:
        logger.error(e)
