import logging
import requests
from django.core.management import BaseCommand
from django.conf import settings
from cms.models import Access

logger = logging.getLogger('log')


class Command(BaseCommand):
    def handle(self, *args, **options):
        token = Access.objects.get(id=1).token
        url = settings.REFRESH_TOKEN_URL
        data = {'token': token}
        r = requests.post(url, data=data)
        if r.status_code != 200:
            logger.error('Fail to refresh OPS token')
        else:
            logger.info('Success to refresh OPS token')
            new_token = r.json().get('token')
            Access.objects.filter(id=1).update(token=new_token)
