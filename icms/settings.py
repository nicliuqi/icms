"""
Django settings for icms project.
"""

import os
import time
import sys
import yaml


CONFIG_PATH = os.getenv('CONFIG_PATH')
if not os.path.exists(CONFIG_PATH):
    sys.exit()
with open(CONFIG_PATH, 'r') as f:
    content = yaml.safe_load(f)
DEFAULT_CONF = content
if sys.argv[0] == 'uwsgi':
    os.remove(CONFIG_PATH)
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = DEFAULT_CONF.get('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'cms.apps.CmsConfig',
    'rest_framework',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'icms.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'icms.wsgi.application'


# Database

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': DEFAULT_CONF.get('DB_NAME'),
        'USER': DEFAULT_CONF.get('DB_USER'),
        'PASSWORD': DEFAULT_CONF.get('DB_PASS'),
        'HOST': DEFAULT_CONF.get('DB_HOST'),
        'PORT': DEFAULT_CONF.get('DB_PORT'),
    }
}

# Password validation

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

USE_TZ = False

STATIC_ROOT = os.path.join(BASE_DIR, 'static')

STATIC_URL = '/static/'

cur_path = os.path.dirname(os.path.realpath(__file__))

log_path = os.path.join(os.path.dirname(cur_path), 'logs')

if not os.path.exists(log_path):
    os.mkdir(log_path)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'standard': {
            'format': '[%(asctime)s] [%(filename)s:%(lineno)d] [%(module)s:%(funcName)s] '
                      '[%(levelname)s]- %(message)s'},
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'filters': {
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(log_path, 'all-{}.log'.format(time.strftime('%Y-%m-%d'))),
            'maxBytes': 1024 * 1024 * 5,
            'backupCount': 5,
            'formatter': 'standard',
            'encoding': 'utf-8',
        },
        'error': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(log_path, 'error-{}.log'.format(time.strftime('%Y-%m-%d'))),
            'maxBytes': 1024 * 1024 * 5,
            'backupCount': 5,
            'formatter': 'standard',
            'encoding': 'utf-8',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
        'info': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(log_path, 'info-{}.log'.format(time.strftime('%Y-%m-%d'))),
            'maxBytes': 1024 * 1024 * 5,
            'backupCount': 5,
            'formatter': 'standard',
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['default', 'console'],
            'level': 'INFO',
            'propagate': False
        },
        'log': {
            'handlers': ['error', 'info', 'console', 'default'],
            'level': 'INFO',
            'propagate': True
        },
    }
}

ATTENTION_EMAIL_TEMPLATE = 'cms/utils/email_attention.txt'
ATTENTION_EMAIL_SUBJECT = 'Infrastructure CVE vulnerability awareness attention'
COLLECT_GITHUB_CODE_SCRIPT = 'cms/utils/collect_github_repo.sh'
COLLECT_OTHER_CODE_SCRIPT = 'cms/utils/collect_other_repo.sh'
CVE_SOURCE_URL = DEFAULT_CONF.get('CVE_SOURCE_URL')
GITHUB_TOKEN = DEFAULT_CONF.get('GITHUB_TOKEN')
GIT_TOKEN = DEFAULT_CONF.get('GIT_TOKEN')
JSON_FILES_PATH = 'cms/data/json'
OPS_SOURCE_URL = DEFAULT_CONF.get('OPS_SOURCE_URL')
REFRESH_TOKEN_URL = DEFAULT_CONF.get('REFRESH_TOKEN_URL')
SMTP_HOST = DEFAULT_CONF.get('SMTP_HOST')
SMTP_PORT = DEFAULT_CONF.get('SMTP_PORT')
SMTP_USERNAME = DEFAULT_CONF.get('SMTP_USERNAME')
SMTP_PASSWORD = DEFAULT_CONF.get('SMTP_PASSWORD')
SMTP_SENDER = DEFAULT_CONF.get('SMTP_SENDER')
VALID_PROJECTS_CONF = 'cms/utils/valid_projects.yaml'
VUL_DETAIL_PREFIX = DEFAULT_CONF.get('VUL_DETAIL_PREFIX')
