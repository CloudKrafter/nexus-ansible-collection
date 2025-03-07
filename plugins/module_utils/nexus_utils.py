REQUESTS_IMP_ERR = None
BS4_IMP_ERR = None
PACKAGING_IMP_ERR = None

try:
    import requests
except ImportError as e:
    REQUESTS_IMP_ERR = str(e)
    requests = None

try:
    from bs4 import BeautifulSoup
except ImportError as e:
    BS4_IMP_ERR = str(e)
    BeautifulSoup = None

try:
    from packaging import version
except ImportError as e:
    PACKAGING_IMP_ERR = str(e)
    version = None

try:
    import urllib3
except ImportError:
    urllib3 = None


__all__ = [
    'requests',
    'BeautifulSoup',
    'version',
    'urllib3'
]

