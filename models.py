''' Creates the models for the phish collector '''
from datetime import datetime
from elasticsearch import Elasticsearch
from urlparse import urlparse

es = Elasticsearch()


class Phish(object):
    ''' A class representing a possible phishing site '''
    _index = 'samples'
    _type = 'phish'

    def __init__(self, *args, **kwargs):
        self.pid = kwargs.get('pid')
        self.url = kwargs.get('url')
        self.index_url = Phish.clean_url(self.url)
        self.ip_address = kwargs.get('ip_address', '0.0.0.0')
        self.feed = kwargs.get('feed')
        self.indexing_enabled = kwargs.get('indexing_enabled', False)
        self.has_kit = kwargs.get('has_kit', False)
        self.kits = kwargs.get('kits', [])
        self.timestamp = datetime.now()
        self.status_code = kwargs.get('status_code')
        self.html = kwargs.get('html')

    @classmethod
    def clean_url(cls, url):
        ''' Cleans the URL provided to be a basic scheme://host/path format.

        This removes any params, trailing slashes, etc. to help us remove duplicate
        URLs from our index.

        Args:
            url {str} - The URL to search
        '''
        parts = urlparse(url)
        path = parts.path
        # Strip the trailing slash
        if path and path[-1] == '/':
            path = path[:-1]
        clean_url = '{}://{}{}'.format(parts.scheme, parts.netloc.encode('utf-8'), path.encode('utf-8', 'ignore'))
        return clean_url

    def to_dict(self):
        ''' Creates a dict representation of the Phish instance that
        is compatible with Elasticsearch '''
        return {
            'pid': self.pid,
            'url': self.url,
            'index_url': self.index_url,
            'ip_address': self.ip_address,
            'feed': self.feed,
            'indexing_enabled': self.indexing_enabled,
            'has_kit': self.has_kit,
            'kits': self.kits,
            'timestamp': self.timestamp,
            'status_code': self.status_code,
            'html': self.html
        }

    def index(self):
        ''' Indexes the document into Elasticsearch '''
        return es.index(
            index=Phish._index,
            doc_type=Phish._type,
            id=self.pid,
            body=self.to_dict())

    @classmethod
    def exists(cls, url):
        ''' Checks if a Phish entry with the provided URL already exists in
        elasticsearch.

        Args:
        url {str} - The URL to the phishing page
        '''
        url = Phish.clean_url(url)
        exists = False
        result = es.search(
            index=cls._index,
            doc_type=cls._type,
            terminate_after=1,
            size=0,
            body={'query': {
                'term': {
                    'index_url.raw': url
                }
            }})
        if result['hits']['total']:
            exists = True
        return exists

    @classmethod
    def get_most_recent(cls, feed=None):
        ''' Returns the most recent Phish entry if it exists in Elasticsearch '''
        most_recent = None
        result = es.search(
            index=cls._index,
            doc_type=cls._type,
            size=1,
            body={
                "query": {
                    "term": {
                        'feed': feed
                    }
                },
                "sort": [{
                    "timestamp": {
                        "order": "desc"
                    }
                }]
            })
        hits = result['hits']['hits']
        if hits:
            sample = hits[0]['_source']
            most_recent = Phish(url=sample['url'], pid=sample['pid'])
        return most_recent


class PhishKit(object):
    ''' A class representing phishing kits stored on the filesystem.

    Phishkits are stored as child objects in a one-to-many relationship with Phish samples.'''
    _index = 'samples'
    _type = 'kit'

    def __init__(self, **kwargs):
        '''
        Creates a new instance of the phishkit metadata entry to be stored
        in Elasticsearch
        '''
        self.hash = kwargs.get('hash')
        self.filepath = kwargs.get('filepath')
        self.filename = kwargs.get('filename')
        self.url = kwargs.get('url')
        self.emails = kwargs.get('emails')
        self.parent = kwargs.get('parent')

    def to_dict(self):
        ''' Creates a dict representation of the Phish instance that
        is compatible with Elasticsearch '''
        return {
            'hash': self.hash,
            'filepath': self.filepath,
            'filename': self.filename,
            'url': self.url,
            'emails': self.emails
        }

    def index(self):
        ''' Indexes the document into Elasticsearch '''
        return es.index(
            index=PhishKit._index,
            doc_type=PhishKit._type,
            id=self.hash,
            body=self.to_dict())

    @classmethod
    def exists(cls, url):
        ''' Finds a kit with the given URL. Typically, we would search by hash, but
        we want to be able to find multiple occurrences of the same kit across different sites.

        If a kit is found in Elasticsearch, we return the `models.PhishKit` instance associated
        with it.

        Args:
            url {str} The URL to search for
        '''
        kit = None
        result = es.search(
            index=cls._index,
            doc_type=cls._type,
            terminate_after=1,
            size=1,
            body={'query': {
                'term': {
                    'url.raw': url
                }
            }})
        if result['hits']['total']:
            kit_dict = result['hits']['hits'][0]['_source']
            kit = PhishKit.from_dict(kit_dict)
        return kit

    @classmethod
    def from_dict(self, kit_dict):
        ''' Loads and returns a PhishKit instance from a dict found in a response
        from Elasticsearch.

        Args:
            kit_dict {dict} - The dictionary to load
        '''
        kit = PhishKit(
            hash=kit_dict.get('hash'),
            filepath=kit_dict.get('filepath'),
            filename=kit_dict.get('filename'),
            url=kit_dict.get('url'),
            emails=kit_dict.get('emails'))
        return kit
