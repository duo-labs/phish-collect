'''Implements a provider for the OpenPhish free phishing feed.'''
import hashlib
import requests

from config import config
from feeds.feed import Feed, FetchException
from models import Phish


class OpenphishFeed(Feed):
    '''Implements a provider for the OpenPhish free phishing feed.'''

    def __init__(self):
        '''Creates a new instance of the OpenPhish feed.'''
        self.feed = 'openphish'
        self.url = config['openphish']['url']

    def _process_rows(self, rows):
        '''
        Processes new phishing entries from the OpenPhish feed.

        Every line is simply a URL for a phishing site. We need to
        check for existence and create the `models.Phish` entry to use for storage.

        For the OpenPhish feed, the PID is simply the hash of the URL.

        Args:
            rows {list[str]} - The rows to process
        '''
        entries = []
        urls_seen = []
        for url in rows:
            if Phish.exists(url) or Phish.clean_url(url) in urls_seen:
                continue
            url_hash = hashlib.sha1()
            url_hash.update(url)
            urls_seen.append(Phish.clean_url(url))
            entries.append(
                Phish(pid=url_hash.hexdigest(), url=url, feed=self.feed))
        return entries

    def get(self, offset=0):
        '''
        Gets the latest phishing sites from the OpenPhish feed.

        If the latest site isn't in the new text file, all entries are returned.

        Args:
            offset {str} - The phish ID offset. Not used for this feed.
        '''
        response = requests.get(self.url, timeout=5)
        if not response.ok:
            raise FetchException(
                'Error fetching OpenPhish response:\nStatus: {}\nResponse: {}'.
                format(response.status_code, response.text))
        entries = response.text.splitlines()
        return self._process_rows(entries)
