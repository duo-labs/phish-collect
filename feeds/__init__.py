'''Provides phishing feed classes for various providers'''

from config import config
from feeds.phishtank import PhishtankFeed
from feeds.openphish import OpenphishFeed

feeds = []

if config['phishtank']['url']:
    feeds.append(PhishtankFeed())

if config['openphish']['url']:
    feeds.append(OpenphishFeed())
