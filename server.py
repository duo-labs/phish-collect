import sys
import uuid
import logging

from flask import Flask, request, abort, jsonify
from multiprocessing import Pool, Queue

from config import config
from models import Phish
from collector import Collector
'''
server.py - A simple Flask server to receive URLs to process by the phish collector. 

Jordan Wright <jwright@duo.com>
'''

app = Flask(__name__)
sample_queue = Queue()

DEFAULT_FEED = 'server'


def start_workers():
    pool = Pool(processes=4)
    pool.apply_async(collect_sample)


def collect_sample():
    c = Collector()
    while True:
        sample = sample_queue.get()
        logging.info('Processing sample {}'.format(sample.url))
        try:
            c.collect(sample)
        except Exception as e:
            logging.info('Error processing sample: ')


@app.route('/', methods=['POST'])
def process():
    ''' Adds a sample to the queue to be processed by the collector.

    The following parameters are available:

    url (str: required) - The URL to process
    pid (str: optional) - The ID to assign to the sample (default: UUID4)
    feed (str: optional) - The feed to assign to the sample (default: 'server')
    '''
    url = request.values.get('url')
    if not url:
        abort(400, 'Missing url parameter')
        return
    pid = request.values.get('pid')
    if not pid:
        pid = str(uuid.uuid4())
    feed = request.values.get('feed')
    if not feed:
        feed = DEFAULT_FEED

    # Create a new sample from just the URL and send it to the workers
    sample = Phish(pid=pid, url=url, feed=feed)
    sample_queue.put(sample)
    return jsonify({'processing': True})


def main():
    if not config.get('server'):
        print 'Error - Please configure the server entry in config.toml'
        sys.exit(1)

    start_workers()
    app.run(host=config['server']['host'], port=config['server']['port'])


if __name__ == '__main__':
    main()