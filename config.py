from os import environ, path

import toml
'''
config.py - A basic configuration file
'''


def load_config(config_path=None):
    ''' Loads the config from config.toml '''
    if config_path is None:
        config_path = environ.get(
            'PHISHCOLLECT_CONFIG',
            path.join(path.dirname(__file__), 'config.toml'), )

    with open(config_path) as f:
        return toml.load(f)


config = load_config()
