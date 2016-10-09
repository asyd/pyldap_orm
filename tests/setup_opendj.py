#!/usr/bin/env python3

import requests
import subprocess
import os
import logging

ZIP_URL = 'http://download.forgerock.org/downloads/opendj/nightly/20161008_2333/opendj-4.0.0-20161008.zip'
LDAP_PORT = 9389
LDAPS_PORT = 9636
ADMIN_PORT = 9444
JMX_PORT = 9445
DIRECTORY_MANAGER_PASSWORD = 'password'

logger = logging.getLogger('opendj')


def run_cmd(command, cwd):
    logger.debug('Running command: %s in path: %s', ' '.join(command), cwd)
    process = subprocess.Popen(command, cwd=cwd)
    process.communicate()


def setup_opendj(cwd):
    archive = '{}/opendj.zip'.format(cwd)
    if not os.path.isfile(archive):
        logger.info("Downloading OpenDJ, please wait")
        r = requests.get(ZIP_URL, stream=True)
        with open(archive, 'wb') as fh:
            for chunk in r.iter_content():
                if chunk:
                    fh.write(chunk)

    if not os.path.isdir('{}/opendj'.format(cwd)):
        logger.info("Extracting OpenDJ")
        run_cmd(['unzip', 'opendj.zip'], cwd)

    if not os.path.isdir('{}/opendj/config'.format(cwd)):
        logger.info("Setup OpenDJ")
        args = ['./setup',
                '-i',  # Cli mode
                '-n',  # No prompt
                '-b', 'dc=example,dc=com',
                '-p', str(LDAP_PORT),
                '--adminConnectorPort', str(ADMIN_PORT),
                '-x', str(JMX_PORT),
                '-w', DIRECTORY_MANAGER_PASSWORD,
                '-l', '{}/extra/opendj-sample.ldif'.format(cwd)]
        run_cmd(args, cwd='{}/opendj'.format(cwd))


def start_opendj(cwd):
    if not os.path.isfile('{}/opendj/logs/server.pid'.format(cwd)):
        logging.info('Starting OpenDJ')
        run_cmd(['./opendj/bin/start-ds'], cwd=cwd)


def main():
    # Get directory where this file is
    cwd = os.path.dirname(os.path.realpath(__file__))
    # Is OpenDJ already installed?
    logging.basicConfig(level=logging.DEBUG)
    if not os.path.isdir('{}/opendj/config'.format(cwd)):
        setup_opendj(cwd)
    start_opendj(cwd)

if __name__ == '__main__':
    main()
