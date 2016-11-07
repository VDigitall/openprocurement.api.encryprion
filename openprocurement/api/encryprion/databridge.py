import logging
import logging.config
import os
import argparse
from yaml import load
from urlparse import urljoin
from openprocurement_client.sync import get_tenders
from openprocurement_client.client import TendersClient
from .utils import decrypt_file
import errno
from socket import error
from requests.exceptions import ConnectionError, MissingSchema

from gevent import monkey
monkey.patch_all()

try:
    import urllib3.contrib.pyopenssl
    urllib3.contrib.pyopenssl.inject_into_urllib3()
except ImportError:
    pass

BID_DOCUMENTS_DECRYPT_STATUS = 'active.qualification'
# BID_DOCUMENTS_DECRYPT_STATUS = 'active.qualification.decrypt'

logger = logging.getLogger(__name__)


class DataBridgeConfigError(Exception):
    pass


class EncryptDataBridge(object):

    """Encrypt Bridge"""

    def __init__(self, config):
        super(EncryptDataBridge, self).__init__()
        self.config = config
        self.api_host = self.config_get('tenders_api_server')
        self.api_version = self.config_get('tenders_api_version')
        self.retrievers_params = self.config_get('retrievers_params')

        try:
            self.client = TendersClient(host_url=self.api_host,
                                        api_version=self.api_version, key='')
        except MissingSchema:
            raise DataBridgeConfigError('In config dictionary empty or missing \
                \'tenders_api_server\'')
        except ConnectionError as e:
            raise e

    def config_get(self, name):
        try:
            return self.config.get('main').get(name)
        except AttributeError as e:
            raise DataBridgeConfigError('In config dictionary missed section \
                \'main\'')

    def decrypt_bid_files(self, tender, bid):
        decrypt_count = 0
        if 'documents' in bid:
            for document in bid.documents:
                if 'secret_key' in document:
                    encrypted_file = self.client.get_file(tender, document.url)
                    decrypted_file = decrypt_file(document.secret_key,
                                                  encrypted_file)
                    self.client.update_bid_document(decrypt_file, tender,
                                                    bid.id, document.id)
                    logger.info(
                        'Decrypt file {} of bid {} and updated.'.format(
                            document.id, bid.id
                        ),
                        extra={'MESSAGE_ID': 'update_decrypted_file'})
                    decrypt_count += 1
        logger.info('Decrypted {} documents of bid {}'.format(decrypt_count,
                                                              bid.id),
                    extra={'MESSAGE_ID': 'decrypted_bid'})

    def get_teders_list(self):
        for item in self.client.get_tenders(
            feed=None,
            params={'mode': '_all_', 'opt_fields': 'status'},
        ):
            if item['status'] == BID_DOCUMENTS_DECRYPT_STATUS:
                yield (item["id"])

    def run(self):
        logger.info('Start Encrypt Bridge',
                    extra={'MESSAGE_ID': 'encrypt_bridge_start_bridge'})
        logger.info('Start data sync...',
                    extra={'MESSAGE_ID': 'encrypt_bridge_data_sync'})
        for tender_id in self.get_teders_list():
            tender = self.client.get_tender(tender_id)
            print tender.data.id
            logger.info('Getting tender {} with status({})'
                        .format(tender_id, BID_DOCUMENTS_DECRYPT_STATUS))
            bids = self.client._get_tender_resource_list(tender, 'bids')
            for bid in bids.data:
                self.decrypt_bid_files(tender, bid)
            tender = self.client.patch_tender({
                'data': {
                    'id': tender.data.id,
                    'status': 'active.qualification'
                }
            })
            if tender.status == 'active.qualification':
                logger.info(
                    'Patch tender {} status (active.qualification)'.format(
                        tender.id
                    ), extra={'MESSAGE_ID': 'patch_tender_status'})


def main():
    parser = argparse.ArgumentParser(description='---- Encrypt Bridge ----')
    parser.add_argument('config', type=str, help='Path to configuration file')
    params = parser.parse_args()
    if os.path.isfile(params.config):
        with open(params.config) as config_file_obj:
            config = load(config_file_obj.read())
        logging.config.dictConfig(config)
        EncryptDataBridge(config).run()


##############################################################

if __name__ == "__main__":
    main()
