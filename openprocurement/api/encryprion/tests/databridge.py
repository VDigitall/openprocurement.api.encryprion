# -*- coding: utf-8 -*-
import unittest
import webtest
import uuid
from openprocurement.api.encryprion.databridge import EncryptDataBridge
from openprocurement.api.encryprion.databridge import DataBridgeConfigError
from mock import MagicMock, patch
import datetime
import io
import os
import logging
from requests.exceptions import ConnectionError
from StringIO import StringIO
from openprocurement.api.encryprion.utils import generate_secret_key
from openprocurement.api.encryprion.utils import encrypt_file
from openprocurement.api.encryprion.databridge import BID_DOCUMENTS_DECRYPT_STATUS
from munch import munchify
import simplejson

logger = logging.getLogger()
logger.level = logging.DEBUG

ROOT = os.path.dirname(__file__) + '/data/'


class TestEncryptDataBridge(unittest.TestCase):
    config = {
        'main': {
            'tenders_api_server': 'https://lb.api-sandbox.openprocurement.org',
            'tenders_api_version': "0",
            'public_tenders_api_server': 'https://lb.api-sandbox.openprocurement.org'
        },
        'version': 1
    }

    def test_init(self):
        bridge = EncryptDataBridge(self.config)
        self.assertIn('tenders_api_server', bridge.config['main'])
        self.assertIn('tenders_api_version', bridge.config['main'])
        self.assertIn('public_tenders_api_server', bridge.config['main'])
        test_config = {}

        # Create EncryptDataBridge object with wrong config variable structure
        test_config = {
           'mani': {
                'tenders_api_server': 'https://lb.api-sandbox.openprocurement.org',
                'tenders_api_version': "0",
                'public_tenders_api_server': 'https://lb.api-sandbox.openprocurement.org',
            },
           'version': 1
        }
        with self.assertRaises(DataBridgeConfigError):
            EncryptDataBridge(test_config)

        # Create EncryptDataBridge object with wrong tenders_api_server
        test_config['main'] = {}
        test_config['main']['tenders_api_server'] = 'https://lb.api-sandbox.openprocurement.or'
        with self.assertRaises(ConnectionError):
            EncryptDataBridge(test_config)

        test_config['main']['tenders_api_server'] = 'https://lb.api-sandbox.openprocurement.org'
        test_config['main']['tenders_api_version'] = "0"

        del test_config['main']['tenders_api_version']
        bridge = EncryptDataBridge(test_config)
        self.assertEqual(type(bridge), EncryptDataBridge)
        with self.assertRaises(KeyError):
            test_config['main']['tenders_api_version']
        del bridge

    @patch('openprocurement_client.client.TendersClient.get_tenders')
    def test_get_tenders_list(self, mock_get_tenders):
        tid = uuid.uuid4().hex
        t_date_modified = datetime.datetime.utcnow().isoformat()
        mock_get_tenders.return_value = [{'id': tid, 'status': BID_DOCUMENTS_DECRYPT_STATUS}]
        bridge = EncryptDataBridge(self.config)
        for tender_id in bridge.get_tenders_list():
            self.assertEqual(tender_id, tid)

    @patch('openprocurement_client.client.TendersClient.get_file')
    @patch('openprocurement_client.client.TendersClient.update_bid_document')
    def test_decrypt_bid_files(self, mock_update_bid_document, mock_get_file):
        log_string = io.BytesIO()
        stream_handler = logging.StreamHandler(log_string)
        logger.addHandler(stream_handler)
        tender = munchify({
            'data': {
                'id': uuid.uuid4().hex,
                'status': 'active.qualification.decrypt'
            }
        })
        decrypted_file = StringIO()
        decrypted_file.write('Very secret information\n')
        secret_key = generate_secret_key()
        decrypted_file.seek(0)
        encrypted_file = encrypt_file(secret_key, decrypted_file)
        mock_get_file.return_value = (encrypted_file.getvalue(), 'secret.docx')
        with open(ROOT + 'bids.json') as json_file:
            bids = simplejson.load(json_file)['data']
        bids[0]['documents'][0]['secret_key'] = secret_key
        bids[1]['documents'][0]['secret_key'] = ''
        bids = munchify(bids)
        bridge = EncryptDataBridge(self.config)
        bridge.decrypt_bid_files(tender, bids[0])
        bridge.decrypt_bid_files(tender, bids[1])
        bids[1].documents[0].secret_key = '!V#N' * 16
        bridge.decrypt_bid_files(tender, bids[1])
        tender.data.status = ''
        x = log_string.getvalue().split('\n')
        self.assertEqual(x[1], 'Decrypt file {} of bid {} and updated.'.format(
            bids[0]['documents'][0].id, bids[0].id))
        self.assertEqual(x[2], 'Decrypted 1 documents of bid {}'.format(
            bids[0].id))
        self.assertEqual(x[3], 'Invalid length decrypt key for document {} bid {} tender {}'.format(
            bids[1].documents[0].id, bids[1].id, tender.data.id
        ))
        self.assertEqual(x[4], 'Decrypted 0 documents of bid {}'.format(
            bids[1].id))
        self.assertEqual(x[5], 'Invalid decrypt key: Non-hexadecimal digit found. For document {} bid {} tender {}'.format(
            bids[1].documents[0].id, bids[1].id, tender.data.id
        ))
        self.assertEqual(x[6], 'Decrypted 0 documents of bid {}'.format(
            bids[1].id))
        logger.removeHandler(stream_handler)
        log_string.close()

    @patch('openprocurement_client.client.TendersClient.get_tenders')
    @patch('openprocurement_client.client.TendersClient.get_tender')
    @patch('openprocurement_client.client.TendersClient._get_tender_resource_list')
    @patch('openprocurement_client.client.TendersClient.patch_tender')
    def test_run(self, mock_patch_tender, mock__get_tender_resource_list,
                 mock_get_tender, mock_get_tenders):
        log_string = io.BytesIO()
        stream_handler = logging.StreamHandler(log_string)
        logger.addHandler(stream_handler)
        with open(ROOT + 'tenders_with_decrypted_bids_documents.json') as json:
            tender = munchify(simplejson.load(json))
        tender.data.status = 'active.qualification.decrypt'
        mock_get_tenders.return_value = [{
            'id': tender.data.id,
            'status': tender.data.status
        }]
        mock_get_tender.return_value = tender
        mock__get_tender_resource_list.return_value = tender.data.bids
        mock_patch_tender.return_value = munchify({
            'data': {
                'id': tender.data.id,
                'status': 'active.qualification'
            }
        })
        bridge = EncryptDataBridge(self.config)
        bridge.run()
        x = log_string.getvalue().split('\n')
        self.assertEqual(x[3], 'Getting tender {} with status (active.qualification.decrypt)'.format(
            tender.data.id))
        for i in xrange(0, 3):
            self.assertEqual(x[4+i], 'Decrypted 0 documents of bid {}'.format(
                tender.data.bids[i].id))
        self.assertEqual(x[7], 'Patch tender {} status (active.qualification)'.format(
            tender.data.id))
        log_string = io.BytesIO()
        stream_handler = logging.StreamHandler(log_string)
        logger.addHandler(stream_handler)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestEncryptDataBridge))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
