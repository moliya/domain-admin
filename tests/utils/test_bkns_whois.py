# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals, absolute_import, division

import unittest
from datetime import datetime
from unittest import mock

from domain_admin.utils.whois_util import bkns_whois


class BknsWhoisTest(unittest.TestCase):
    def test_fallback_returns_default_result_when_default_query_has_expire_time(self):
        default_result = {
            'start_time': datetime(2026, 1, 1),
            'expire_time': datetime(2027, 1, 1),
            'registrar': 'Default Registrar',
            'registrar_url': 'https://example.com',
        }

        def default_query(domain):
            return default_result

        self.assertEqual(
            bkns_whois.get_domain_info_with_fallback('example.com', default_query),
            default_result
        )

    def test_fallback_queries_bkns_when_default_query_returns_none(self):
        bkns_result = {
            'start_time': datetime(2026, 3, 25, 6, 48),
            'expire_time': datetime(2027, 3, 25, 6, 48),
            'registrar': 'Cong ty TNHH phan mem Nhan Hoa',
            'registrar_url': '',
        }

        def default_query(domain):
            return None

        with mock.patch.object(bkns_whois, 'get_bkns_domain_info', return_value=bkns_result):
            self.assertEqual(
                bkns_whois.get_domain_info_with_fallback('anphongmall.vn', default_query),
                bkns_result
            )

    def test_parse_bkns_response_maps_dates_and_registrar(self):
        raw_data = {
            'status': 'registered',
            'data': {
                'registrar': {
                    'name': 'Cong ty TNHH phan mem Nhan Hoa',
                },
                'dates': {
                    'created': '2026-03-25T06:48:00.000Z',
                    'expiry': '2027-03-25T06:48:00.000Z',
                },
            },
        }

        result = bkns_whois.parse_bkns_response(raw_data)

        self.assertEqual(result['start_time'], datetime(2026, 3, 25, 6, 48))
        self.assertEqual(result['expire_time'], datetime(2027, 3, 25, 6, 48))
        self.assertEqual(result['registrar'], 'Cong ty TNHH phan mem Nhan Hoa')
        self.assertEqual(result['registrar_url'], '')
