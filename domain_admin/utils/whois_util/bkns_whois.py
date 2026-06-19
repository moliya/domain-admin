# -*- coding: utf-8 -*-
"""
BKNS WHOIS HTTP fallback.
"""
from __future__ import print_function, unicode_literals, absolute_import, division

import traceback

import requests
from dateutil import parser

from domain_admin.log import logger

BKNS_LOOKUP_URL = 'https://whois.bkns.vn/api/internal/lookup'


def get_domain_info_with_fallback(domain, default_query):
    """
    Query the original WHOIS provider first, then fall back to BKNS if expiry is unavailable.
    :param domain: str
    :param default_query: callable
    :return: dict | None
    """
    default_result = None

    try:
        default_result = default_query(domain)
    except Exception:
        logger.error(traceback.format_exc())

    if default_result and default_result.get('expire_time'):
        return default_result

    fallback_result = get_bkns_domain_info(domain)
    if fallback_result and fallback_result.get('expire_time'):
        return fallback_result

    return default_result


def get_bkns_domain_info(domain):
    """
    Query BKNS HTTP WHOIS API and normalize the response to the project WHOIS format.
    :param domain: str
    :return: dict | None
    """
    try:
        response = requests.get(BKNS_LOOKUP_URL, params={'domain': domain}, timeout=10)
        if not response.ok:
            return None

        return parse_bkns_response(response.json())
    except Exception:
        logger.error(traceback.format_exc())
        return None


def parse_bkns_response(data):
    """
    Convert BKNS JSON response to the existing whois_util.get_domain_info response shape.
    :param data: dict
    :return: dict | None
    """
    if not data or data.get('status') != 'registered':
        return None

    payload = data.get('data') or {}
    dates = payload.get('dates') or {}
    expiry = dates.get('expiry')

    if not expiry:
        return None

    created = dates.get('created')
    registrar = payload.get('registrar') or {}

    return {
        'start_time': _parse_time(created),
        'expire_time': _parse_time(expiry),
        'registrar': (registrar.get('name') or '').strip(),
        'registrar_url': '',
    }


def _parse_time(value):
    if not value:
        return None

    return parser.parse(value).replace(tzinfo=None)
