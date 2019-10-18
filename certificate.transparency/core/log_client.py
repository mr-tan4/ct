import requests
import base64
from absl import flags
from proto import client_pb2
import logging
import json


class Error(Exception):
    pass


class InvalidResponseError(Error):
    pass


class HTTPError(Error):
    pass


FLAGS = flags.FLAGS

_GET_ROOTS_PATH = '{}ct/v1/get-roots'
_GET_ENTRIES_PATH = '{}ct/v1/get-entries?start={}&end={}'


def _parse_entry(json_entry):
    entry_response = client_pb2.ParsedEntry()
    try:
        entry_response.leaf_input = base64.b64decode(json_entry['leaf_input'])
        entry_response.extra_data = base64.b64decode(json_entry['extra_data'])
    except (TypeError, ValueError, KeyError) as e:
        raise InvalidResponseError("Invalid entry: %s\n%s" % (json_entry, e))
    return entry_response


def _parse_entries(entries_body):
    try:
        responses = json.loads(entries_body)
    except ValueError as e:
        raise InvalidResponseError("Invalid response %s\n%s" %
                                   (entries_body, e))

    try:
        entries = iter(responses['entries'])
    except(TypeError, KeyError) as e:
        raise InvalidResponseError("Invalid response: expected "
                                   "an array of entries, got %s\n%s)" %
                                   (responses, e))
    return [_parse_entry(e) for e in entries]


class LoginClient(object):
    ########################
    # 日志客户端             #
    # 用于获取roots和entries #
    ########################
    def __init__(self):
        self.url = 'https://ct.googleapis.com/logs/argon2017/'

    @property
    def servername(self):
        return self.url

    def get_entries(self, start, end):
        if start < 0 or end < 0 or start > end:
            raise InvalidResponseError()
        while start <= end:
            response = self._req_body(self.url, _GET_ENTRIES_PATH, params={'start': start, 'end': end})
            entries = _parse_entries(response)
            for entry in entries:
                yield entry
            start += len(entries)

    def get_roots(self):
        response = self._req_body(self.url, _GET_ROOTS_PATH, None)
        response = json.loads(response)
        try:
            return [base64.b64decode(u) for u in response['certificates']]
        except (TypeError, KeyError, ValueError) as e:
            raise InvalidResponseError()

    def _req_body(self, url, path, params=None):
        if url is not None:
            if params is not None:
                try:
                    start = params['start']
                    end = params['end']
                    path = path.format(url, start, end)
                except (ValueError, KeyError) as e:
                    raise InvalidResponseError()
            else:
                path = path.format(url)
        else:
            raise InvalidResponseError()
        try:
            html = requests.get(path, verify=False)
            return html.text
        except HTTPError as e:
            raise InvalidResponseError()
