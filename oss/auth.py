# -*- coding: utf-8 -*-


from . import utils
import logging
import hmac
import hashlib
import time
from .compat import urlquote, to_bytes

logger = logging.getLogger(__name__)


# removed items for signatures match: 'referer'
class Auth(object):
    _subresource_key_set = frozenset(
        ['response-content-type', 'response-content-language',
         'response-cache-control', 'response-content-encoding',
         'acl', 'uploadId', 'uploads', 'partNumber', 'group', 'link',
         'delete', 'website', 'location', 'objectInfo', 'logging',
         'response-expires', 'response-content-disposition', 'cors',
         'restore', 'qos', 'stat', 'bucketInfo', 'security-token', 'lifecycle',
         'live', 'comp', 'status', 'vod', 'startTime', 'endTime', 'x-oss-process',
         'symlink', 'callback', 'callback-var', 'tagging', 'encryption', 'versions',
         'versioning', 'versionId', 'policy', 'requestPayment', 'x-oss-traffic-limit']
    )

    def __init__(self, access_key_id, access_key_secret):
        self.access_key_id = access_key_id.strip()
        self.secret = access_key_secret.strip()

    def _sign_request(self, req, bucket_name, key):
        req.headers['date'] = utils.http_date()

        signature = self.__make_signature(req, bucket_name, key)
        req.headers['authorization'] = "OSS {0}:{1}".format(self.access_key_id, signature)

    def _sign_url(self, req, bucket_name, key, expires):
        expiration_time = int(time.time()) + expires

        req.headers['date'] = str(expiration_time)
        signature = self.__make_signature(req, bucket_name, key)

        req.params['AccessKeyId'] = self.access_key_id
        req.params['Expires'] = str(expiration_time)
        req.params['Signature'] = signature

        return req.url + '?' + '&'.join(_param_to_quoted_query(k, v) for k, v in req.params.items())

    def __make_signature(self, req, bucket_name, key):
        string_to_sign = self.__get_string_to_sign(req, bucket_name, key)
        logger.debug('Make signature: string to be signed = {0}'.format(string_to_sign))

        h = hmac.new(to_bytes(self.secret), to_bytes(string_to_sign), hashlib.sha1)
        return utils.b64encode_as_string(h.digest())

    def __get_string_to_sign(self, req, bucket_name, key):
        resource_string = self.__get_resource_string(req, bucket_name, key)
        headers_string = self.__get_headers_string(req)

        content_md5 = req.headers.get('content-md5', '')
        content_type = req.headers.get('content-type', '')
        date = req.headers.get('date', '')
        return '\n'.join([req.method,
                          content_md5,
                          content_type,
                          date,
                          headers_string + resource_string])

    def __get_headers_string(self, req):
        headers = req.headers
        canon_headers = []
        for k, v in headers.items():
            lower_key = k.lower()
            if lower_key.startswith('x-oss-'):
                canon_headers.append((lower_key, v))

        canon_headers.sort(key=lambda x: x[0])

        if canon_headers:
            return '\n'.join(k + ':' + v for k, v in canon_headers) + '\n'
        else:
            return ''

    def __get_resource_string(self, req, bucket_name, key):
        if not bucket_name:
            return '/'
        else:
            return '/{0}/{1}{2}'.format(bucket_name, key, self.__get_subresource_string(req.params))

    def __get_subresource_string(self, params):
        if not params:
            return ''

        subresource_params = []
        for key, value in params.items():
            if key in self._subresource_key_set:
                subresource_params.append((key, value))

        subresource_params.sort(key=lambda e: e[0])

        if subresource_params:
            return '?' + '&'.join(self.__param_to_query(k, v) for k, v in subresource_params)
        else:
            return ''

    def __param_to_query(self, k, v):
        if v:
            return k + '=' + v
        else:
            return k


def _param_to_quoted_query(k, v):
    if v:
        return urlquote(k, '') + '=' + urlquote(v, '')
    else:
        return urlquote(k, '')
