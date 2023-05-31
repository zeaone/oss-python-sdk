# -*- coding: utf-8 -*-

import logging

from . import xml_utils
from . import utils

from .compat import urlquote, urlparse, to_unicode, to_string
from . import defaults

from . import entity
from .entity import *
from .headers import *

from . import exceptions
from . import http
import shutil

logger = logging.getLogger(__name__)


def _normalize_endpoint(endpoint):
    if not endpoint.startswith('http://') and not endpoint.startswith('https://'):
        return 'http://' + endpoint
    else:
        return endpoint


class Base(object):
    def __init__(self, auth, endpoint, is_cname, session, connect_timeout,
                 app_name='', enable_crc=True):
        self.auth = auth
        self.endpoint = _normalize_endpoint(endpoint.strip())
        self.session = session or http.Session()
        self.timeout = defaults.get(connect_timeout, defaults.connect_timeout)
        self.app_name = app_name
        self.enable_crc = enable_crc

        self._make_url = _UrlMaker(self.endpoint, is_cname)

    def _do(self, method, bucket_name, key, **kwargs):
        key = to_string(key)
        if key.endswith('/'):
            key = urlquote(key.rstrip('/'), '') + '/'
        else:
            key = urlquote(key, '')
        req = http.Request(method, self._make_url(bucket_name, key),
                           app_name=self.app_name,
                           **kwargs)
        self.auth._sign_request(req, bucket_name, key)
        resp = self.session.do_request(req, timeout=self.timeout)
        if resp.status // 100 != 2:
            e = exceptions.make_exception(resp)
            # logger.info("Exception: {0}".format(e))
            raise e

        # Note that connections are only released back to the pool for reuse once all body data has been read;
        # be sure to either set stream to False or read the content property of the Response object.
        # For more details, please refer to http://docs.python-requests.org/en/master/user/advanced/#keep-alive.
        content_length = entity._hget(resp.headers, 'content-length', int)
        if content_length is not None and content_length == 0:
            resp.read()

        return resp

    def _do_url(self, method, sign_url, **kwargs):
        req = http.Request(method, sign_url, app_name=self.app_name, **kwargs)
        resp = self.session.do_request(req, timeout=self.timeout)
        if resp.status // 100 != 2:
            e = exceptions.make_exception(resp)
            logger.info("Exception: {0}".format(e))
            raise e

        # Note that connections are only released back to the pool for reuse once all body data has been read;
        # be sure to either set stream to False or read the content property of the Response object.
        # For more details, please refer to http://docs.python-requests.org/en/master/user/advanced/#keep-alive.
        content_length = entity._hget(resp.headers, 'content-length', int)
        if content_length is not None and content_length == 0:
            resp.read()

        return resp
    def _parse_result(self, resp, parse_func, klass):
        result = klass(resp)
        pyversion = sys.version
        if (pyversion[0] == '3'):
            body = resp.read().decode()
        elif (pyversion[0] == '2'):
            body = resp.read()
        else:
            print("python version error!\n")
        body = body.replace('xmlns="http://s3.amazonaws.com/doc/2006-03-01/"', '')
        parse_func(result, body)
        return result


class Service(Base):
    def __init__(self, auth, endpoint,
                 session=None,
                 connect_timeout=None,
                 app_name=''):
        # logger.debug("Init oss service, endpoint: {0}, connect_timeout: {1}, app_name: {2}".format(
        #     endpoint, connect_timeout, app_name))
        super(Service, self).__init__(auth, endpoint, False, session, connect_timeout,
                                      app_name=app_name)

    def list_buckets(self, prefix='', marker='', max_keys=100, params=None):
        listParam = {}
        listParam['prefix'] = prefix
        listParam['marker'] = marker
        listParam['max-keys'] = str(max_keys)

        if params is not None:
            if 'tag-key' in params:
                listParam['tag-key'] = params['tag-key']
            if 'tag-value' in params:
                listParam['tag-value'] = params['tag-value']

        resp = self._do('GET', '', '', params=listParam)
        # logger.debug("List buckets done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_list_buckets, ListBucketsResult)


class Bucket(Base):
    ACL = 'acl'
    CORS = 'cors'
    LIFECYCLE = 'lifecycle'
    LOCATION = 'location'
    LOGGING = 'logging'
    REFERER = 'referer'
    WEBSITE = 'website'
    LIVE = 'live'
    COMP = 'comp'
    STATUS = 'status'
    VOD = 'vod'
    SYMLINK = 'symlink'
    STAT = 'stat'
    BUCKET_INFO = 'bucketInfo'
    PROCESS = 'x-oss-process'
    TAGGING = 'tagging'
    ENCRYPTION = 'encryption'
    VERSIONS = 'versions'
    VERSIONING = 'versioning'
    VERSIONID = 'versionId'
    RESTORE = 'restore'
    OBJECTMETA = 'objectMeta'
    POLICY = 'policy'
    REQUESTPAYMENT = 'requestPayment'
    QUOTA = 'quota'

    def __init__(self, auth, endpoint, bucket_name, is_cname=False, session=None, connect_timeout=None, app_name='',
                 enable_crc=True):
        super(Bucket, self).__init__(auth, endpoint, is_cname, session, connect_timeout, app_name, enable_crc)
        self.bucket_name = bucket_name.strip()

    def create_bucket(self, acl=None, bucket_config=None):
        if acl:
            headers = {OSS_CANNED_ACL: acl}
        else:
            headers = None

        data = self.__convert_data(BucketCreateConfig, xml_utils.to_create_bucket_config, bucket_config)
        logger.debug("Start to create bucket, bucket: {0}, permission: {1}, config: {2}".format(self.bucket_name,
                                                                                                acl, data))
        print('data = ' + str(data))
        res = self.__do_bucket('PUT', headers=headers, data=data)

        logger.debug("Create bucket done, req_id: {0}, status_code: {1}".format(res.request_id, res.status))
        return RequestResult(res)

    def delete_bucket(self):
        """删除一个Bucket。只有没有任何文件，也没有任何未完成的分片上传的Bucket才能被删除。

        :return: :class:`RequestResult <oss.entity.RequestResult>`

        ":raises: 如果试图删除一个非空Bucket，则抛出 :class:`BucketNotEmpty <oss.exceptions.BucketNotEmpty>`
        """
        logger.info("Start to delete bucket, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('DELETE')
        logger.debug("Delete bucket done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def does_bucket_exist(self):
        """判断bucket是否存在

        :return: :class:`bool`
        """
        try:
            self.get_bucket_acl()
        except oss.NoSuchBucket:
            return False
        else:
            return True

    def get_bucket_location(self):
        """获取Bucket的数据中心。

        :return: :class:`GetBucketLocationResult <oss.entity.GetBucketLocationResult>`
        """
        logger.debug("Start to get bucket location, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('GET', params={Bucket.LOCATION: ''})
        logger.debug("Get bucket location done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_get_bucket_location, GetBucketLocationResult)

    def get_bucket_acl(self):
        """获取Bucket的ACL。

        :return: :class:`GetBucketAclResult <oss.entity.GetBucketAclResult>`
        """
        logger.debug("Start to get bucket acl, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('GET', params={Bucket.ACL: ''})
        logger.debug("Get bucket acl done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_get_bucket_acl, GetBucketAclResult)

    def put_bucket_acl(self, permission):
        """设置Bucket的ACL。

        :param str permission: 新的ACL，可以是oss.BUCKET_ACL_PRIVATE、oss.BUCKET_ACL_PUBLIC_READ或
            oss.BUCKET_ACL_PUBLIC_READ_WRITE
        """
        logger.debug("Start to put bucket acl, bucket: {0}, acl: {1}".format(self.bucket_name, permission))
        resp = self.__do_bucket('PUT', headers={OSS_CANNED_ACL: permission}, params={Bucket.ACL: ''})
        logger.debug("Put bucket acl done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    
    # def put_bucket_referer(self,  input):
    #      """设置Bucket的防盗链配置。

    #     :param oss.BucketReferer input: 防盗链配置，由是否允许空referer及防盗链列表组成
        
    #     """
    #     data = self.__convert_data(BucketReferer, xml_utils.to_put_bucket_referer, input)
    #     logger.debug("Start to put bucket referer, bucket: {0}, referer: {1}".format(self.bucket_name, to_string(data)))
    #     resp = self.__do_bucket('PUT', data=data, params={Bucket.REFERER: ''})
    #     logger.debug("Put bucket referer done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
    #     return RequestResult(resp)

    def get_bucket_referer(self):
        """获取Bucket的防盗链配置。

        :return: :class:`GetBucketRefererResult <oss2.entity.GetBucketRefererResult>`
        """
        logger.debug("Start to get bucket referer, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('GET', params={Bucket.REFERER: ''})
        logger.debug("Get bucket referer done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_get_bucket_referer, GetBucketRefererResult)

    def remove_bucket_referer(self):
        self.put_bucket_referer(BucketReferer(True, []))


    ################################################
    def put_quota(self, quotaSizeMB):
        logger.debug("Start to put bucket quota")
        resp = self.__do_bucket('PUT', headers={OSS_QUOTA_SIZE: quotaSizeMB}, params={Bucket.QUOTA: ''})
        logger.debug("Put bucket quota done")
        return RequestResult(resp)
    ################################################

    def put_object_from_file(self, key, filename,
                             headers=None,
                             progress_callback=None):
        """上传一个本地文件到OSS的普通文件。

        :param str key: 上传到OSS的文件名
        :param str filename: 本地文件名，需要有可读权限

        :param headers: 用户指定的HTTP头部。可以指定Content-Type、Content-MD5、x-oss-meta-开头的头部等
        :type headers: 可以是dict，建议是oss.CaseInsensitiveDict

        :param progress_callback: 用户指定的进度回调函数。参考 :ref:`progress_callback`

        :return: :class:`PutObjectResult <oss.entity.PutObjectResult>`
        """
        headers = utils.set_content_type(http.CaseInsensitiveDict(headers), filename)
        logger.debug("Put object from file, bucket: {0}, key: {1}, file path: {2}".format(
            self.bucket_name, to_string(key), filename))
        with open(to_unicode(filename), 'rb') as f:
            return self.put_object(key, f, headers=headers, progress_callback=progress_callback)

    def put_object(self, key, data, headers=None, progress_callback=None):

        headers = utils.set_content_type(http.CaseInsensitiveDict(headers), key)

        if progress_callback:
            data = utils.make_progress_adapter(data, progress_callback)

        if self.enable_crc:
            data = utils.make_crc_adapter(data)

        logger.debug("Start to put object, bucket: {0}, key: {1}, headers: {2}".format(self.bucket_name, to_string(key),
                                                                                       headers))
        resp = self.__do_object('PUT', key, data=data, headers=headers)
        logger.debug("Put object done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        result = PutObjectResult(resp)

        if self.enable_crc and result.crc is not None:
            utils.check_crc('put object', data.crc, result.crc, result.request_id)

        return result

    def append_object(self, key, position, data,
                      headers=None,
                      progress_callback=None,
                      init_crc=None):
        """追加上传一个文件。

        :param str key: 新的文件名，或已经存在的可追加文件名
        :param int position: 追加上传一个新的文件， `position` 设为0；追加一个已经存在的可追加文件， `position` 设为文件的当前长度。
            `position` 可以从上次追加的结果 `AppendObjectResult.next_position` 中获得。

        :param data: 用户数据
        :type data: str、bytes、file-like object或可迭代对象

        :param headers: 用户指定的HTTP头部。可以指定Content-Type、Content-MD5、x-oss-开头的头部等
        :type headers: 可以是dict，建议是oss2.CaseInsensitiveDict

        :param progress_callback: 用户指定的进度回调函数。参考 :ref:`progress_callback`

        :return: :class:`AppendObjectResult <oss2.entity.AppendObjectResult>`

        :raises: 如果 `position` 和当前文件长度不一致，抛出 :class:`PositionNotEqualToLength <oss2.exceptions.PositionNotEqualToLength>` ；
                 如果当前文件不是可追加类型，抛出 :class:`ObjectNotAppendable <oss2.exceptions.ObjectNotAppendable>` ；
                 还会抛出其他一些异常
        """
        headers = utils.set_content_type(http.CaseInsensitiveDict(headers), key)

        if progress_callback:
            data = utils.make_progress_adapter(data, progress_callback)

        if self.enable_crc and init_crc is not None:
            data = utils.make_crc_adapter(data, init_crc)

        logger.debug("Start to append object, bucket: {0}, key: {1}, headers: {2}, position: {3}".format(
            self.bucket_name, to_string(key), headers, position))
        resp = self.__do_object('PUT', key,
                                data=data,
                                headers=headers,
                                params={'append': '', 'position': str(position)})
        logger.debug("Append object done, req_id: {0}, statu_code: {1}".format(resp.request_id, resp.status))
        result = AppendObjectResult(resp)

        if self.enable_crc and result.crc is not None and init_crc is not None:
            utils.check_crc('append object', data.crc, result.crc, result.request_id)

        return result


    def init_multipart_upload(self, key, headers=None):
        headers = utils.set_content_type(http.CaseInsensitiveDict(headers), key)

        logger.debug("Start to init multipart upload, bucket: {0}, keys: {1}, headers: {2}".format(
            self.bucket_name, to_string(key), headers))
        resp = self.__do_object('POST', key, params={'uploads': ''}, headers=headers)
        logger.debug("Init multipart upload done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_init_multipart_upload, InitMultipartUploadResult)

    def upload_part(self, key, upload_id, part_number, data, progress_callback=None, headers=None):
        headers = http.CaseInsensitiveDict(headers)

        if progress_callback:
            data = utils.make_progress_adapter(data, progress_callback)

        if self.enable_crc:
            data = utils.make_crc_adapter(data)

        logger.debug(
            "Start to upload multipart, bucket: {0}, key: {1}, upload_id: {2}, part_number: {3}, headers: {4}".format(
                self.bucket_name, to_string(key), upload_id, part_number, headers))
        params = {'uploadId': upload_id, 'partNumber': str(part_number)}
        resp = self.__do_object('PUT', key, params=params, headers=headers, data=data)
        logger.debug("Upload multipart done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        result = PutObjectResult(resp)

        if self.enable_crc and result.crc is not None:
            utils.check_crc('upload part', data.crc, result.crc, result.request_id)

        return result

    def complete_multipart_upload(self, key, upload_id, parts, headers=None):
        headers = http.CaseInsensitiveDict(headers)
        parts = sorted(parts, key=lambda p: p.part_number)
        data = xml_utils.to_complete_upload_request(parts)

        logger.debug("Start to complete multipart upload, bucket: {0}, key: {1}, upload_id: {2}, parts: {3}".format(
            self.bucket_name, to_string(key), upload_id, data))

        resp = self.__do_object('POST', key,
                                params={'uploadId': upload_id},
                                data=data,
                                headers=headers)
        logger.debug(
            "Complete multipart upload done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))

        result = PutObjectResult(resp)

        if self.enable_crc:
            object_crc = utils.calc_obj_crc_from_parts(parts)
            utils.check_crc('resumable upload', object_crc, result.crc, result.request_id)

        return result

    def abort_multipart_upload(self, key, upload_id, headers=None):

        logger.debug("Start to abort multipart upload, bucket: {0}, key: {1}, upload_id: {2}".format(
            self.bucket_name, to_string(key), upload_id))

        headers = http.CaseInsensitiveDict(headers)

        resp = self.__do_object('DELETE', key,
                                params={'uploadId': upload_id}, headers=headers)
        logger.debug("Abort multipart done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def get_object(self, key,
                   byte_range=None,
                   headers=None,
                   progress_callback=None,
                   process=None,
                   params=None):
        """下载一个文件。

        用法 ::

            >>> result = bucket.get_object('readme.txt')
            >>> print(result.read())
            'hello world'

        :param key: 文件名
        :param byte_range: 指定下载范围。参见 :ref:`byte_range`

        :param headers: HTTP头部
        :type headers: 可以是dict，建议是oss.CaseInsensitiveDict

        :param progress_callback: 用户指定的进度回调函数。参考 :ref:`progress_callback`

        :param process: oss文件处理，如图像服务等。指定后process，返回的内容为处理后的文件。

        :param params: http 请求的查询字符串参数
        :type params: dict

        :return: file-like object

        :raises: 如果文件不存在，则抛出 :class:`NoSuchKey <oss.exceptions.NoSuchKey>` ；还可能抛出其他异常
        """
        headers = http.CaseInsensitiveDict(headers)

        range_string = _make_range_string(byte_range)
        if range_string:
            headers['range'] = range_string

        params = {} if params is None else params
        if process:
            params.update({Bucket.PROCESS: process})

        logger.debug("Start to get object, bucket: {0}， key: {1}, range: {2}, headers: {3}, params: {4}".format(
            self.bucket_name, to_string(key), range_string, headers, params))
        resp = self.__do_object('GET', key, headers=headers, params=params)
        logger.debug("Get object done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))

        return GetObjectResult(resp, progress_callback, self.enable_crc)

    def get_object_to_file(self, key, filename,
                           byte_range=None,
                           headers=None,
                           progress_callback=None,
                           process=None,
                           params=None):
        """下载一个文件到本地文件。

        :param key: 文件名
        :param filename: 本地文件名。要求父目录已经存在，且有写权限。
        :param byte_range: 指定下载范围。参见 :ref:`byte_range`

        :param headers: HTTP头部
        :type headers: 可以是dict，建议是oss2.CaseInsensitiveDict

        :param progress_callback: 用户指定的进度回调函数。参考 :ref:`progress_callback`

        :param process: oss文件处理，如图像服务等。指定后process，返回的内容为处理后的文件。

        :param params: http 请求的查询字符串参数
        :type params: dict

        :return: 如果文件不存在，则抛出 :class:`NoSuchKey <oss2.exceptions.NoSuchKey>` ；还可能抛出其他异常
        """
        logger.debug("Start to get object to file, bucket: {0}, key: {1}, file path: {2}".format(
            self.bucket_name, to_string(key), filename))
        with open(to_unicode(filename), 'wb') as f:
            result = self.get_object(key, byte_range=byte_range, headers=headers, progress_callback=progress_callback,
                                     process=process, params=params)

            if result.content_length is None:
                shutil.copyfileobj(result, f)
            else:
                utils.copyfileobj_and_verify(result, f, result.content_length, request_id=result.request_id)

            if self.enable_crc and byte_range is None:
                if (headers is None) or ('Accept-Encoding' not in headers) or (headers['Accept-Encoding'] != 'gzip'):
                    utils.check_crc('get', result.client_crc, result.server_crc, result.request_id)

            return result

    def delete_object(self, key, params=None, headers=None):
        """删除一个文件。

        :param str key: 文件名
        :param params: 请求参数

        :param headers: HTTP头部
        :type headers: 可以是dict，建议是oss.CaseInsensitiveDict

        :return: :class:`RequestResult <oss.entity.RequestResult>`
        """

        headers = http.CaseInsensitiveDict(headers)

        logger.info("Start to delete object, bucket: {0}, key: {1}".format(self.bucket_name, to_string(key)))
        resp = self.__do_object('DELETE', key, params=params, headers=headers)
        logger.debug("Delete object done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def batch_delete_objects(self, key_list, headers=None):
        """批量删除文件。待删除文件列表不能为空。

        :param key_list: 文件名列表，不能为空。
        :type key_list: list of str

        :param headers: HTTP头部

        :return: :class:`BatchDeleteObjectsResult <oss2.models.BatchDeleteObjectsResult>`
        """
        if not key_list:
            raise ClientError('key_list should not be empty')

        logger.debug("Start to delete objects, bucket: {0}, keys: {1}".format(self.bucket_name, key_list))

        data = xml_utils.to_batch_delete_objects_request(key_list, False)

        headers = http.CaseInsensitiveDict(headers)
        headers['Content-MD5'] = utils.content_md5(data)

        resp = self.__do_object('POST', '',
                                data=data,
                                params={'delete': '', 'encoding-type': 'url'},
                                headers=headers)
        logger.debug("Delete objects done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_batch_delete_objects, BatchDeleteObjectsResult)

    def list_objects(self, prefix='', delimiter='', marker='', max_keys=100, allow_unordered='false', headers=None):
        # type: (object, object, object, object, object) -> object
        """根据前缀罗列Bucket里的文件。

        :param str prefix: 只罗列文件名为该前缀的文件
        :param str delimiter: 分隔符。可以用来模拟目录
        :param str marker: 分页标志。首次调用传空串，后续使用返回值的next_marker
        :param int max_keys: 最多返回文件的个数，文件和目录的和不能超过该值

        :param headers: HTTP头部
        :type headers: 可以是dict，建议是oss.CaseInsensitiveDict

        :return: :class:`ListObjectsResult <oss.entity.ListObjectsResult>`
        """
        headers = http.CaseInsensitiveDict(headers)
        logger.debug(
            "Start to List objects, bucket: {0}, prefix: {1}, delimiter: {2}, marker: {3}, max-keys: {4}".format(
                self.bucket_name, to_string(prefix), delimiter, to_string(marker), max_keys))
        resp = self.__do_object('GET', '',
                                params={'prefix': prefix,
                                        'delimiter': delimiter,
                                        'marker': marker,
                                        'max-keys': str(max_keys),
                                        'allow_unordered': allow_unordered,
                                        'encoding-type': 'url'},
                                headers=headers)
        logger.debug("List objects done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_list_objects, ListObjectsResult)

    def get_object_meta(self, key, params=None, headers=None):
        """获取文件基本元信息，包括该Object的ETag、Size（文件大小）、LastModified，并不返回其内容。

        HTTP响应的头部包含了文件基本元信息，可以通过 `GetObjectMetaResult` 的 `last_modified`，`content_length`,`etag` 成员获得。

        :param key: 文件名
        :param dict params: 请求参数

        :param headers: HTTP头部
        :type headers: 可以是dict，建议是oss.CaseInsensitiveDict

        :return: :class:`GetObjectMetaResult <oss.entity.GetObjectMetaResult>`

        :raises: 如果文件不存在，则抛出 :class:`NoSuchKey <oss.exceptions.NoSuchKey>` ；还可能抛出其他异常
        """
        headers = http.CaseInsensitiveDict(headers)
        logger.debug("Start to get object metadata, bucket: {0}, key: {1}".format(self.bucket_name, to_string(key)))

        if params is None:
            params = dict()

        if Bucket.OBJECTMETA not in params:
            params[Bucket.OBJECTMETA] = ''

        resp = self.__do_object('GET', key, params=params, headers=headers)
        logger.debug("Get object metadata done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return GetObjectMetaResult(resp)

    def head_object(self, key, headers=None, params=None):
        """获取文件元信息。

        HTTP响应的头部包含了文件元信息，可以通过 `RequestResult` 的 `headers` 成员获得。
        用法 ::

            >>> result = bucket.head_object('readme.txt')
            >>> print(result.content_type)
            text/plain

        :param key: 文件名

        :param headers: HTTP头部
        :type headers: 可以是dict，建议是oss.CaseInsensitiveDict

        :param params: HTTP请求参数，传入versionId，获取指定版本Object元信息
        :type params: 可以是dict，建议是oss.CaseInsensitiveDict

        :return: :class:`HeadObjectResult <oss.entity.HeadObjectResult>`

        :raises: 如果Bucket不存在或者Object不存在，则抛出 :class:`NotFound <oss.exceptions.NotFound>`
        """
        logger.debug("Start to head object, bucket: {0}, key: {1}, headers: {2}".format(
            self.bucket_name, to_string(key), headers))

        resp = self.__do_object('HEAD', key, headers=headers, params=params)

        logger.debug("Head object done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return HeadObjectResult(resp)

    def put_bucket_lifecycle(self, input):
        """设置生命周期管理的配置。
            
        :param oss.BucketLifecycle input: 生命周期规则，创建时参数为生命周期规则组成的数组。
        """
        data = self.__convert_data(BucketLifecycle, xml_utils.to_put_bucket_lifecycle, input)
        headers = http.CaseInsensitiveDict()
        headers['Content-MD5'] = utils.content_md5(data)
        logger.debug("Start to put bucket lifecycle, bucket: {0}, lifecycle: {1}".format(self.bucket_name, data))
        resp = self.__do_bucket('PUT', data=data, params={Bucket.LIFECYCLE: ''}, headers=headers)
        logger.debug("Put bucket lifecycle done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def delete_bucket_lifecycle(self):
        """删除生命周期管理配置。

        :raises: 如果没有生命周期规则，则抛出 oss.NoSuchLifecycle
        """
        logger.debug("Start to delete bucket lifecycle, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('DELETE', params={Bucket.LIFECYCLE: ''})
        logger.debug("Delete bucket lifecycle done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def get_bucket_lifecycle(self):
        """获取生命周期配置。

        :return class:`GetBucketLifecycleResult <oss.entity.GetBucketLifecycleResult>`
        """
        logger.debug("Start to get bucket lifecycle, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('GET', params={Bucket.LIFECYCLE: ''})
        logger.debug("Get bucket lifecycle done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_get_bucket_lifecycle, GetBucketLifecycleResult)

    def object_exists(self, key, headers=None):
        """如果文件存在就返回True，否则返回False。如果Bucket不存在，或是发生其他错误，则抛出异常。"""
        #:param key: 文件名

        #:param headers: HTTP头部
        #:type headers: 可以是dict，建议是oss.CaseInsensitiveDict

        headers = http.CaseInsensitiveDict(headers)
        logger.debug("Start to check if object exists, bucket: {0}, key: {1}".format(self.bucket_name, to_string(key)))
        try:
            self.get_object_meta(key, headers=headers)
        except exceptions.NoSuchKey:
            return False
        except:
            raise

        return True

    def put_object_acl(self, key, permission):
        """设置文件的ACL。

        :param str key: 文件名
        :param str permission: 可以是oss.OBJECT_ACL_DEFAULT、oss.OBJECT_ACL_PRIVATE、oss.OBJECT_ACL_PUBLIC_READ或
            oss.OBJECT_ACL_PUBLIC_READ_WRITE。

        :return: :class:`RequestResult <oss.entity.RequestResult>`
        """
        logger.debug("Start to put object acl, bucket: {0}, key: {1}, acl: {2}".format(
            self.bucket_name, to_string(key), permission))

        resp = self.__do_object('PUT', key, headers={OSS_CANNED_ACL: permission}, params={Bucket.ACL: ''})
        logger.debug("Put object acl done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))

        return RequestResult(resp)

    def get_object_acl(self, key):
        """获取文件的ACL。

        :param key: 文件名
        :return: :class:`GetObjectAclResult <oss.entity.GetObjectAclResult>`
        """
        logger.debug("Start to get object acl, bucket: {0}, key: {1}".format(self.bucket_name, to_string(key)))
        resp = self.__do_object('GET', key, params={Bucket.ACL: ''})
        logger.debug("Get object acl done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_get_object_acl, GetObjectAclResult)

    def put_bucket_cors(self, input):
        """设置Bucket的CORS。

        :param input: :class:`BucketCors <oss2.entity.BucketCors>` 对象或其他
        """
        data = self.__convert_data(BucketCors, xml_utils.to_put_bucket_cors, input)
        logger.debug("Start to put bucket cors, bucket: {0}, cors: {1}".format(self.bucket_name, data))
        resp = self.__do_bucket('PUT', data=data, params={Bucket.CORS: ''})
        logger.debug("Put bucket cors done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def get_bucket_cors(self):
        """获取Bucket的CORS配置。

        :return: :class:`GetBucketCorsResult <oss2.entity.GetBucketCorsResult>`
        """
        logger.debug("Start to get bucket CORS, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('GET', params={Bucket.CORS: ''})
        logger.debug("Get bucket CORS done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_get_bucket_cors, GetBucketCorsResult)

    def delete_bucket_cors(self):
        """删除Bucket的CORS配置。"""
        logger.debug("Start to delete bucket CORS, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('DELETE', params={Bucket.CORS: ''})
        logger.debug("Delete bucket CORS done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def sign_url(self, method, key, expires, headers=None, params=None, slash_safe=False):
        """生成签名URL。

        常见的用法是生成加签的URL以供授信用户下载，如为log.jpg生成一个5分钟后过期的下载链接::

            >>> bucket.sign_url('GET', 'log.jpg', 5 * 60)
            r'http://your-bucket.oss.cn-north-3.cloudoss.com/logo.jpg?OSSAccessKeyId=wyb2-oss&Expires=1617074629&Signature=NId6LsLcoYlquYJpkgbhgUvLjfU%3D'

        :param method: HTTP方法，如'GET'、'PUT'、'DELETE'等
        :type method: str
        :param key: 文件名
        :param expires: 过期时间（单位：秒），链接在当前时间再过expires秒后过期

        :param headers: 需要签名的HTTP头部，如名称以x-oss-meta-开头的头部（作为用户自定义元数据）、
            Content-Type头部等。对于下载，不需要填。
        :type headers: 可以是dict，建议是oss.CaseInsensitiveDict

        :param params: 需要签名的HTTP查询参数

        :param slash_safe: 是否开启key名称中的‘/’转义保护，如果不开启'/'将会转义成%2F
        :type slash_safe: bool

        :return: 签名URL。
        """
        key = to_string(key)
        logger.debug(
            "Start to sign_url, method: {0}, bucket: {1}, key: {2}, expires: {3}, headers: {4}, params: {5}, slash_safe: {6}".format(
                method, self.bucket_name, to_string(key), expires, headers, params, slash_safe))
        if key.endswith('/'):
            key = urlquote(key.rstrip('/'), '') + '/'
        else:
            key = urlquote(key, '')
        url = self._make_url(self.bucket_name, key, slash_safe)
        req = http.Request(method, url, headers=headers, params=params)
        return self.auth._sign_url(req, self.bucket_name, key, expires)

    def put_object_with_url(self, sign_url, data, headers=None, progress_callback=None):

        """ 使用加签的url上传对象

        :param sign_url: 加签的url
        :param data: 待上传的数据
        :param headers: 用户指定的HTTP头部。可以指定Content-Type、Content-MD5、x-oss-meta-开头的头部等，必须和签名时保持一致
        :param progress_callback: 用户指定的进度回调函数。参考 :ref:`progress_callback`
        :return:
        """
        headers = http.CaseInsensitiveDict(headers)

        if progress_callback:
            data = utils.make_progress_adapter(data, progress_callback)

        if self.enable_crc:
            data = utils.make_crc_adapter(data)

        logger.debug("Start to put object with signed url, bucket: {0}, sign_url: {1}, headers: {2}".format(
            self.bucket_name, sign_url, headers))

        resp = self._do_url('PUT', sign_url, data=data, headers=headers)
        logger.debug("Put object with url done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        result = PutObjectResult(resp)

        if self.enable_crc and result.crc is not None:
            utils.check_crc('put object', data.crc, result.crc, result.request_id)

        return result

    def put_object_with_url_from_file(self, sign_url, filename,
                                      headers=None,
                                      progress_callback=None):
        """ 使用加签的url上传本地文件到oss

        :param sign_url: 加签的url
        :param filename: 本地文件路径
        :param headers: 用户指定的HTTP头部。可以指定Content-Type、Content-MD5、x-oss-meta-开头的头部等，必须和签名时保持一致
        :param progress_callback: 用户指定的进度回调函数。参考 :ref:`progress_callback`
        :return:
        """
        logger.debug("Put object from file with signed url, bucket: {0}, sign_url: {1}, file path: {2}".format(
            self.bucket_name, sign_url, filename))
        with open(to_unicode(filename), 'rb') as f:
            return self.put_object_with_url(sign_url, f, headers=headers, progress_callback=progress_callback)

    def __convert_data(self, klass, converter, data):
        if isinstance(data, klass):
            return converter(data)
        else:
            return data

###################################################
    def get_quota(self):
        logger.debug("Start to get quota")
        resp = self.__do_bucket('GET', params={Bucket.QUOTA: ''})
        logger.debug("Get quota done")
        return self._parse_result(resp, xml_utils.parse_get_bucket_quota, GetQuotaResult)

###################################################

    def put_bucket_logging(self, input):
        """为Bucket配置日志功能。

        :param input: :class:`BucketLogging <oss2.entity.BucketLogging>`
        """
        data = self.__convert_data(BucketLogging, xml_utils.to_put_bucket_logging, input)
        logger.debug("Start to put bucket logging, bucket: {0}, logging: {1}".format(self.bucket_name, data))
        resp = self.__do_bucket('PUT', data=data, params={Bucket.LOGGING: ''})
        logger.debug("Put bucket logging done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def get_bucket_logging(self):
        """获取Bucket的日志信息。

        :return: :class:`GetBucketLoggingResult <oss2.entity.GetBucketLoggingResult>`

        :raises: 如果没有设置静态网站托管，那么就抛出 :class:`NoSuchWebsite <oss2.exceptions.NoSuchWebsite>`
        """
        logger.debug("Start to get bucket logging, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('GET', params={Bucket.LOGGING: ''})
        logger.debug("Get bucket logging done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return self._parse_result(resp, xml_utils.parse_bucket_logging, GetBucketLoggingResult)

    def delete_bucket_logging(self):
        """删除Bucket的日志。如果没有日志也可正确运行。"""
        logger.debug("Start to delete bucket loggging, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('DELETE', params={Bucket.LOGGING: ''})
        logger.debug("Delete bucket lifecycle done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def put_bucket_website(self, input):
        """为Bucket配置静态网站托管功能。

        :param input: :class:`BucketWebsite <oss2.entity.BucketWebsite>`
        """
        data = self.__convert_data(BucketWebsite, xml_utils.to_put_bucket_website, input)
        headers = http.CaseInsensitiveDict()
        headers['Host'] = self.endpoint

        logger.debug("Start to put bucket website, bucket: {0}, website: {1}".format(self.bucket_name, to_string(data)))
        resp = self.__do_bucket('PUT', data=data, params={Bucket.WEBSITE: ''}, headers=headers)
        logger.debug("Put bucket website done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

    def get_bucket_website(self):
        """获取Bucket的静态网站托管配置。

        :return: :class:`GetBucketWebsiteResult <oss2.entity.GetBucketWebsiteResult>`

        :raises: 如果没有设置静态网站托管，那么就抛出 :class:`NoSuchWebsite <oss2.exceptions.NoSuchWebsite>`
        """

        logger.debug("Start to get bucket website, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('GET', params={Bucket.WEBSITE: ''})
        logger.debug("Get bucket website done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))

        return self._parse_result(resp, xml_utils.parse_bucket_website, GetBucketWebsiteResult)

    def delete_bucket_website(self):
        """关闭Bucket的静态网站托管功能。"""
        logger.debug("Start to delete bucket website, bucket: {0}".format(self.bucket_name))
        resp = self.__do_bucket('DELETE', params={Bucket.WEBSITE: ''})
        logger.debug("Delete bucket website done, req_id: {0}, status_code: {1}".format(resp.request_id, resp.status))
        return RequestResult(resp)

###################################################

    def __do_bucket(self, method, **kwargs):
        return self._do(method, self.bucket_name, '', **kwargs)

    def __do_object(self, method, key, **kwargs):
        return self._do(method, self.bucket_name, key, **kwargs)


_ENDPOINT_TYPE_ALIYUN = 0
_ENDPOINT_TYPE_CNAME = 1
_ENDPOINT_TYPE_IP = 2


def _make_range_string(range):
    if range is None:
        return ''

    start = range[0]
    last = range[1]

    if start is None and last is None:
        return ''

    return 'bytes=' + _range(start, last)


def _range(start, last):
    def to_str(pos):
        if pos is None:
            return ''
        else:
            return str(pos)

    return to_str(start) + '-' + to_str(last)


def _deletermine_endpoint_type(netloc, is_cname, bucket_name):
    if utils.is_ip_or_localhost(netloc):
        return _ENDPOINT_TYPE_IP

    if is_cname:
        return _ENDPOINT_TYPE_CNAME

    if utils.is_valid_bucket_name(bucket_name):
        return _ENDPOINT_TYPE_ALIYUN
    else:
        return _ENDPOINT_TYPE_IP


class _UrlMaker(object):
    def __init__(self, endpoint, is_cname):
        p = urlparse(endpoint)

        self.scheme = p.scheme
        self.netloc = p.netloc
        self.is_cname = is_cname

    def __call__(self, bucket_name, key, slash_safe=False):
        self.type = _deletermine_endpoint_type(self.netloc, self.is_cname, bucket_name)

        safe = '/' if slash_safe is True else ''
        # key = urlquote(key, safe=safe)

        if self.type == _ENDPOINT_TYPE_CNAME:
            return '{0}://{1}/{2}'.format(self.scheme, self.netloc, key)

        if self.type == _ENDPOINT_TYPE_IP:
            if bucket_name:
                return '{0}://{1}/{2}/{3}'.format(self.scheme, self.netloc, bucket_name, key)
            else:
                return '{0}://{1}/{2}'.format(self.scheme, self.netloc, key)

        if not bucket_name:
            assert not key
            return '{0}://{1}'.format(self.scheme, self.netloc)

        return '{0}://{1}.{2}/{3}'.format(self.scheme, bucket_name, self.netloc, key)
