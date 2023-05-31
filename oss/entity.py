# -*- coding: utf-8 -*-

from .utils import *
from .exceptions import *
from .compat import urlunquote, to_string, urlquote
from .select_response import SelectResponseAdapter
from .headers import *
import json


class RequestResult(object):
    def __init__(self, resp):
        #: HTTP响应
        self.resp = resp

        #: HTTP状态码
        self.status = resp.status

        #: HTTP头
        self.headers = resp.headers

        #: 请求ID，用于跟踪一个OSS请求。提交工单时，最后能够提供请求ID
        self.request_id = resp.request_id

        self.versionid = _hget(self.headers, 'x-oss-version-id')

        self.delete_marker = _hget(self.headers, 'x-oss-delete-marker', bool)


class SimplifiedBucketInfo(object):
    """:func:`list_buckets <oss.Service.list_objects>` 结果中的单个元素类型。"""

    def __init__(self, name, location, creation_date, extranet_endpoint, intranet_endpoint, storage_class):
        #: Bucket名
        self.name = name

        #: Bucket的区域
        self.location = location

        #: Bucket的创建时间，类型为int。参考 :ref:`unix_time`。
        self.creation_date = creation_date

        #: Bucket访问的外网域名
        self.extranet_endpoint = extranet_endpoint

        #: 同区域ECS访问Bucket的内网域名
        self.intranet_endpoint = intranet_endpoint

        #: Bucket存储类型，支持“Standard”、“IA”、“Archive”
        self.storage_class = storage_class


class AppendObjectResult(RequestResult):
    def __init__(self, resp):
        super(AppendObjectResult, self).__init__(resp)

        #: HTTP ETag
        self.etag = _get_etag(self.headers)

        #: 本次追加写完成后，OSS上文件的CRC64值
        self.crc = _hget(resp.headers, OSS_HASH_CRC64_ECMA, int)

        #: 下次追加写的偏移
        self.next_position = _hget(resp.headers, OSS_NEXT_APPEND_POSITION, int)


class ListBucketsResult(RequestResult):
    def __init__(self, resp):
        super(ListBucketsResult, self).__init__(resp)

        #: True表示还有更多的Bucket可以罗列；False表示已经列举完毕。
        self.is_truncated = False

        #: 下一次罗列的分页标记符，即，可以作为 :func:`list_buckets <oss.Service.list_buckets>` 的 `marker` 参数。
        self.next_marker = ''

        #: 得到的Bucket列表，类型为 :class:`SimplifiedBucketInfo` 。
        self.buckets = []


class BucketCreateConfig(object):
    def __init__(self, storage_class):
        self.storage_class = storage_class


class GetBucketLocationResult(RequestResult):
    def __init__(self, resp):
        super(GetBucketLocationResult, self).__init__(resp)

        #: Bucket所在的数据中心
        self.location = ''


class GetBucketAclResult(RequestResult):
    def __init__(self, resp):
        super(GetBucketAclResult, self).__init__(resp)

        #: Bucket的ACL，其值可以是 `BUCKET_ACL_PRIVATE`、`BUCKET_ACL_PUBLIC_READ`或`BUCKET_ACL_PUBLIC_READ_WRITE`。
        self.acl = ''


class GetQuotaResult(RequestResult):
    def __init__(self, resp):
        super(GetQuotaResult, self).__init__(resp)

        #: quota，模仿get acl实现的
        self.quota = ''


class GetObjectAclResult(RequestResult):
    def __init__(self, resp):
        super(GetObjectAclResult, self).__init__(resp)

        #: 文件的ACL，其值可以是 `OBJECT_ACL_DEFAULT`、`OBJECT_ACL_PRIVATE`、`OBJECT_ACL_PUBLIC_READ`或
        #: `OBJECT_ACL_PUBLIC_READ_WRITE`
        self.acl = ''


class Grantee(object):
    def __init__(self, id=None, display_name=None, uri=None):
        self.id = id
        self.display_name = display_name
        self.uri = uri


class Grant(object):
    def __init__(self, grantee, permission):
        self.grantee = grantee
        self.permission = permission


class Owner(object):
    def __init__(self, id, dispaly_name):
        self.id = id
        self.dispaly_name = dispaly_name


class Acl(object):
    def __init__(self, owner, grants):
        self.owner = owner
        self.grants = grants


class PutObjectResult(RequestResult):
    def __init__(self, resp):
        super(PutObjectResult, self).__init__(resp)

        #: HTTP ETag
        self.etag = _get_etag(self.headers)

        #: 文件上传后，OSS上文件的CRC64值
        self.crc = _hget(resp.headers, OSS_HASH_CRC64_ECMA, int)


class InitMultipartUploadResult(RequestResult):
    def __init__(self, resp):
        super(InitMultipartUploadResult, self).__init__(resp)

        self.upload_id = None


class PartInfo(object):
    """表示分片信息的文件。

    该文件既用于 :func:`list_parts <oss.Bucket.list_parts>` 的输出，也用于 :func:`complete_multipart_upload
    <oss.Bucket.complete_multipart_upload>` 的输入。

    :param int part_number: 分片号
    :param str etag: 分片的ETag
    :param int size: 分片的大小。用在 `list_parts` 的结果里，也用与分片对象做crc combine得到整个对象crc64值
    :param int last_modified: 该分片最后修改的时间戳，类型为int。参考 :ref:`unix_time`
    :param int part_crc: 该分片的crc64值
    """

    def __init__(self, part_number, etag, size=None, last_modified=None, part_crc=None):
        self.part_number = part_number
        self.etag = etag
        self.size = size
        self.last_modified = last_modified
        self.part_crc = part_crc


class HeadObjectResult(RequestResult):
    def __init__(self, resp):
        super(HeadObjectResult, self).__init__(resp)

        #: 文件类型，可以是'Normal'、'Multipart'、'Appendable'等
        self.object_type = _hget(self.headers, OSS_OBJECT_TYPE)

        #: 文件最后修改时间，类型为int。参考 :ref:`unix_time` 。

        self.last_modified = _hget(self.headers, 'last-modified', http_to_unixtime)

        #: 文件的MIME类型
        self.content_type = _hget(self.headers, 'content-type')

        #: Content-Length，可能是None。
        self.content_length = _hget(self.headers, 'content-length', int)

        #: HTTP ETag
        self.etag = _get_etag(self.headers)

        #: 文件 server_crc
        self._server_crc = _hget(self.headers, 'x-oss-hash-crc64ecma', int)

    @property
    def server_crc(self):
        return self._server_crc


class ListObjectsResult(RequestResult):
    def __init__(self, resp):
        super(ListObjectsResult, self).__init__(resp)

        #: True表示还有更多的文件可以罗列；False表示已经列举完毕。
        self.is_truncated = False

        #: 下一次罗列的分页标记符，即，可以作为 :func:`list_objects <oss.Bucket.list_objects>` 的 `marker` 参数。
        self.next_marker = ''

        #: 本次罗列得到的文件列表。其中元素的类型为 :class:`SimplifiedObjectInfo` 。
        self.object_list = []

        #: 本次罗列得到的公共前缀列表，类型为str列表。
        self.prefix_list = []


class SimplifiedObjectInfo(object):
    def __init__(self, key, last_modified, etag, type, size, storage_class):
        #: 文件名，或公共前缀名。
        self.key = key

        #: 文件的最后修改时间
        self.last_modified = last_modified

        #: HTTP ETag
        self.etag = etag

        #: 文件类型
        self.type = type

        #: 文件大小
        self.size = size

        #: 文件的存储类别，是一个字符串。
        self.storage_class = storage_class

    def is_prefix(self):
        """如果是公共前缀，返回True；是文件，则返回False"""
        return self.last_modified is None


class GetObjectResult(HeadObjectResult):
    def __init__(self, resp, progress_callback=None, crc_enabled=False, crypto_provider=None):
        super(GetObjectResult, self).__init__(resp)
        self.__crc_enabled = crc_enabled
        self.__crypto_provider = crypto_provider

        if _hget(resp.headers, 'x-oss-meta-oss-crypto-key') and _hget(resp.headers, 'Content-Range'):
            raise ClientError('Could not get an encrypted object using byte-range parameter')

        if progress_callback:
            self.stream = make_progress_adapter(self.resp, progress_callback, self.content_length)
        else:
            self.stream = self.resp

        if self.__crc_enabled:
            self.stream = make_crc_adapter(self.stream)

        if self.__crypto_provider:
            key = self.__crypto_provider.decrypt_oss_meta_data(resp.headers, 'x-oss-meta-oss-crypto-key')
            start = self.__crypto_provider.decrypt_oss_meta_data(resp.headers, 'x-oss-meta-oss-crypto-start')
            cek_alg = _hget(resp.headers, 'x-oss-meta-oss-cek-alg')
            if key and start and cek_alg:
                self.stream = self.__crypto_provider.make_decrypt_adapter(self.stream, key, start)
            else:
                raise InconsistentError('all metadata keys are required for decryption (x-oss-meta-oss-crypto-key, \
                                        x-oss-meta-oss-crypto-start, x-oss-meta-oss-cek-alg)', self.request_id)

    def read(self, amt=None):
        return self.stream.read(amt)

    def __iter__(self):
        return iter(self.stream)

    @property
    def client_crc(self):
        if self.__crc_enabled:
            return self.stream.crc
        else:
            return None


class GetObjectMetaResult(RequestResult):
    def __init__(self, resp):
        super(GetObjectMetaResult, self).__init__(resp)

        #: 文件最后修改时间，类型为int。参考 :ref:`unix_time` 。
        self.last_modified = _hget(self.headers, 'last-modified', http_to_unixtime)

        #: Content-Length，文件大小，类型为int。
        self.content_length = _hget(self.headers, 'content-length', int)

        #: HTTP ETag
        self.etag = _get_etag(self.headers)


class CorsRule(object):
    """CORS（跨域资源共享）规则。

    :param allowed_origins: 允许跨域访问的域。
    :type allowed_origins: list of str

    :param allowed_methods: 允许跨域访问的HTTP方法，如'GET'等。
    :type allowed_methods: list of str

    :param allowed_headers: 允许跨域访问的HTTP头部。
    :type allowed_headers: list of str

    """

    def __init__(self,
                 allowed_origins=None,
                 allowed_methods=None,
                 allowed_headers=None,
                 expose_headers=None,
                 max_age_seconds=None):
        self.allowed_origins = allowed_origins or []
        self.allowed_methods = allowed_methods or []
        self.allowed_headers = allowed_headers or []
        self.expose_headers = expose_headers or []
        self.max_age_seconds = max_age_seconds


class BucketCors(object):
    def __init__(self, rules=None):
        self.rules = rules or []


class GetBucketCorsResult(RequestResult, BucketCors):
    def __init__(self, resp):
        RequestResult.__init__(self, resp)
        BucketCors.__init__(self)


class LifecycleRule(object):
    """生命周期规则。"""
    ENABLED = 'Enabled'
    DISABLED = 'Disabled'

    def __init__(self, id, prefix,
                 status=ENABLED, expiration=None,
                 abort_multipart_upload=None,
                 storage_transitions=None, tagging=None,
                 noncurrent_version_expiration=None,
                 noncurrent_version_sotrage_transitions=None):
        self.id = id
        self.prefix = prefix
        self.status = status
        self.expiration = expiration
        self.abort_multipart_upload = abort_multipart_upload
        self.storage_transitions = storage_transitions
        self.tagging = tagging
        self.noncurrent_version_expiration = noncurrent_version_expiration
        self.noncurrent_version_sotrage_transitions = noncurrent_version_sotrage_transitions


class LifecycleExpiration(object):
    """过期删除操作。"""

    def __init__(self, days=None, date=None, created_before_date=None, expired_delete_marker=None,
                 noncurrent_days=None):
        not_none_fields = 0
        if days is not None:
            not_none_fields += 1
        if date is not None:
            not_none_fields += 1
        if created_before_date is not None:
            not_none_fields += 1
        if expired_delete_marker is not None:
            not_none_fields += 1
        if noncurrent_days is not None:
            not_none_fields += 1
        if not_none_fields > 1:
            raise ClientError(
                'More than one field(days, date and created_before_date, expired_delete_marker) has been specified')

        self.days = days
        self.date = date
        self.created_before_date = created_before_date
        self.expired_delete_marker = expired_delete_marker
        self.noncurrent_days = noncurrent_days



class AbortMultipartUpload(object):
    """删除parts

    :param days: 删除相对最后修改时间days天之后的parts
    :param created_before_date: 删除最后修改时间早于created_before_date的parts

    """
    def __init__(self, days=None, created_before_date=None):
        if days is not None and created_before_date is not None:
            raise ClientError('days and created_before_date should not be both specified')

        self.days = days
        self.created_before_date = created_before_date


class StorageTransition(object):
    """transit objects

    :param days: 将相对最后修改时间days天之后的Object转储
    :param created_before_date: 将最后修改时间早于created_before_date的对象转储
    :param storage_class: 对象转储到OSS的目标存储类型
    """
    def __init__(self, days=None, created_before_date=None, storage_class=None):
        if days is not None and created_before_date is not None:
            raise ClientError('days and created_before_date should not be both specified')

        self.days = days
        self.created_before_date = created_before_date
        self.storage_class = storage_class


_MAX_OBJECT_TAGGING_KEY_LENGTH = 128
_MAX_OBJECT_TAGGING_VALUE_LENGTH = 256



########################我们仍未知道后端何时会实现此功能#################################
class Tagging(object):

    def __init__(self, tagging_rules=None):
        self.tag_set = tagging_rules or TaggingRule()

    def __str__(self):
        tag_str = ""

        tagging_rule = self.tag_set.tagging_rule

        for key in tagging_rule:
            tag_str += key
            tag_str += "#" + tagging_rule[key] + " "

        return tag_str

class TaggingRule(object):
    """对象标签规则。

    :param oss.tagging rules:由生命周期规则组成的数组。 
    """

    def __init__(self):
        self.tagging_rule = dict()

    def add(self, key, value):

        if key is None or key == '':
            raise ClientError("Tagging key should not be empty")

        if len(key) > _MAX_OBJECT_TAGGING_KEY_LENGTH:
            raise ClientError("Tagging key is too long")

        if len(value) > _MAX_OBJECT_TAGGING_VALUE_LENGTH:
            raise ClientError("Tagging value is too long")

        self.tagging_rule[key] = value

    def delete(self, key):
        del self.tagging_rule[key]

    def len(self):
        return len(self.tagging_rule)

    def to_query_string(self):
        query_string = ''

        for key in self.tagging_rule:
            query_string += urlquote(key)
            query_string += '='
            query_string += urlquote(self.tagging_rule[key])
            query_string += '&'

        if len(query_string) == 0:
            return ''
        else:
            query_string = query_string[:-1]

        return query_string
##########################################################################

class LifecycleExpiration(object):
    """过期删除操作。"""

    def __init__(self, days=None, date=None, created_before_date=None, expired_delete_marker=None):
        not_none_fields = 0
        if days is not None:
            not_none_fields += 1
        if date is not None:
            not_none_fields += 1
        if created_before_date is not None:
            not_none_fields += 1
        if expired_delete_marker is not None:
            not_none_fields += 1

        if not_none_fields > 1:
            raise ClientError('More than one field(days, date and created_before_date, '
                              'expired_delete_marker) has been specified')

        self.days = days
        self.date = date
        self.created_before_date = created_before_date
        self.expired_delete_marker = expired_delete_marker

class BatchDeleteObjectVersionResult(object):
    def __init__(self, key, versionid=None, delete_marker=None, delete_marker_versionid=None):
        self.key = key
        self.versionid = versionid or ''
        self.delete_marker = delete_marker or False
        self.delete_marker_versionid = delete_marker_versionid or ''

class BatchDeleteObjectsResult(RequestResult):
    def __init__(self, resp):
        super(BatchDeleteObjectsResult, self).__init__(resp)

        #: 已经删除的文件名列表
        self.deleted_keys = []

        #：已经删除的带版本信息的文件信息列表
        self.delete_versions = []

class BucketLifecycle(object):
    """Bucket的生命周期配置。

    :param oss.LifecycleRule rules:由生命周期规则组成的数组。 
    """

    def __init__(self, rules=None):
        self.rules = rules or []


class GetBucketLifecycleResult(RequestResult, BucketLifecycle):
    def __init__(self, resp):
        RequestResult.__init__(self, resp)
        BucketLifecycle.__init__(self)


def _get_etag(headers):
    return _hget(headers, 'etag', lambda x: x.strip('"'))


def _hget(headers, key, converter=lambda x: x):
    if key in headers:
        return converter(headers[key])
    else:
        return None


class BucketReferer(object):
    """Bucket防盗链设置。

    :param bool allow_empty_referer: 是否允许空的Referer。
    :param referers: Referer列表，每个元素是一个str。

    """

    def __init__(self, allow_empty_referer, referers):
        self.allow_empty_referer = allow_empty_referer
        self.referers = referers


class GetBucketRefererResult(RequestResult, BucketReferer):
    def __init__(self, resp):
        RequestResult.__init__(self, resp)
        BucketReferer.__init__(self, False, [])


class BucketLogging(object):
    """日志配置。

    :param str target_bucket: 设置日志的目标存储桶
    :param str target_prefix: 存放日志的目录

    """
    def __init__(self, target_bucket, target_prefix):
        self.target_bucket = target_bucket
        self.target_prefix = target_prefix


class GetBucketLoggingResult(RequestResult, BucketLogging):
    def __init__(self, resp):
        RequestResult.__init__(self, resp)
        BucketLogging.__init__(self, '', '')    


class BucketWebsite(object):
    """静态网站托管配置。

    :param str index_file: 索引页面文件
    :param str error_file: 404页面文件
    :param rules : list of class:`RoutingRule <oss2.models.RoutingRule>`

    """

    def __init__(self, index_file, error_file, rules=None):
        if rules is not None:
            if not isinstance(rules, list):
                raise ClientError('rules type should be list.')
            if len(rules) > 5:
                raise ClientError('capacity of rules should not be > 5.')

        self.index_file = index_file
        self.error_file = error_file
        self.rules = rules or []

class GetBucketWebsiteResult(RequestResult, BucketWebsite):
    def __init__(self, resp):
        RequestResult.__init__(self, resp)
        BucketWebsite.__init__(self, '', '', [])