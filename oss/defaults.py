# -*- coding: utf-8 -*-

"""
oss.defaults
~~~~~~~~~~~~~

全局缺省变量。

"""


def get(value, default_value):
    if value is None:
        return default_value
    else:
        return value

#是否忽略证书
is_ignore_certificate = True


#: 连接超时时间
connect_timeout = 60

#: 缺省重试次数
request_retries = 3

#: 对于某些接口，上传数据长度大于或等于该值时，就采用分片上传。
multipart_threshold = 10 * 1024 * 1024

#: 分片上传缺省线程数
multipart_num_threads = 1

#: 缺省分片大小
part_size = 10 * 1024 * 1024


#: 每个Session连接池大小
connection_pool_size = 10


#: 对于断点下载，如果OSS文件大小大于该值就进行并行下载（multiget）
multiget_threshold = 100 * 1024 * 1024

#: 并行下载（multiget）缺省线程数
multiget_num_threads = 4

#: 并行下载（multiget）的缺省分片大小
multiget_part_size = 10 * 1024 * 1024


ACL_DEFAULT = 'default'
ACL_PRIVATE = 'private'
ACL_PUBLIC_READ = 'public-read'
ACL_PUBLIC_READ_WRITE = 'public-read-write'

BUCKET_STORAGE_CLASS_STANDARD = 'Standard'
BUCKET_STORAGE_CLASS_IA = 'IA'
BUCKET_STORAGE_CLASS_ARCHIVE = 'Archive'

REDIRECT_TYPE_MIRROR = 'Mirror'
REDIRECT_TYPE_EXTERNAL = 'External'
REDIRECT_TYPE_INTERNAL = 'Internal'
REDIRECT_TYPE_ALICDN = 'AliCDN'

PAYER_BUCKETOWNER = 'BucketOwner'
PAYER_REQUESTER = 'Requester'

