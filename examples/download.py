# -*- coding: utf-8 -*-

import oss
import logging
import  os

access_key_id = 'OSS_TEST_ACCESS_KEY_ID'
access_key_secret = 'OSS_TEST_ACCESS_KEY_SECRET'
endpoint = 'OSS_TEST_ENDPOINT'
bucket_name = 'OSS_TEST_BUCKET'

logging.basicConfig(format="%(asctime)s %(name)s:%(levelname)s:%(message)s", datefmt="%d-%M-%Y %H:%M:%S", level=logging.DEBUG)


###########下载###########
def DownloadFile(object_name, file_location):
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    bucket.get_object_to_file(object_name, file_location)


###########范围下载###########
def RangeDownload(object_name):
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    # 对于1000字节大小的文件，正常的下载范围取值为0~999。
    # 获取0~999字节范围内的数据，包括0和999，共1000个字节的数据。如果指定的范围无效（比如开始或结束位置的指定值为负数，或指定值大于文件大小），则下载整个文件。
    object_stream = bucket.get_object(object_name, byte_range=(0, 999))
    print(object_stream.content_type)


###########范例上传###########
def ExampleUpload():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.put_object('测试.txt', 'This is Python OSS SDK.')
    except oss.NoSuchBucket:
        print('No such bucket.')


if __name__ == '__main__':
    print("Welcome to oss sdk")

    # # 首先上传案例对象以供验证
    # ExampleUpload()

    # 下载至本地文件
    DownloadFile('测试.txt', 'C:\\Users\\wangyingbin\\Desktop\\144.txt')

    # # 范围下载
    # RangeDownload('UploadExample.txt')


