# -*- coding: utf-8 -*-

import oss
import logging
import os
import sys
from oss import SizedFileAdapter, determine_part_size
from oss.entity import PartInfo

access_key_id = 'OSS_TEST_ACCESS_KEY_ID'
access_key_secret = 'OSS_TEST_ACCESS_KEY_SECRET'
endpoint = 'OSS_TEST_ENDPOINT'
bucket_name = 'OSS_TEST_BUCKET'

logging.basicConfig(format="%(asctime)s %(name)s:%(levelname)s:%(message)s", datefmt="%d-%M-%Y %H:%M:%S", level=logging.DEBUG)


def percentage(consumed_bytes, total_bytes):
    """进度条回调函数，计算当前完成的百分比

    :param consumed_bytes: 已经上传/下载的数据量
    :param total_bytes: 总数据量
    """
    if total_bytes:
        rate = int(100 * (float(consumed_bytes) / float(total_bytes)))
        print('\r{0}% '.format(rate))
        sys.stdout.flush()


#########从文件中简单上传#########
def UploadObjectFromFile(object_name, file_location):

    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    bucket.put_object_from_file(object_name, file_location, progress_callback=percentage)


#########从内存中简单上传#########
def UploadObject(object_name, Data):

    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    bucket.put_object(object_name, Data, progress_callback=percentage)


#########追加上传#########
def AppendUpload(object_name, content):
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    result = bucket.append_object(object_name, 0, content, progress_callback=percentage)#首次上传
    bucket.append_object(object_name, result.next_position, content, progress_callback=percentage)#后续上传


#########分片上传#########
def SliceUpload(object_name, file_location, part_size = 10 * 1024 * 1024):
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    total_size = os.path.getsize(file_location)
    # determine_part_size方法用于确定分片大小。
    part_size = os.path.getsize(file_location)
    # 初始化分片
    upload_id = bucket.init_multipart_upload(object_name).upload_id
    parts = []
    # 逐个上传分片。
    with open(file_location, 'rb') as fileobj:
        part_number = 1
        offset = 0
        while offset < total_size:
            num_to_upload = min(part_size, total_size - offset)
            # 调用SizedFileAdapter(fileobj, size)方法会生成一个新的文件对象，重新计算起始追加位置。
            result = bucket.upload_part(object_name, upload_id, part_number,
                                        SizedFileAdapter(fileobj, num_to_upload),
                                        progress_callback=percentage)
            parts.append(PartInfo(part_number, result.etag))

            offset += num_to_upload
            part_number += 1
    # 完成分片上传
    bucket.complete_multipart_upload(object_name, upload_id, parts)


#########签名上传#########
def URLUpload(key, file_path):
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    with open(file_path) as fr:
        data = fr.read()

    url = bucket.sign_url('PUT', key, 3600)
    bucket.put_object_with_url(url, data)
    get_url = bucket.sign_url('GET', key, 3600)
    print("The url for the website is " + get_url)

#########签名分片上传#########
def SliceUploadWithURL(key, fileName):
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)

    totalSize = os.path.getsize(fileName)

    part_size = oss.determine_part_size(totalSize, preferred_size=16 * 1024 * 1024)

    # 1.初始化
    uploadId = bucket.init_multipart_upload(key).upload_id

    with open(fileName, 'rb') as fileobj:
        parts = []
        part_number = 1
        offset = 0
        while offset < totalSize:
            size_to_upload = min(part_size, totalSize - offset)
            data = oss.SizedFileAdapter(fileobj, size_to_upload)
            params = {'uploadId': uploadId, 'partNumber': str(part_number)}
            # 获取上传的URL
            url = bucket.sign_url('PUT', key, 3600, params=params)
        # 发送请求
        result = bucket.put_object_with_url(url, data)
        parts.append(oss.entity.PartInfo(part_number, result.etag, size=size_to_upload, part_crc=result.crc))
        offset += size_to_upload
        part_number += 1

    # 完成分片上传
    bucket.complete_multipart_upload(key, uploadId, parts)

if __name__ == '__main__':
    print("Welcome to oss sdk")

    # 创建本地范例文件以验证上传
    fName = 'download.py'

    # 从文件中上传
    UploadObjectFromFile("TestUpload1.txt", fName)

    # 从内存中上传
    UploadObject("TestUpload2.txt", "This is OSS Cloud.")

    # 追加上传
    AppendUpload("TestUpload3.txt", "This is OSS Cloud")

    # 分片上传
    SliceUpload("TestUpload4.txt", fName)

    # 使用URL进行简单上传
    URLUpload("TestUpload5.txt", fName)

    # 使用URL进行分片上传
    SliceUploadWithURL("TestUpload6.txt", fName)

    # 删除临时验证文件
    os.remove(fName)