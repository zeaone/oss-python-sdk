# -*- coding: utf-8 -*-

import os
from oss import SizedFileAdapter, determine_part_size
from oss.entity import PartInfo
import oss
from itertools import islice
import hashlib
from hashlib import  md5

access_key_id = 'OSS_TEST_ACCESS_KEY_ID'
access_key_secret = 'OSS_TEST_ACCESS_KEY_SECRET'
endpoint = 'OSS_TEST_ENDPOINT'
bucket_name = 'OSS_TEST_BUCKET'

########查看桶内文件########
def ListObject():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    listObjectsResult = bucket.list_objects()
    for obj in listObjectsResult.object_list:
        print(obj.key)


########删除桶内文件########
def DeleteObject():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.delete_object('ExampleUpload.txt')
    except oss.NoSuchBucket:
        print("No such bucket")
    else:
        print("The object is successfully deleted.")

########批量删除桶内文件########
def BatchDeleteObject():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.batch_delete_objects(['111', '12'])
    except oss.NoSuchBucket:
        print("No such bucket")
    else:
        print("The object is successfully deleted.")


###########获取MD5###########
def GetMD5():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    object_name = 'UploadExample.txt'
    simplifiedmeta = bucket.get_object_meta(object_name)
    return simplifiedmeta.headers['ETag']


###########获取文件大小###########
def GetObjLength():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    simplifiedmeta = bucket.get_object_meta('UploadExample.txt')
    return simplifiedmeta.headers['Content-Length']


###########判断是否上传成功###########
def DoesObjExist():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    if bucket.object_exists('UploadExample.txt'):
        print("The object is in the bucket.")
    else:
        print("The object is not in the bucket.")


###########生成签名url###########
def SignObjUrl():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        url = bucket.sign_url('GET', 'UploadExample.txt', 60)
    except oss.NoSuchKey:
        print("No such key")
    except oss.NoSuchBucket:
        print("No such bucket")
    else:
        print("The url for the object is " + url)


###########范例上传###########
def ExampleUpload():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.put_object('UploadExample.txt', 'This is Python OSS SDK.')
    except oss.NoSuchBucket:
        print('No such bucket.')

if __name__ == '__main__':
    print("Welcome to oss sdk")


    # # # 创建一个范例对象
    # ExampleUpload()
    #
    # 批量删除对象
    BatchDeleteObject()
    #
    # # 判断是否上传成功
    # DoesObjExist()
    #
    # # 也可以通过列举对象的方式来判断
    # ListObject()
    #
    # # 获取对象大小
    # print("File Size: " + GetObjLength() + " byte.")
    #
    # # 获取对象MD5
    # print("File MD5: " + GetMD5())
    #
    # # 设置使用url访问
    # SignObjUrl()
    #
    # 删除文件
    # DeleteObject()


