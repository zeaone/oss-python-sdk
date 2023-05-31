# -*- coding: utf-8 -*-

import oss
import logging

logging.basicConfig(format="%(asctime)s %(name)s:%(levelname)s:%(message)s", datefmt="%d-%M-%Y %H:%M:%S", level=logging.DEBUG)


access_key_id = 'ACCESS_KEY_ID'
access_key_secret = 'ACCESS_KEY_SECRET'
endpoint = 'OSS_TEST_ENDPOINT'
bucket_name = 'OSS_TEST_BUCKET'

###########创建桶###########
def CreateBucket():
    bucket = oss.Bucket(oss.Auth(access_key_id, access_key_secret), endpoint, bucket_name)
    bucket.create_bucket()


###########列举桶###########
def ListBucket():
    service = oss.Service(oss.Auth(access_key_id, access_key_secret), endpoint)
    buckets = service.list_buckets()
    for bucket in buckets.buckets:
        print(bucket.name)
        print(bucket.creation_date)


###########获得桶位置###########
def GetBucketLocation():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    locationResult = bucket.get_bucket_location()
    location = locationResult.location
    print(location)


###########判断桶是否存在###########
def DoesBucketExist():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    if bucket.does_bucket_exist():
        print("Yes")
    else:
        print("No")


###########设置桶的ACL###########
def PutBucketACL(acl):
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    bucket.put_bucket_acl(acl)


###########查看桶的ACL###########
def GetBucketACL():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    print(bucket.get_bucket_acl().acl)


###########删除桶###########
def DeleteBucket():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.delete_bucket()
    except oss.BucketNotEmpty:
        print('Bucket not empty.')
    except oss.NoSuchBucket:
        print('No such bucket.')
    else:
        print('your bucket: "'+bucket_name+'" delete ok.')

###########查看桶配额###########
def GetQuota():
    bucket = oss.Bucket(oss.Auth(access_key_id, access_key_secret), endpoint, bucket_name)
    quota = bucket.get_quota()
    print(quota)

###########设置桶配额###########
def PutQuota(sizeMB):
    size_to_string = str(sizeMB)
    bucket = oss.Bucket(oss.Auth(access_key_id, access_key_secret), endpoint, bucket_name)
    quota = bucket.put_quota(size_to_string)

###########设置跨域资源共享###########
def SetCorsRule():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    rule = oss.CorsRule(allowed_origins=['*'],
                        allowed_methods=['GET', 'HEAD'],
                        allowed_headers=['*'],
                        max_age_seconds=1000)
    try:
        bucket.put_bucket_cors(oss.BucketCors([rule]))
    except oss.NoSuchBucket:
        print('No Such Bucket')
    else:
        print('your bucket: "'+bucket_name+'" set cors rule ok.')


###########获取跨域资源共享###########
def GetCorsRule():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        cors = bucket.get_bucket_cors()
    except oss.NoSuchBucket:
        print('No Such Bucket')
    except oss.NoSuchCors:
        print('No Such Cors')
    else:
        for rule in cors.rules:
            print('AllowedOrigins={0}'.format(rule.allowed_origins))
            print('AllowedMethods={0}'.format(rule.allowed_methods))
            print('AllowedHeaders={0}'.format(rule.allowed_headers))
            print('ExposeHeaders={0}'.format(rule.expose_headers))
            print('MaxAgeSeconds={0}'.format(rule.max_age_seconds))


###########删除跨域资源共享###########
def DeleteCorsRule():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        cors = bucket.delete_bucket_cors()
    except oss.NoSuchBucket:
        print('No Such Bucket')
    except oss.NoSuchCors:
        print('No Such Cors')
    else:
        print('delete ok')


###########设置生命周期###########
def PutLifeCycleRule():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    rule1 = oss.LifecycleRule('rule1', '', expiration=oss.LifecycleExpiration(7))
    LCR = oss.BucketLifecycle([rule1])
    try:
        bucket.put_bucket_lifecycle(LCR)
    except oss.NoSuchBucket:
        print('No Such Bucket')
    else:
        print('Your bucket: "'+bucket_name+'" has set a lifecycle rule.')


###########查看生命周期###########
def GetLifeCycleRule():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    result = bucket.get_bucket_lifecycle()
    for lcr in result.rules:
        print('ID:', lcr.id)
        print('prefix:', lcr.prefix)
        print('status:', lcr.status)

        if lcr.tagging is not None:
            print('tagging:', lcr.tagging)

        if lcr.abort_multipart_upload is not None:
            if lcr.abort_multipart_upload.days is not None:
                print('abort_multipart_upload days:', lcr.abort_multipart_upload.days)
            else:
                print('abort_multipart_upload created_before_date:', lcr.abort_multipart_upload.created_before_date)

        if lcr.expiration is not None:
            if lcr.expiration.days is not None:
                print('expiration days:', lcr.expiration.days)
            elif lcr.expiration.expired_delete_marker is not None:
                print('expiration marker date:', lcr.expiration.expired_delete_marker)
            elif lcr.expiration.created_before_date is not None:
                print('expiration created_before_date:', lcr.expiration.created_before_date)

        if len(lcr.storage_transitions) > 0:
            storage_info = ''
            for storage_rule in lcr.storage_transitions:
                if storage_rule.days is not None:
                    storage_info += 'days={0}, storage_class={1} *** '.format(
                        storage_rule.days, storage_rule.storage_class)
                else:
                    storage_info += 'created_before_date={0}, storage_class={1} *** '.format(
                        storage_rule.created_before_date, storage_rule.storage_class)
            print('storage_transitions:', storage_info)


###########删除生命周期###########
def DeleteLifeCycleRule():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.delete_bucket_lifecycle()
    except oss.NoSuchBucket:
        print("No such bucket.")
    except oss.NoSuchLifecycle:
        print("No such Lifecycle")
    else:
        print('Your bucket: ' + bucket_name + " has deleted the lifecycle rule.")

###########设置防盗链###########
def PutReferer():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    ref = oss.BucketReferer(True, 'http://*.oss.com')
    try:
        bucket.put_bucket_referer(ref)
    except oss.NoSuchBucket:
        print("No such bucket.")
    else:
        print('Your bucket: ' + bucket_name + ' has set the referer.')


###########查看防盗链###########
def GetReferer():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    ref = bucket.get_bucket_referer()
    print('Allow empty referer = [0], referers = [1]'.format(ref.allow_empty_referer,
                                                             ref.referers))


###########删除防盗链###########
def DeleteReferer():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.remove_bucket_referer()
    except oss.NoSuchBucket:
        print("No such bucket.")
    else:
        print('Your bucket: ' + bucket_name + " has removed the referer.")

###########设置静态网站托管###########
def PutWebsite():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    web = oss.BucketWebsite('www.index.com', 'www.error.com')
    try:
        bucket.put_bucket_website(web)
    except oss.NoSuchBucket:
        print("No such bucket.")
    else:
        print("Your bucket: " + bucket_name + " has set up the website.")

###########查看静态网站托管###########
def GetWebsite():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    website = bucket.get_bucket_website()
    print('The index website is [1],  the error webiste is [2]'.format(website.index_file,
                                                                       website.error_file))
###########删除静态网站托管###########
def DeleteWebsite():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.delete_bucket_website()
    except oss.NoSuchBucket:
        print("No such bucket.")
    except oss.NoSuchWebsite:
        print("No such website.")
    else:
        print('Your bucket: ' + bucket_name + " has deleted the website.")


###########设置日志###########
def Putlogging():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    logs = oss.BucketLogging(bucket_name, 'logs/')
    try:
        bucket.put_bucket_logging(logs)
    except oss.NoSuchBucket:
        print('No such bucket')
    else:
        print("Your bucket: " + bucket_name + " has set up the logging.")


###########查看日志日志###########
def Getlogging():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    result = bucket.get_bucket_logging()
    print('TargetBucket={0}, TargetPrefix={1}'.format(
        result.target_bucket, result.target_prefix))

###########删除日志###########
def Deletelogging():
    auth = oss.Auth(access_key_id, access_key_secret)
    bucket = oss.Bucket(auth, endpoint, bucket_name)
    try:
        bucket.delete_bucket_logging()
    except oss.NoSuchBucket:
        print("No such bucket.")
    else:
        print('Your bucket: ' + bucket_name + " has deleted the logs .")

if __name__ == '__main__':
    print("Welcome to oss sdk")

    # # 创造示例存储桶
    # CreateBucket()

    # # 验证是否创建成功
    # DoesBucketExist()
    #
    # # 也可以通过列举存储桶来验证
    # ListBucket()
    #
    # # 设置桶的访问权限
    # PutBucketACL(oss.ACL_PUBLIC_READ_WRITE)
    #
    # # 查看访问权限
    # GetBucketACL()
    #
    # # 查看存储桶地域
    # GetBucketLocation()
    #
    # # 设置存储桶份额
    # PutQuota(5)
    #
    # # 获取存储桶份额
    # GetQuota()
    #
    # # 设置跨域资源共享
    # SetCorsRule()
    #
    # # 获取跨域资源共享
    # GetCorsRule()
    #
    # # 删除跨域资源共享
    # DeleteCorsRule()
    #
    # # 设置生命周期
    # PutLifeCycleRule()
    #
    # # 查看生命周期
    # GetLifeCycleRule()
    #
    # 删除生命周期
    DeleteLifeCycleRule()
    #
    # # 设置防盗链
    # PutReferer()
    #
    # # 查看防盗链
    # GetReferer()
    #
    # # 删除防盗链
    # DeleteReferer()
    #
    # # 设置日志
    # Putlogging()
    #
    # # 查看日志
    # Getlogging()
    #
    # # 删除日志
    # Deletelogging()
    #
    # # 设置静态网站托管
    # PutWebsite()
    #
    # # 查看托管网站
    # GetWebsite()
    #
    # # 移除静态网站托管
    # DeleteWebsite()
    #
    # # 删除存储桶
    # DeleteBucket()
