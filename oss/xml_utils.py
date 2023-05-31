# -*- coding: utf-8 -*-

import logging
import xml.etree.ElementTree as ElementTree

from .entity import *

from .select_params import (SelectJsonTypes, SelectParameters)
#
from .compat import urlunquote, to_unicode, to_string
from .defaults import *


# from .utils import iso8601_to_unixtime, date_to_iso8601, iso8601_to_date
# from . import utils
# import base64
# from .exceptions import SelectOperationClientError


def _find_tag(parent, path):
    child = parent.find(path)
    if child is None:
        raise RuntimeError("parse xml: " + path + " could not be found under " + parent.tag)

    if child.text is None:
        return ''

    return to_string(child.text)


def _find_bool(parent, path):
    text = _find_tag(parent, path)
    if text == 'true':
        return True
    elif text == 'false':
        return False
    else:
        raise RuntimeError("parse xml: value of " + path + " is not a boolean under " + parent.tag)


def _find_int(parent, path):
    return int(_find_tag(parent, path))


def _find_object(parent, path, url_encoded):
    name = _find_tag(parent, path)
    if url_encoded:
        return urlunquote(name)
    else:
        return name


def _find_all_tags(parent, tag):
    return [to_string(node.text) or '' for node in parent.findall(tag)]


def _is_url_encoding(root):
    node = root.find('EncodingType')
    if node is not None and to_string(node.text) == 'url':
        return True
    else:
        return False


def _node_to_string(root):
    return ElementTree.tostring(root, encoding='utf-8')


def _add_node_list(parent, tag, entries):
    for e in entries:
        _add_text_child(parent, tag, e)


def _add_text_child(parent, tag, text):
    ElementTree.SubElement(parent, tag).text = to_unicode(text)


def _add_node_child(parent, tag):
    return ElementTree.SubElement(parent, tag)

def to_batch_delete_objects_request(keys, quiet):
    root_node = ElementTree.Element('Delete')

    _add_text_child(root_node, 'Quiet', str(quiet).lower())

    for key in keys:
        object_node = ElementTree.SubElement(root_node, 'Object')
        _add_text_child(object_node, 'Key', key)

    return _node_to_string(root_node)

def parse_batch_delete_objects(result, body):
    if not body:
        return result
    root = ElementTree.fromstring(body)
    url_encoded = _is_url_encoding(root)

    for deleted_node in root.findall('Deleted'):
        key = _find_object(deleted_node, 'Key', url_encoded)

        result.deleted_keys.append(key)

        versionid_node = deleted_node.find('VersionId')
        versionid = None
        if versionid_node is not None:
            versionid = _find_tag(deleted_node, 'VersionId')

        delete_marker_node = deleted_node.find('DeleteMarker')
        delete_marker = False
        if delete_marker_node is not None:
            delete_marker = _find_bool(deleted_node, 'DeleteMarker')

        marker_versionid_node = deleted_node.find('DeleteMarkerVersionId')
        delete_marker_versionid = ''
        if marker_versionid_node is not None:
            delete_marker_versionid = _find_tag(deleted_node, 'DeleteMarkerVersionId')
        result.delete_versions.append(BatchDeleteObjectVersionResult(key, versionid, delete_marker, delete_marker_versionid))

    return result


def parse_list_buckets(result, body):
    root = ElementTree.fromstring(body)
    namespaces = {'ListAllMyBucketsResult': 'http://s3.amazonaws.com/doc/2006-03-01/'}

    # if root.find('IsTruncated') is None:
    #     result.is_truncated = False
    # else:
    #     result.is_truncated = _find_bool(root, 'IsTruncated')
    #
    # if result.is_truncated:
    #     result.next_marker = _find_tag(root, 'NextMarker')

    # for bucket_node in root.findall(
    #         '{http://s3.amazonaws.com/doc/2006-03-01/}Buckets/{http://s3.amazonaws.com/doc/2006-03-01/}Bucket'):
    #     result.buckets.append(SimplifiedBucketInfo(
    #         _find_tag(bucket_node, '{http://s3.amazonaws.com/doc/2006-03-01/}Name'),
    #         '',
    #         '',
    #         '',
    #         '',
    #         ''
    #     ))
    for bucket_node in root.findall(
            'Buckets/Bucket'):
        result.buckets.append(SimplifiedBucketInfo(
            _find_tag(bucket_node, 'Name'),
            '',
            _find_tag(bucket_node, 'CreationDate'),
            '',
            '',
            ''
        ))
    return result


def to_create_bucket_config(bucket_config):
    root = ElementTree.Element('CreateBucketConfiguration')
    _add_text_child(root, 'LocationConstraint', str(bucket_config.storage_class))
    return _node_to_string(root)


def parse_init_multipart_upload(result, body):
    root = ElementTree.fromstring(body)
    result.upload_id = _find_tag(root, 'UploadId')

    return result


def to_complete_upload_request(parts):
    root = ElementTree.Element('CompleteMultipartUpload')
    for p in parts:
        part_node = ElementTree.SubElement(root, "Part")
        _add_text_child(part_node, 'PartNumber', str(p.part_number))
        _add_text_child(part_node, 'ETag', '"{0}"'.format(p.etag))

    return _node_to_string(root)


def parse_list_objects(result, body):
    root = ElementTree.fromstring(body)
    url_encoded = _is_url_encoding(root)
    result.is_truncated = _find_bool(root, 'IsTruncated')
    if result.is_truncated:
        result.next_marker = _find_object(root, 'NextMarker', url_encoded)

    for contents_node in root.findall('Contents'):
        result.object_list.append(SimplifiedObjectInfo(
            _find_object(contents_node, 'Key', url_encoded),
            iso8601_to_unixtime(_find_tag(contents_node, 'LastModified')),
            _find_tag(contents_node, 'ETag').strip('"'),
            _find_tag(contents_node, 'Type'),
            int(_find_tag(contents_node, 'Size')),
            _find_tag(contents_node, 'StorageClass')
        ))

    for prefix_node in root.findall('CommonPrefixes'):
        result.prefix_list.append(_find_object(prefix_node, 'Prefix', url_encoded))

    return result


def parse_get_bucket_location(result, body):
    result.location = to_string(ElementTree.fromstring(body).text)
    return result


def parse_get_bucket_acl(result, body):
    return parse_acl(body, result)

def parse_get_bucket_quota(result, body):
    return parse_quota(body, result)

def parse_acl(body, result):
    root = ElementTree.fromstring(body)
    owner = Owner(_find_tag(root, 'Owner/ID'), _find_tag(root, 'Owner/DisplayName'))
    grants = parseGrants(root.findall('AccessControlList/Grant'))
    acl = Acl(owner=owner, grants=grants)
    permissions = []
    for i in range(len(grants)):
        permissions.append(grants[i].permission)
    ##has problem
    # permissions = map(lambda grants: grants.permission, acl.grants)
    if 'DEFAULT' in permissions:
        result.acl = ACL_DEFAULT
    elif 'WRITE' in permissions:
        result.acl = ACL_PUBLIC_READ_WRITE
    elif 'READ' in permissions:
        result.acl = ACL_PUBLIC_READ
    else:
        result.acl = ACL_PRIVATE
    return result

def parse_quota(body, result):
    result = 1
    return result

def parse_get_object_acl(result, body):
    return parse_acl(body, result)

def to_put_bucket_cors(bucket_cors):
    root = ElementTree.Element('CORSConfiguration')

    for rule in bucket_cors.rules:
        rule_node = ElementTree.SubElement(root, 'CORSRule')
        _add_node_list(rule_node, 'AllowedOrigin', rule.allowed_origins)
        _add_node_list(rule_node, 'AllowedMethod', rule.allowed_methods)
        _add_node_list(rule_node, 'AllowedHeader', rule.allowed_headers)
        _add_node_list(rule_node, 'ExposeHeader', rule.expose_headers)

        if rule.max_age_seconds is not None:
            _add_text_child(rule_node, 'MaxAgeSeconds', str(rule.max_age_seconds))

    return _node_to_string(root)


def parse_get_bucket_cors(result, body):
    root = ElementTree.fromstring(body)

    for rule_node in root.findall('CORSRule'):
        rule = CorsRule()
        rule.allowed_origins = _find_all_tags(rule_node, 'AllowedOrigin')
        rule.allowed_methods = _find_all_tags(rule_node, 'AllowedMethod')
        rule.allowed_headers = _find_all_tags(rule_node, 'AllowedHeader')
        rule.expose_headers = _find_all_tags(rule_node, 'ExposeHeader')

        max_age_node = rule_node.find('MaxAgeSeconds')
        if max_age_node is not None:
            rule.max_age_seconds = int(max_age_node.text)

        result.rules.append(rule)

    return result


def parseGrants(grants):
    grant_list = []
    if grants is not None:
        ns = '{http://www.w3.org/2001/XMLSchema-instance}'
        for grant in grants:
            if grant.find('Grantee').attrib.get('{0}type'.format(ns)) == 'Group':
                uri = _find_tag(grant, 'Grantee/URI')
                grantee = Grantee(uri=uri)
            elif grant.find('Grantee').attrib.get('{0}type'.format(ns)) == 'CanonicalUser':
                id = _find_tag(grant, 'Grantee/ID')
                # name = _find_tag(grant, 'Grantee/DisplayName')
                # grantee = Grantee(id=id, display_name=name)
                grantee = Grantee(id=id)

            permission = _find_tag(grant, 'Permission')
            cur_grant = Grant(grantee=grantee, permission=permission)
            grant_list.append(cur_grant)
    return grant_list

def to_put_bucket_lifecycle(bucket_lifecycle):
    root = ElementTree.Element('LifecycleConfiguration')

    for rule in bucket_lifecycle.rules:
        rule_node = ElementTree.SubElement(root, 'Rule')
        _add_text_child(rule_node, 'ID', rule.id)
        _add_text_child(rule_node, 'Prefix', rule.prefix)
        _add_text_child(rule_node, 'Status', rule.status)

        expiration = rule.expiration
        if expiration:
            expiration_node = ElementTree.SubElement(rule_node, 'Expiration')

            if expiration.days is not None:
                _add_text_child(expiration_node, 'Days', str(expiration.days))
            elif expiration.date is not None:
                _add_text_child(expiration_node, 'Date', date_to_iso8601(expiration.date))
            elif expiration.created_before_date is not None:
                _add_text_child(expiration_node, 'CreatedBeforeDate', date_to_iso8601(expiration.created_before_date))
            elif expiration.expired_delete_marker is not None:
                _add_text_child(expiration_node, 'ExpiredObjectDeleteMarker', str(expiration.expired_delete_marker))

        abort_multipart_upload = rule.abort_multipart_upload
        if abort_multipart_upload:
            abort_multipart_upload_node = ElementTree.SubElement(rule_node, 'AbortMultipartUpload')
            if abort_multipart_upload.days is not None:
                _add_text_child(abort_multipart_upload_node, 'Days', str(abort_multipart_upload.days))
            elif abort_multipart_upload.created_before_date is not None:
                _add_text_child(abort_multipart_upload_node, 'CreatedBeforeDate',
                                date_to_iso8601(abort_multipart_upload.created_before_date))

        storage_transitions = rule.storage_transitions
        if storage_transitions:
            for storage_transition in storage_transitions:
                storage_transition_node = ElementTree.SubElement(rule_node, 'Transition')
                _add_text_child(storage_transition_node, 'StorageClass', str(storage_transition.storage_class))
                if storage_transition.days is not None:
                    _add_text_child(storage_transition_node, 'Days', str(storage_transition.days))
                elif storage_transition.created_before_date is not None:
                    _add_text_child(storage_transition_node, 'CreatedBeforeDate',
                                    date_to_iso8601(storage_transition.created_before_date))

        tagging = rule.tagging
        if tagging:
            tagging_rule = tagging.tag_set.tagging_rule
            for key in tagging.tag_set.tagging_rule:
                tag_node = ElementTree.SubElement(rule_node, 'Tag')
                _add_text_child(tag_node, 'Key', key)
                _add_text_child(tag_node, 'Value', tagging_rule[key])

        noncurrent_version_expiration = rule.noncurrent_version_expiration
        if noncurrent_version_expiration is not None:
            version_expiration_node = ElementTree.SubElement(rule_node, 'NoncurrentVersionExpiration')
            _add_text_child(version_expiration_node, 'NoncurrentDays', str(noncurrent_version_expiration.noncurrent_days))

        noncurrent_version_sotrage_transitions = rule.noncurrent_version_sotrage_transitions
        if noncurrent_version_sotrage_transitions is not None:
            for noncurrent_version_sotrage_transition in noncurrent_version_sotrage_transitions:
                version_transition_node = ElementTree.SubElement(rule_node, 'NoncurrentVersionTransition')
                _add_text_child(version_transition_node, 'NoncurrentDays', str(noncurrent_version_sotrage_transition.noncurrent_days))
                _add_text_child(version_transition_node, 'StorageClass', str(noncurrent_version_sotrage_transition.storage_class))
        print(_node_to_string(root))

    return _node_to_string(root)

def parse_lifecycle_expiration(expiration_node):
    if expiration_node is None:
        return None

    expiration = LifecycleExpiration()

    if expiration_node.find('Days') is not None:
        expiration.days = _find_int(expiration_node, 'Days')
    elif expiration_node.find('Date') is not None:
        expiration.date = iso8601_to_date(_find_tag(expiration_node, 'Date'))
    elif expiration_node.find('CreatedBeforeDate') is not None:
        expiration.created_before_date = iso8601_to_date(_find_tag(expiration_node, 'CreatedBeforeDate'))
    elif expiration_node.find('ExpiredObjectDeleteMarker') is not None:
        expiration.expired_delete_marker = _find_bool(expiration_node, 'ExpiredObjectDeleteMarker')

    return expiration


def parse_lifecycle_abort_multipart_upload(abort_multipart_upload_node):
    if abort_multipart_upload_node is None:
        return None
    abort_multipart_upload = AbortMultipartUpload()

    if abort_multipart_upload_node.find('Days') is not None:
        abort_multipart_upload.days = _find_int(abort_multipart_upload_node, 'Days')
    elif abort_multipart_upload_node.find('CreatedBeforeDate') is not None:
        abort_multipart_upload.created_before_date = iso8601_to_date(_find_tag(abort_multipart_upload_node,
                                                                               'CreatedBeforeDate'))
    return abort_multipart_upload


def parse_lifecycle_storage_transitions(storage_transition_nodes):
    storage_transitions = []
    for storage_transition_node in storage_transition_nodes:
        storage_class = _find_tag(storage_transition_node, 'StorageClass')
        storage_transition = StorageTransition(storage_class=storage_class)
        if storage_transition_node.find('Days') is not None:
            storage_transition.days = _find_int(storage_transition_node, 'Days')
        elif storage_transition_node.find('CreatedBeforeDate') is not None:
            storage_transition.created_before_date = iso8601_to_date(_find_tag(storage_transition_node,
                                                                               'CreatedBeforeDate'))

        storage_transitions.append(storage_transition)

    return storage_transitions

def parse_lifecycle_object_taggings(lifecycle_tagging_nodes):
    
    if lifecycle_tagging_nodes is None or len(lifecycle_tagging_nodes) == 0: 
        return None 
    
    tagging_rule = TaggingRule()
    for tag_node in lifecycle_tagging_nodes:
        key = _find_tag(tag_node, 'Key')
        value = _find_tag(tag_node, 'Value')
        tagging_rule.add(key, value)

    return Tagging(tagging_rule)

def parse_lifecycle_version_expiration(version_expiration_node):
    if version_expiration_node is None:
        return None

    noncurrent_days = _find_int(version_expiration_node, 'NoncurrentDays')
    expiration = NoncurrentVersionExpiration(noncurrent_days)

    return expiration

def parse_lifecycle_verison_storage_transitions(version_storage_transition_nodes):
    version_storage_transitions = []
    for transition_node in version_storage_transition_nodes:
        storage_class = _find_tag(transition_node, 'StorageClass')
        non_crurrent_days = _find_int(transition_node, 'NoncurrentDays')
        version_storage_transition = NoncurrentVersionStorageTransition(non_crurrent_days, storage_class)
        version_storage_transitions.append(version_storage_transition)

    return version_storage_transitions

def parse_get_bucket_lifecycle(result, body):

    root = ElementTree.fromstring(body)
    url_encoded = _is_url_encoding(root)

    for rule_node in root.findall('Rule'):
        expiration = parse_lifecycle_expiration(rule_node.find('Expiration'))
        abort_multipart_upload = parse_lifecycle_abort_multipart_upload(rule_node.find('AbortMultipartUpload'))
        storage_transitions = parse_lifecycle_storage_transitions(rule_node.findall('Transition'))
        tagging = parse_lifecycle_object_taggings(rule_node.findall('Tag'))
        noncurrent_version_expiration = parse_lifecycle_version_expiration(rule_node.find('NoncurrentVersionExpiration'))
        noncurrent_version_sotrage_transitions = parse_lifecycle_verison_storage_transitions(rule_node.findall('NoncurrentVersionTransition'))

        rule = LifecycleRule(
            _find_tag(rule_node, 'ID'),
            _find_tag(rule_node, 'Prefix'),
            status=_find_tag(rule_node, 'Status'),
            expiration=expiration,
            abort_multipart_upload=abort_multipart_upload,
            storage_transitions=storage_transitions,
            tagging=tagging,
            noncurrent_version_expiration = noncurrent_version_expiration,
            noncurrent_version_sotrage_transitions = noncurrent_version_sotrage_transitions
            )
        result.rules.append(rule)

    return result

########################################################
########################################################

def to_put_bucket_referer(bucket_referer):
    root = ElementTree.Element('RefererConfiguration')

    _add_text_child(root, 'AllowEmptyReferer', str(bucket_referer.allow_empty_referer).lower())
    list_node = ElementTree.SubElement(root, 'RefererList')

    for r in bucket_referer.referers:
        _add_text_child(list_node, 'Referer', r)

    return _node_to_string(root)

def parse_get_bucket_referer(result, body):
    root = ElementTree.fromstring(body)

    result.allow_empty_referer = _find_bool(root, 'AllowEmptyReferer')
    result.referers = _find_all_tags(root, 'RefererList/Referer')

    return result

def to_put_bucket_logging(bucket_logging):
    root = ElementTree.Element('BucketLoggingStatus')

    if bucket_logging.target_bucket:
        logging_node = ElementTree.SubElement(root, 'LoggingEnabled')
        _add_text_child(logging_node, 'TargetBucket', bucket_logging.target_bucket)
        _add_text_child(logging_node, 'TargetPrefix', bucket_logging.target_prefix)

    return _node_to_string(root)

def parse_bucket_logging(result, body):
    root = ElementTree.fromstring(body)

    if root.find('LoggingEnabled/TargetBucket') is not None:
        result.target_bucket = _find_tag(root, 'LoggingEnabled/TargetBucket')

    if root.find('LoggingEnabled/TargetPrefix') is not None:
        result.target_prefix = _find_tag(root, 'LoggingEnabled/TargetPrefix')

    return result

def to_put_bucket_website(bucket_website):
    root = ElementTree.Element('WebsiteConfiguration')

    index_node = ElementTree.SubElement(root, 'IndexDocument')
    _add_text_child(index_node, 'Suffix', bucket_website.index_file)

    error_node = ElementTree.SubElement(root, 'ErrorDocument')
    _add_text_child(error_node, 'Key', bucket_website.error_file)

    if len(bucket_website.rules) == 0:
        return _node_to_string(root)

    rules_node = ElementTree.SubElement(root, "RoutingRules")

    for rule in bucket_website.rules:
        rule_node = ElementTree.SubElement(rules_node, 'RoutingRule')
        _add_text_child(rule_node, 'RuleNumber', str(rule.rule_num))

        condition_node = ElementTree.SubElement(rule_node, 'Condition')
        
        if rule.condition.key_prefix_equals is not None:
            _add_text_child(condition_node, 'KeyPrefixEquals', rule.condition.key_prefix_equals)
        if rule.condition.http_err_code_return_equals is not None:    
            _add_text_child(condition_node, 'HttpErrorCodeReturnedEquals', 
                str(rule.condition.http_err_code_return_equals))
       
        for header in rule.condition.include_header_list:
            include_header_node = ElementTree.SubElement(condition_node, 'IncludeHeader')
            _add_text_child(include_header_node, 'Key', header.key)
            _add_text_child(include_header_node, 'Equals', header.equals)

        if rule.redirect is not None:    
            redirect_node = ElementTree.SubElement(rule_node, 'Redirect')

            # common
            _add_text_child(redirect_node, 'RedirectType', rule.redirect.redirect_type)
            
            if rule.redirect.pass_query_string is not None:
                _add_text_child(redirect_node, 'PassQueryString', str(rule.redirect.pass_query_string))          

            # External, AliCDN
            if rule.redirect.redirect_type in [REDIRECT_TYPE_EXTERNAL, REDIRECT_TYPE_ALICDN]:
                if rule.redirect.proto is not None:
                    _add_text_child(redirect_node, 'Protocol', rule.redirect.proto)
                if rule.redirect.host_name is not None:
                    _add_text_child(redirect_node, 'HostName', rule.redirect.host_name)
                if rule.redirect.http_redirect_code is not None:
                    _add_text_child(redirect_node, 'HttpRedirectCode', str(rule.redirect.http_redirect_code))

            # External, AliCDN, Internal
            if rule.redirect.redirect_type in [REDIRECT_TYPE_EXTERNAL, REDIRECT_TYPE_ALICDN, REDIRECT_TYPE_INTERNAL]:
                if rule.redirect.replace_key_with is not None:
                    _add_text_child(redirect_node, 'ReplaceKeyWith', rule.redirect.replace_key_with)
                if rule.redirect.replace_key_prefix_with is not None:
                    _add_text_child(redirect_node, 'ReplaceKeyPrefixWith', rule.redirect.replace_key_prefix_with)  

            # Mirror
            elif rule.redirect.redirect_type == REDIRECT_TYPE_MIRROR: 
                if rule.redirect.mirror_url is not None:
                    _add_text_child(redirect_node, 'MirrorURL', rule.redirect.mirror_url)
                if rule.redirect.mirror_url_slave is not None:
                    _add_text_child(redirect_node, 'MirrorURLSlave', rule.redirect.mirror_url_slave)
                if rule.redirect.mirror_url_probe is not None:
                    _add_text_child(redirect_node, 'MirrorURLProbe', rule.redirect.mirror_url_probe)
                if rule.redirect.mirror_pass_query_string is not None:
                    _add_text_child(redirect_node, 'MirrorPassQueryString', str(rule.redirect.mirror_pass_query_string))
                if rule.redirect.mirror_follow_redirect is not None:
                    _add_text_child(redirect_node, 'MirrorFollowRedirect', str(rule.redirect.mirror_follow_redirect))
                if rule.redirect.mirror_check_md5 is not None:
                    _add_text_child(redirect_node, 'MirrorCheckMd5', str(rule.redirect.mirror_check_md5))

                if rule.redirect.mirror_headers is not None:
                    mirror_headers_node = ElementTree.SubElement(redirect_node, 'MirrorHeaders')

                    if rule.redirect.mirror_headers.pass_all is not None:
                        _add_text_child(mirror_headers_node, 'PassAll', str(rule.redirect.mirror_headers.pass_all))

                    for pass_param in rule.redirect.mirror_headers.pass_list:
                        _add_text_child(mirror_headers_node, 'Pass', pass_param)   
                    for remove_param in rule.redirect.mirror_headers.remove_list:
                        _add_text_child(mirror_headers_node, 'Remove', remove_param)
                    for set_param in rule.redirect.mirror_headers.set_list:
                        set_node = ElementTree.SubElement(mirror_headers_node, 'Set')
                        _add_text_child(set_node, 'Key', set_param.key)
                        _add_text_child(set_node, 'Value', set_param.value)
    title = ElementTree.Element('<?xml version="1.0" encoding="UTF-8"?>')
    root.insert(0, title)
    return str(_node_to_string(root))
 
def parse_bucket_website(result, body):
    root = ElementTree.fromstring(body)
    result.index_file = _find_tag(root, 'IndexDocument/Suffix')
    result.error_file = _find_tag(root, 'ErrorDocument/Key')

    if root.find('RoutingRules') is None:
        return result

    routing_rules_node = root.find('RoutingRules')

    for rule_node in routing_rules_node.findall('RoutingRule'):
        rule_num = _find_int(rule_node, 'RuleNumber')
        condition = parse_routing_rule_condition(rule_node.find('Condition'))
        redirect = parse_routing_rule_redirect(rule_node.find('Redirect'))
        rule = RoutingRule(rule_num, condition, redirect);
        result.rules.append(rule)

    return result