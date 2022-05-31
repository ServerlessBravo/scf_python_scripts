# -*- coding:utf-8 -*-
import requests
import time
import hmac
import base64
import urllib
import json
import sys
import os
import binascii
import hashlib
import random
from urllib import urlencode
from datetime import datetime

reload(sys)
sys.setdefaultencoding('utf8')

#must change this
secretid = "yoursecretid"
secretkey = "yoursecretkey"


req_url = "https://asr.tencentcloudapi.com"

def _build_header(action):
    header = dict()
    header["Content-Type"] = "application/json; charset=utf-8"
    header["Host"] = "asr.tencentcloudapi.com"
    header["X-TC-Action"] = action
    header["X-TC-RequestClient"] = "SDK_PYTHON_27"
    header["X-TC-Timestamp"] = str(int(time.time()))
    header["X-TC-Version"] = "2019-06-14"
    header["X-TC-Region"] = "ap-shanghai"
    return header

def _build_req_with_tc3_signature(action, params, header):
    timestamp = int(time.time())
    service = "asr"
    date = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d')
    signature = _get_tc3_signature(params, date, service, header)

    auth = "TC3-HMAC-SHA256"
    auth += " Credential=%s/%s/%s/tc3_request" % (secretid, date, service)
    auth += ", SignedHeaders=content-type;host, Signature=%s" % signature
    header["Authorization"] = auth

def _get_tc3_signature(params, date, service, header):
    canonical_uri = "/"
    canonical_querystring = ''

    payload = json.dumps(params)
    payload_hash = hashlib.sha256(payload).hexdigest()

    canonical_headers = 'content-type:%s\nhost:%s\n' % (
        header["Content-Type"], header["Host"])
    signed_headers = 'content-type;host'
    canonical_request = '%s\n%s\n%s\n%s\n%s\n%s' % ("POST",
                                                    canonical_uri,
                                                    canonical_querystring,
                                                    canonical_headers,
                                                    signed_headers,
                                                    payload_hash)

    algorithm = 'TC3-HMAC-SHA256'
    credential_scope = date + '/' + service + '/tc3_request'
    digest = hashlib.sha256(canonical_request).hexdigest()
    string2sign = '%s\n%s\n%s\n%s' % (algorithm,
                                      header["X-TC-Timestamp"],
                                      credential_scope,
                                      digest)

    signature = sign_tc3(secretkey, date, service, string2sign)
    return signature


def sign_tc3(secret_key, date, service, str2sign):
    def _hmac_sha256(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256)

    def _get_signature_key(key, date, service):
        k_date = _hmac_sha256(('TC3' + key).encode('utf-8'), date)
        k_service  = _hmac_sha256(k_date.digest(), service)
        k_signing = _hmac_sha256(k_service.digest(), 'tc3_request')
        return k_signing.digest()

    signing_key = _get_signature_key(secret_key, date, service)
    signature = _hmac_sha256(signing_key, str2sign).hexdigest()
    return signature

def create_task(file_path):
    request_data = dict()
    request_data['ChannelNum'] = 2
    request_data['ChannelNum'] = 1
    request_data['EngineModelType'] = "8k_0"
    request_data['EngineModelType'] = "16k_zh"
    request_data['ResTextFormat'] = 0
    request_data['ResTextFormat'] = 1
    request_data['SourceType'] = 1
    request_data['FilterModal'] = 2


    file_object = open(file_path, 'rb')
    file_object.seek(0, os.SEEK_END)
    datalen = file_object.tell()
    file_object.seek(0, os.SEEK_SET)
    content = file_object.read(datalen)
    file_object.close()
    data = base64.b64encode(content)
    request_data['Data'] = data

    action = "CreateRecTask"
    header = _build_header(action)
    _build_req_with_tc3_signature(action, request_data, header)

    r = requests.post(req_url, headers=header, data=json.dumps(request_data))
    print r.text
    resp = json.loads(r.text)
    taskid = resp["Response"]["Data"]["TaskId"]
    return taskid

def get_result(taskid):
    req = dict()
    req['TaskId'] = taskid
    #req['TaskId'] = 647730162

    action = "DescribeTaskStatus"
    header = _build_header(action)
    _build_req_with_tc3_signature(action, req, header)

    r = requests.post(req_url, headers=header, data=json.dumps(req))
    print r.text.encode('utf-8')

    resp = json.loads(r.text)
    status = resp["Response"]["Data"]["Status"]
    return status

if __name__ == '__main__':
    f = "./tjg_1210356921_1047_1b0f839d38ad4c0fad7ece0235e4vide.f30.wav"
    f = "bugscaner-tts-auido.mp3"
    f = "000-1646281993-12364-3319f65659cc44ff9cdbdfe0653bfcb0-000-1578475901.pcm"
    f = "./30s_16k.wav"
    #f = "./123123.pcm"
    #create task
    taskid = create_task(f)
    print "===================================="

    status = 0
    #get task result
    while status < 2:
        time.sleep(2)
        # status: 0:waiting, 1:doing, 2:success, 3:failed
        status = get_result(taskid)
