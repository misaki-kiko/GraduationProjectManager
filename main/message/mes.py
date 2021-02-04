#!/usr/bin/env python
#coding=utf-8
import random
import main.config.base as conb
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
#SMS_206551364
def SendMessage(phone, TCode, MessageCode):
    if not conb.getConfig('messageSwitch'):
        return {'error:':'管理员关闭了短信发送功能','errno':'4001'}
    client = AcsClient(conb.getConfigStr('accessKeyId'), conb.getConfigStr('accessSecret'), 'cn-hangzhou')

    request = CommonRequest()
    request.set_accept_format('json')
    request.set_domain('dysmsapi.aliyuncs.com')
    request.set_method('POST')
    request.set_protocol_type('https')  # https | http
    request.set_version('2017-05-25')
    request.set_action_name('SendSms')

    request.add_query_param('RegionId', "cn-hangzhou")
    request.add_query_param('PhoneNumbers', phone)
    request.add_query_param('SignName', conb.getConfigStr('messageSignName'))
    request.add_query_param('TemplateCode', TCode)
    request.add_query_param('TemplateParam', "{\"code\":\""+MessageCode+"\"}")

    response = client.do_action(request)
    # python2:  print(response)
    print(str(response, encoding='utf-8'))

# SendMessage('13282011321', 'SMS_206551364', str(int(random.random() * 1000000)))