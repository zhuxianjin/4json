#!/usr/bin/env python
#coding: utf-8
#Author: J0k3r https://github.com/zhuxianjin

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo

import re
import json

class BurpExtender(IBurpExtender, IHttpListener):
    '''
    IBurpExtender 初始化
    '''
    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        # 插件名
        self._callbacks.setExtensionName("4json")
        # 注册下接口
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        '''
        判断当前是否位于 PROXY SCANNER INTRUDER 和 REPEATER 下
        '''
        if toolFlag == 4 or toolFlag == 64 or toolFlag == 16 or toolFlag == 32: 
            '''
            只处理 Response
            '''
            if not messageIsRequest:
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers = analyzedResponse.getHeaders()
                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring()
                for header in headers:
                    if header.startswith("Content-Type:"):
                        if "application/json" or "text/javascript" in header:
                            body_string = self.parseJsonp(body_string)
                new_body_string = self.decodeUnicode(body_string)
                new_body = self._helpers.bytesToString(new_body_string)
                messageInfo.setResponse(self._helpers.buildHttpMessage(headers, new_body))

    def decodeUnicode(self,_str):
        '''
        Unicode 解码处理
        '''
        match_string = re.findall(r"(\\u[0-9a-f]{4}.*)+", _str)
        if len(match_string):
            match_string = match_string[0]
            new_body_string = _str.replace(match_string, match_string.decode("unicode-escape").encode('utf-8'))
            return new_body_string

    def parseJsonp(self, _jsonp):
        '''
        Jsonp/json 格式化处理
        '''
        try:
            jsonpMessage = re.match(".*?({.*}).*", _jsonp, re.S).group(1)
            return json.dumps(json.loads(jsonpMessage), sort_keys=True, indent=4, separators=(', ', ': '))
        except:
            raise ValueError('Invalid Input')

print "Success\nNow you json / jsonp data will be formatting"
print "Author: J0k3r"