#!/usr/bin/env python
# coding: utf-8
import json
import logging

from datetime import datetime
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA

from .compat import (
    quote_plus,
    urlopen,
    decodebytes,
    encodebytes,
)
from .exceptions import (
    AliPayException,
    AliPayValidationError,
)
logger = logging.getLogger('openapi.alipay')


class BaseAliPayClient(object):

    @property
    def appid(self):
        return self.__appid

    @property
    def sign_type(self):
        return self.__sign_type

    @property
    def gateway(self):
        if self.__custom_gateway:
            return self.__custom_gateway
        return "https://openapi.alipay.com/gateway.do"

    def __init__(self,
                 appid=None,
                 notify_url=None,
                 private_key=None,
                 alipay_public_key=None,
                 sign_type="RSA2",
                 custom_gateway=None,
                 verify_return_data=True):
        self.__appid = appid
        self.__notify_url = notify_url
        self.__private_key = private_key
        self.__alipay_public_key = alipay_public_key
        self.__sign_type = sign_type
        self.__custom_gateway = custom_gateway
        self.__verify = verify_return_data

        self.__check_internal_configuration()

        if sign_type not in ("RSA", "RSA2"):
            raise AliPayException(None,
                                  "Unsupported sign type {}".format(sign_type))

    def __ordered_data(self, data):
        complex_keys = []
        for key, value in data.items():
            if isinstance(value, dict):
                complex_keys.append(key)

        # 将字典类型的数据dump出来
        for key in complex_keys:
            data[key] = json.dumps(data[key], separators=(',', ':'))

        return sorted([(k, v) for k, v in data.items()])

    def __check_internal_configuration(self):
            assert self.__appid, "appid is not configured"
            assert self.__private_key, "app_private_key is not configured"
            assert self.__alipay_public_key, "alipay_public_key is not configured"  # noqa

    def _sign(self, unsigned_string, private_key):
        """
        通过如下方法调试签名
        方法1
            key = rsa.PrivateKey.load_pkcs1(self.__private_key)
            sign = rsa.sign(unsigned_string.encode("utf8"), key, "SHA-1")
            # base64 编码，转换为unicode表示并移除回车
            sign = base64.encodebytes(sign).decode("utf8").replace("\n", "")
        方法2
            key = RSA.importKey(self.__private_key)
            signer = PKCS1_v1_5.new(key)
            signature = signer.sign(SHA.new(unsigned_string.encode("utf8")))
            # base64 编码，转换为unicode表示并移除回车
            sign = base64.encodebytes(signature).decode("utf8").replace("\n", "")
        方法3
            echo "abc" | openssl sha1 -sign alipay.key | openssl base64

        """
        # 开始计算签名
        key = RSA.importKey(private_key)
        signer = PKCS1_v1_5.new(key)
        if self.__sign_type == "RSA":
            signature = signer.sign(SHA.new(unsigned_string.encode("utf8")))
        else:
            signature = signer.sign(SHA256.new(unsigned_string.encode("utf8")))
        # base64 编码，转换为unicode表示并移除回车
        sign = encodebytes(signature).decode("utf8").replace("\n", "")
        return sign

    def _sign_data_with_private_key(self, data, private_key):
        data.pop("sign", None)
        # 排序后的字符串
        unsigned_items = self.__ordered_data(data)
        unsigned_string = "&".join("{}={}".format(k, v)
                                   for k, v in unsigned_items)
        return self._sign(unsigned_string, private_key)

    def _sign_data(self, data, private_key_path):
        sign = self._sign_data_with_private_key(data, private_key_path)
        ordered_items = self.__ordered_data(data)
        quoted_string = "&".join("{}={}".format(k, quote_plus(v))
                                 for k, v in ordered_items)

        signed_string = quoted_string + "&sign=" + quote_plus(sign)
        return signed_string

    def verify_notify(self, data, signature):
        return self._verify_data(data, signature, self.__alipay_public_key)

    def _verify(self, raw_content, signature, alipay_public_key):
        key = RSA.importKey(alipay_public_key)
        signer = PKCS1_v1_5.new(key)
        if self.__sign_type == "RSA":
            digest = SHA.new()
        else:
            digest = SHA256.new()
        digest.update(raw_content.encode("utf8"))
        if signer.verify(digest, decodebytes(signature.encode("utf8"))):
            return True
        return False

    def _verify_data(self, data, signature, alipay_public_key):
        if "sign_type" in data:
            sign_type = data.pop("sign_type")
            if sign_type != self.__sign_type:
                raise AliPayException(None,
                                      "Unknown sign type: {}".format(sign_type))

        unsigned_items = self.__ordered_data(data)
        message = "&".join("{}={}".format(k, v) for k, v in unsigned_items)
        return self._verify(message, signature, alipay_public_key)

    def __verify_and_return_data(self, raw_string, response_type):
        """
        return data if verification succeeded, else raise exception
        """
        logger.info('alipay return, %r', raw_string)
        response = json.loads(raw_string)
        if 'error_response' in response:
            raise AliPayException(code=response['error_response']['code'],
                                  msg=response['error_response']['msg'])

        result = response[response_type]
        try:
            sign = response["sign"]
        except KeyError:
            raise AliPayException(result['code'], result['msg'])

        # locate string to be signed
        raw_string = self.get_string_to_be_signed(
            raw_string, response_type
        )

        if self.__verify and \
                not self._verify(raw_string, sign, self.__alipay_public_key):
            raise AliPayValidationError
        return result

    @classmethod
    def get_string_to_be_signed(cls, raw_string, response_type):
        """
        https://doc.open.alipay.com/docs/doc.htm?docType=1&articleId=106120
        从同步返回的接口里面找到待签名的字符串
        """
        left_index = 0
        right_index = 0

        index = raw_string.find(response_type)
        left_index = raw_string.find("{", index)
        index = left_index + 1

        balance = -1
        while balance < 0 and index < len(raw_string) - 1:
            index_a = raw_string.find("{", index)
            index_b = raw_string.find("}", index)

            # 右括号没找到， 退出
            if index_b == -1:
                break
            right_index = index_b

            # 左括号没找到，移动到右括号的位置
            if index_a == -1:
                index = index_b + 1
                balance += 1
            # 左括号出现在有括号之前，移动到左括号的位置
            elif index_a > index_b:
                balance += 1
                index = index_b + 1
            # 左括号出现在右括号之后， 移动到右括号的位置
            else:
                balance -= 1
                index = index_a + 1

        return raw_string[left_index: right_index + 1]

    def _request(self, method, timeout=10, **kwargs):
        data = {
            "app_id": str(self.__appid),
            "format": "JSON",
            "charset": "utf-8",
            "sign_type": self.__sign_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "method": method
        }
        if kwargs:
            data.update(kwargs)

        url = self.gateway + "?" + self._sign_data(data, self.__private_key)
        logger.info('alipay request url: %r', url)
        raw_string = urlopen(url, timeout=timeout).read().decode("utf-8")
        response_type = method.replace('.', '_') + '_response'
        return self.__verify_and_return_data(raw_string, response_type)


class AliPayClient(BaseAliPayClient):
    def request(self, method, **kwargs):
        timeout = kwargs.pop('timeout', 10)
        return self._request(method, timeout=timeout, **kwargs)

    def get_oauth_token(self, grant_type, **kwargs):
        return self._request('alipay.system.oauth.token',
                             grant_type=grant_type,
                             **kwargs)

    def ele_order_sync(self, **kwargs):
        return self._request('koubei.catering.ele.order.sync', **kwargs)