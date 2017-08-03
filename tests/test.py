#!/usr/bin/env python
# coding: utf-8
import unittest
import json
import subprocess

from alipay import AliPayClient
from tests import helper
from tests.compat import mock

valid_response = json.dumps({
    "xxx_response": {
        "code": "10000"
    }
}).encode("utf-8")

invalid_response = json.dumps({
    "xxx_response": {
        "code": "20001",
        "sub_msg": "错误的消息"
    }
}).encode("utf-8")


class AliPayTestCase(unittest.TestCase):

    def setUp(self):
        super(AliPayTestCase, self).setUp()
        self.__private_key, self.__ali_public_key = helper.get_certs()
        self.__private_key_path, self.__ali_public_key_path = \
            helper.get_certs_path()

    def _prepare_sync_response(self, alipay, response_type):
        """sign data with private key so we can validate with our public key 
        later
        """
        data = {
            "name": "Lily",
            "age": "12"
        }
        response = {
            response_type: data,
            "sign": alipay._sign(json.dumps(data), self.__private_key)
        }
        return json.dumps(response).encode("utf-8")

    def _prepare_get_oauth_token_response(self, alipay):
        return self._prepare_sync_response(alipay,
                                           "alipay_system_oauth_token_response")

    def get_client(self, sign_type):
        return AliPayClient(
            appid="appid",
            notify_url="http://example.com/app_notify_url",
            private_key=self.__private_key,
            alipay_public_key=self.__ali_public_key,
            sign_type=sign_type
        )

    def test_sign_data_with_private_key_sha1(self):
        """openssl 以及 alipay 分别对数据进行签名，得到同样的结果
        """
        alipay = self.get_client("RSA")
        result1 = alipay._sign("hello\n", self.__private_key)
        result2 = subprocess.check_output(
            "echo hello | openssl sha -sha1 -sign {} | openssl base64".format(
                self.__private_key_path
            ), shell=True).decode("utf-8")
        result2 = result2.replace("\n", "")
        self.assertEqual(result1, result2)

    def test_sign_data_with_private_key_sha256(self):
        """openssl 以及 alipay 分别对数据进行签名，得到同样的结果
        """
        alipay = self.get_client("RSA2")
        result1 = alipay._sign("hello\n", self.__private_key)
        result2 = subprocess.check_output(
            "echo hello | openssl sha -sha256 -sign {} | openssl base64".format(
                self.__private_key_path
            ), shell=True).decode("utf-8")
        result2 = result2.replace("\n", "")
        self.assertEqual(result1, result2)

    def test_verify_sha1(self):
        alipay = self.get_client("RSA")
        raw_content = "hello\n"
        signature = alipay._sign(raw_content, self.__private_key)

        # 签名验证成功
        self.assertTrue(alipay._verify(raw_content, signature,
                                       self.__ali_public_key))
        # 签名失败
        self.assertFalse(alipay._verify(raw_content[:-1], signature,
                                        self.__ali_public_key))

    def test_verify_sha256(self):
        alipay = self.get_client("RSA2")
        raw_content = "hello\n"
        signature = alipay._sign(raw_content, self.__private_key)

        # 签名验证成功
        self.assertTrue(alipay._verify(raw_content, signature,
                                       self.__ali_public_key))
        # 签名失败
        self.assertFalse(alipay._verify(raw_content[:-1], signature,
                                        self.__ali_public_key))

    @mock.patch("alipay.urlopen")
    def test_get_oauth_token(self, mock_urlopen):
        alipay = self.get_client("RSA")

        response = mock.Mock()
        response.read.return_value = self._prepare_get_oauth_token_response(alipay)
        mock_urlopen.return_value = response

        alipay.get_oauth_token(
            grant_type='code'
        )

        self.assertTrue(mock_urlopen.called)

    def test__get_string_to_be_signed(self):
        alipay = self.get_client("RSA2")

        # 简单测试
        s = """{"response_type":{"key1":"name"}}"""
        expected = """{"key1":"name"}"""
        returned = alipay.get_string_to_be_signed(s, "response_type")
        self.assertEqual(expected, returned)
        # 嵌套测试
        s = """{"response_type":{"key1":{"key2": ""}}}"""
        expected = """{"key1":{"key2": ""}}"""
        returned = alipay.get_string_to_be_signed(s, "response_type")
        self.assertEqual(expected, returned)
        # 不合法测试, 不报错就好
        s = """{"response_type":{"key1":{"key2": {{"""
        alipay.get_string_to_be_signed(s, "response_type")
