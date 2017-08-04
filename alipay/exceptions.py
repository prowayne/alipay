#!/usr/bin/env python
# coding: utf-8


class AliPayException(Exception):
    def __init__(self, code, msg, sub_code=None, sub_msg=None):
        self.code = code
        self.msg = msg
        self.sub_code = sub_code
        self.sub_msg = sub_msg

    def __repr__(self):
        return u"AliPayException<code:{}, message:{}, sub_code:{}, sub_msg:{}>".format(  # noqa
            self.code, self.msg, self.sub_code, self.sub_msg)

    def __unicode__(self):
        return u"AliPayException<code:{}, message:{}, sub_code:{}, sub_msg:{}>".format(  # noqa
            self.code, self.msg, self.sub_code, self.sub_msg)


class AliPayValidationError(Exception):
    pass
