#!/usr/bin/env python
# coding: utf-8
import os


current_dir = os.path.dirname(os.path.realpath(__file__))


def get_certs():
    return (
        open(os.path.join(current_dir, "certs", "ali_private_key.pem")).read(),
        open(os.path.join(current_dir, "certs", "ali_public_key.pem")).read()
    )


def get_certs_path():
    return (
        os.path.join(current_dir, "certs", "ali_private_key.pem"),
        os.path.join(current_dir, "certs", "ali_public_key.pem")
    )
