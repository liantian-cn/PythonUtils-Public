# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import pathlib
import datetime
import marshal
from slugify import slugify

BASE_DIR = pathlib.Path(__file__).parent
DATA_DIR = BASE_DIR.joinpath("DATA")
DATA_DIR.mkdir(exist_ok=True)


def save_date(data, title, suffix, delta=86400):
    return True


def load_data(title, suffix):
    return False
