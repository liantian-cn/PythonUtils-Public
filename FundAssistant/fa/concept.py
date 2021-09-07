# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base import DATA_DIR
import akshare as ak
import datetime


concept_list = []

def init_concept_info():
    q = ak.stock_board_concept_name_ths()
    q.name.values.tolist()
