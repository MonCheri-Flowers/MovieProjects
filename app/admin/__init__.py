# coding:utf8
__author__ = 'dimples'
__date__ = '2017/10/2 20:24'

from flask import Blueprint

admin = Blueprint('admin', __name__)

import app.admin.views


