# coding:utf8
__author__ = 'dimples'
__date__ = '2017/10/2 20:23'

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
import pymysql
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:111111@localhost/movie'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'c897d479e321481c915e4c8f3b676a11'

# 文件上传保存路径
app.config['UP_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static\\uploads\\")
app.config['FC_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static\\uploads\\user\\")

print(app.config['FC_DIR'])


app.debug = True
db = SQLAlchemy(app)

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

# 注册蓝图
app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix='/admin')


@app.errorhandler(404)
def page_not_found(error):
    return render_template("home/404.html"), 404




