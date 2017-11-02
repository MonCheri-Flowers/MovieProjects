# coding:utf8
__author__ = 'dimples'
__date__ = '2017/10/2 20:04'

from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "<h1 style='color:red'>haha </h1>"


if __name__ == '__main__':
    app.run()
