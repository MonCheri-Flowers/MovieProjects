# coding:utf8
__author__ = 'dimples'
__date__ = '2017/10/2 20:24'

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import DataRequired, EqualTo, Email, Regexp, ValidationError

# 验证唯一性
from app.models import User


# 会员注册
class RegistForm(FlaskForm):
    name = StringField(
        label="昵称",
        validators=[
            DataRequired("请输入昵称！")
        ],
        description="昵称",
        render_kw={  # 附加选项
            "class": "form-control input-lg",
            "placeholder": "请输入账号！",
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码！")
        ],
        description="密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入密码",
        }
    )
    repwd = PasswordField(
        label="确认密码",
        validators=[
            DataRequired("请输入确认密码！"),
            EqualTo('pwd', message="两次密码不一致")
        ],
        description="确认密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入确认密码",
        }
    )
    email = StringField(
        label="邮箱",
        validators=[
            DataRequired("请输入邮箱！"),
            Email("邮箱格式不正确！")
        ],
        description="邮箱",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入邮箱",
        }
    )
    phone = StringField(
        label="手机",
        validators=[
            DataRequired("请输入手机！"),
            # 通过正则验证
            Regexp("^1[34578]\\d{9}", message="手机号码格式不正确！")
        ],
        description="手机",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入手机",
        }
    )
    submit = SubmitField(
        "注册",
        render_kw={
            "class": "btn btn-lg btn-success btn-block",
        }
    )

    # 验证
    def validate_name(self, field):
        name = field.data
        user = User.query.filter_by(name=name).count()
        if user == 1:
            raise ValidationError("昵称已经存在")

    def validate_email(self, field):
        email = field.data
        user = User.query.filter_by(email=email).count()
        if user == 1:
            raise ValidationError("邮箱已经存在")

    def validate_phone(self, field):
        phone = field.data
        user = User.query.filter_by(phone=phone).count()
        if user == 1:
            raise ValidationError("手机号码已经存在")


class LoginForm(FlaskForm):
    name = StringField(
        label="账号",
        validators=[
            DataRequired("请输入账号！")
        ],
        description="账号",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入账号！",
        }
    )
    pwd = PasswordField(
        label="密码",
        description="请输入密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入密码",
        }
    )
    submit = SubmitField(
        "登录",
        render_kw={
            "class": "btn btn-lg btn-success btn-block",
        }
    )

    # 账号密码验证
    def validate_name(self, field):
        name = field.data
        user = User.query.filter_by(name=name).count()
        if user == 0:
            raise ValidationError('账号不存在')


class UserdetailForm(FlaskForm):
    name = StringField(
        label="账号",
        validators=[
            DataRequired("请输入账号！")
        ],
        description="账号",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入账号！",
        }
    )
    email = StringField(
        label="邮箱",
        validators=[
            DataRequired("请输入邮箱！"),
            Email("邮箱格式不正确！")
        ],
        description="邮箱",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入邮箱",
        }
    )
    phone = StringField(
        label="手机",
        validators=[
            DataRequired("请输入手机！"),
            # 通过正则验证
            Regexp("^1[34578]\\d{9}", message="手机号码格式不正确！")
        ],
        description="手机",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入手机",
        }
    )

    info = TextAreaField(
        label="简介",
        validators=[
            DataRequired("请输入简介")
        ],
        description="简介",
        render_kw={
            "class": "form-control",
            "rows": "10",
        }
    )
    face = FileField(
        label="头像",
        validators=[
            DataRequired("请上传头像")
        ],
        description="头像",
    )
    submit = SubmitField(
        "保存修改",
        render_kw={
            "class": "btn btn-success",
        }
    )


class PwdForm(FlaskForm):
    oldPwd = PasswordField(
        label="旧密码",
        validators=[
            DataRequired('请输入旧密码')
        ],
        description="请输入旧密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入旧密码",
            "id": "input_pwd"
        }
    )
    newPwd = PasswordField(
        label="新密码",
        validators=[
            DataRequired('请输入新密码')
        ],
        description="请输入新密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入新密码",
            "id": "input_newpwd"
        }
    )
    submit = SubmitField(
        "修改密码",
        render_kw={
            "class": "btn btn-success",
        }
    )

    #     验证旧密码
    # def validate_oldPwd(self, field):
    #     from flask import session
    #     pwd = field.data
    #     name = session["user"]
    #     user = User.query.filter_by(
    #         name=name
    #     ).first()
    #     if not user.check_pwd(pwd):
    #         raise ValidationError('旧密码错误')


# 评论
class CommentForm(FlaskForm):
    submit = SubmitField(
        "提交评论",
        render_kw={
            "class": "btn btn-success",
            "id": "btn-sub",
        }
    )
    content = TextAreaField(
        label="内容",
        validators=[
            DataRequired("请输入内容")
        ],
        description="内容",
        render_kw={
            "id": "input_content",
        }
    )


