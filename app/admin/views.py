# coding:utf8
__author__ = 'dimples'
__date__ = '2017/10/2 20:24'

from . import admin
from flask import render_template, redirect, url_for, flash, session, request, abort
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, Oplog, Adminlog, Userlog, Role, Auth
from functools import wraps
from app import db, app
from werkzeug.utils import secure_filename  # 把 filename转换安全
import os
import stat
import datetime
import uuid


# 上下文应用处理器（管理员登录时间）
@admin.context_processor
def tol_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data


# 登录装饰器
def admin_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 访问权限控制，装饰器
def admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session['admin_id']
        ).first()
        auths = admin.role.auths
        auths = list(map(lambda v: int(v), auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if val == v.id]
        rule = request.url_rule
        if rule not in urls:
            abort(404)
        return f(*args, **kwargs)

    return decorated_function


# 修改文件名称(用户登录时间)
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y-%m-%d%H-%M-%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@admin.route("/")
@admin_login_req
def index():
    return render_template('admin/index.html')


@admin.route("/login/", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # 提交的时候进行验证(获取表单信息)
        data = form.data
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.check_pwd(data['pwd']):
            flash('密码错误', 'err')
            return redirect(url_for('admin.login'))
        session['admin'] = data['account']
        session['admin_id'] = admin.id
        # 会员登录日志
        adminlog = Adminlog(
            ip=request.remote_addr,
            admin_id=admin.id
        )
        db.session.add(adminlog)
        db.session.commit()

        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


@admin.route("/logout/")
@admin_login_req
def logout():
    session.pop("admin", None)
    session.pop("admin_id", None)
    return redirect(url_for('admin.login'))


# 修改密码
@admin.route("/pwd/", methods=['GET', 'POST'])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session["admin"]).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data["newPwd"])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功,请重新登录", 'ok')
        return redirect(url_for('admin.logout'))
    return render_template('admin/pwd.html', form=form)


# 标签管理页面（添加标签）
@admin.route("/tag/add/", methods=['GET', 'POST'])
@admin_login_req
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data['name']).count()
        if tag == 1:
            flash("标签已经存在", "err")
            return redirect(url_for('admin.tag_add'))
        tag = Tag(  # 存入数据库
            name=data['name']
        )
        db.session.add(tag)
        db.session.commit()
        flash("添加成功", 'ok')
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,  # 获取登录的Ip
            reason="%s" % data['name']
        )
        db.session.add(oplog)
        db.session.commit()
        redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


@admin.route("/tag/list/<int:page>/", methods=['GET'])
@admin_login_req
def tag_list(page=None):
    """查询，分页显示"""
    if page is None:
        page = 1
    page_data = Tag.query.order_by(
        Tag.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('admin/tag_list.html', page_data=page_data)


# 标签的删除
@admin.route("/tag/del/<int:id>/", methods=['GET'])
@admin_login_req
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash("删除标签成功", 'ok')
    return redirect(url_for('admin.tag_list', page=1))


# 编辑标签
@admin.route("/tag/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data['name']).count()
        if tag.name != data['name'] and tag_count == 1:
            flash("标签已经存在", "err")
            return redirect(url_for('admin.tag_edit', id=id))
        tag.name = data['name']  # 修改
        db.session.add(tag)
        db.session.commit()
        flash("添加成功", 'ok')
        redirect(url_for('admin.tag_edit', id=id))
    return render_template('admin/tag_edit.html', form=form, tag=tag)


# 电影管理
@admin.route("/movie/add/", methods=['GET', 'POST'])
@admin_login_req
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        # print("data = ", data)
        # 获取上传的数据
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)
        # print("file_url = ", file_url)
        # print("file_logo = ", file_logo)
        # 把文件保存在目录下
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            # 授权
            os.chmod(app.config['UP_DIR'], stat.S_IREAD + stat.S_IWRITE)

        url = change_filename(file_url)
        logo = change_filename(file_logo)
        # print("url = ", url)
        # print("logo = ", logo)
        # 保存
        form.url.data.save(app.config['UP_DIR'] + url)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        movie = Movie(
            title=data["title"],
            url=url,
            info=data["info"],
            logo=logo,
            star=int(data["star"]),
            playnum=0,
            commentnum=0,
            tag_id=int(data["tag_id"]),
            area=data["area"],
            length=data["length"],
            release_time=data["release_time"],
        )
        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功", 'ok')
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie_add.html', form=form)


@admin.route("/movie/list/<int:page>", methods=['GET'])
@admin_login_req
def movie_list(page=None):
    if page is None:
        page = 1
    # 多表关联的时候使用filter
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('admin/movie_list.html', page_data=page_data)


# 删除电影
@admin.route("/movie/del/<int:id>", methods=['GET'])
@admin_login_req
def movie_del(id=None):
    movie = Movie.query.get_or_404(int(id))
    db.session.delete(movie)
    db.session.commit()
    flash("删除成功", 'ok')
    return redirect(url_for('admin.movie_list', page=1))


# 编辑电影
@admin.route("/movie/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_req
def movie_edit(id=None):
    form = MovieForm()
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(int(id))
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star

    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count == 1 and movie.title != data['title']:
            flash("片名已经存在", 'err')
            return redirect(url_for('admin.movie_edit', id=movie.id))

        # 把文件保存在目录下
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], stat.S_IREAD + stat.S_IWRITE)

        if form.url.data.filename != "":
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config['UP_DIR'] + movie.url)

        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            # 保存
            form.logo.data.save(app.config['UP_DIR'] + movie.logo)

        movie.title = data['title']
        movie.info = data['info']
        movie.star = data['star']
        movie.tag_id = data['tag_id']
        movie.area = data['area']
        movie.length = data['length']
        movie.release_time = data['release_time']

        db.session.add(movie)
        db.session.commit()
        flash("修改成功", 'ok')
        return redirect(url_for('admin.movie_edit', id=movie.id))

    return render_template("admin/movie_edit.html", form=form, movie=movie)


# 上映预告
@admin.route("/preview/add/", methods=['GET', 'POST'])
@admin_login_req
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        # 获取上传的数据
        file_logo = secure_filename(form.logo.data.filename)
        print("file_logo = ", file_logo)
        # 把文件保存在目录下
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            # 授权
            os.chmod(app.config['UP_DIR'], stat.S_IREAD + stat.S_IWRITE)

        logo = change_filename(file_logo)
        print("logo = ", logo)
        # 保存
        form.logo.data.save(app.config['UP_DIR'] + logo)
        preview = Preview(
            title=data["title"],
            logo=logo,
        )
        db.session.add(preview)
        db.session.commit()
        flash("添加封面成功", 'ok')
        return redirect(url_for('admin.preview_add'))
    return render_template('admin/preview_add.html', form=form)


# 预告列表
@admin.route("/preview/list/<int:page>", methods=['GET'])
@admin_login_req
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.addtime.desc()
    ).paginate(page=page, per_page=3)
    return render_template('admin/preview_list.html', page_data=page_data)


# 删除预告
@admin.route("/preview/del/<int:id>", methods=['GET'])
@admin_login_req
def preview_del(id=None):
    preview = Preview.query.get_or_404(int(id))
    db.session.delete(preview)
    db.session.commit()
    flash("删除预告成功！", 'ok')
    return redirect(url_for('admin.preview_list', page=1))


# 修改预告
@admin.route("/preview/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_req
def preview_edit(id=None):
    form = PreviewForm()
    preview = Preview.query.get_or_404(int(id))

    if form.validate_on_submit():
        data = form.data
        form.logo.validators = []

        preview_count = Preview.query.filter_by(title=data["title"]).count()
        # and preview.title != data['title']
        if preview_count == 1:
            flash("标题已经存在", "err")
            return redirect(url_for('admin.preview_edit', id=preview.id))

        if form.logo.data.filename != "":
            # 获取上传的数据
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + preview.logo)

        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], stat.S_IREAD + stat.S_IWRITE)

        preview.title = data["title"]

        db.session.add(preview)
        db.session.commit()
        flash("修改封面成功", 'ok')
        return redirect(url_for('admin.preview_edit', id=preview.id))
    return render_template('admin/preview_edit.html', form=form, preview=preview)


# 会员管理（会员列表、查看会员）
@admin.route("/user/list/<int:page>", methods=['GET'])
@admin_login_req
def user_list(page=None):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        User.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template('admin/user_list.html', page_data=page_data)


# 查看用户
@admin.route("/user/view/<int:id>", methods=['GET', 'POST'])
@admin_login_req
def user_view(id=None):
    user = User.query.get_or_404(int(id))
    return render_template('admin/user_view.html', user=user)


# 删除用户
@admin.route("/user/del/<int:id>", methods=['GET'])
@admin_login_req
def user_del(id=None):
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash("删除用户成功！", 'ok')
    return redirect(url_for('admin.user_list', page=1))


# 评论管理(多表)
@admin.route("/comment/list/<int:page>", methods=['GET'])
@admin_login_req
def comment_list(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template('admin/comment_list.html', page_data=page_data)


# 删除评论
@admin.route("/comment/del/<int:id>", methods=['GET'])
@admin_login_req
def comment_del(id=None):
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("删除评论成功！", 'ok')
    return redirect(url_for('admin.comment_list', page=1))


# 收藏管理
@admin.route("/moviecol/list/<int:page>", methods=['GET'])
@admin_login_req
def moviecol_list(page=None):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Moviecol.movie_id == Movie.id,
        Moviecol.user_id == User.id
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template('admin/moviecol_list.html', page_data=page_data)


# 删除收藏
@admin.route("/moviecol/del/<int:id>", methods=['GET'])
@admin_login_req
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功！", 'ok')
    return redirect(url_for('admin.moviecol_list', page=1))


# 日志管理(操作日志列表、管理员登录列表、会员登录列表)
@admin.route("/oplog/list/<int:page>", methods=['GET'])
@admin_login_req
def oplog_list(page=None):
    if page is None:
        page = 1
    page_data = Oplog.query.join(
        Admin
    ).order_by(
        Oplog.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template('admin/oplog_list.html', page_data=page_data)


@admin.route("/adminloginlog/list/<int:page>", methods=['GET'])
@admin_login_req
def adminloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Adminlog.query.join(
        Admin
    ).filter(
        Admin.id == Adminlog.admin_id
    ).order_by(
        Adminlog.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template('admin/adminloginlog_list.html', page_data=page_data)


@admin.route("/userloginlog/list/<int:page>", methods=['GET'])
@admin_login_req
def userloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.join(
        User
    ).filter(
        User.id == Userlog.user_id
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template('admin/userloginlog_list.html', page_data=page_data)


# 权限管理(添加权限、列表)
@admin.route("/auth/add/", methods=['GET', 'POST'])
@admin_login_req
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data

        auth = Auth(
            name=data['name'],
            url=data['url'],
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功！", 'ok')
        return redirect(url_for('admin.auth_add'))
    return render_template('admin/auth_add.html', form=form)


@admin.route("/auth/list/<int:page>", methods=['GET'])
@admin_login_req
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(
        Auth.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template('admin/auth_list.html', page_data=page_data)


# 修改权限
@admin.route('/auth/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(int(id))
    if form.validate_on_submit():
        data = form.data
        # auth_count = Auth.query.filter_by(name=data["name"]).count()
        # if auth_count == 1:
        #     flash("权限已经存在", "err")
        #     return redirect(url_for('admin.auth_edit', id=auth.id))

        auth.name = data['name']
        auth.url = data['url']
        db.session.add(auth)
        db.session.commit()
        flash("修改权限成功!", "ok")
        return redirect(url_for('admin.auth_edit', id=id))
    return render_template('admin/auth_edit.html', form=form, auth=auth)


# 删除权限
@admin.route('/auth/del/<int:id>/', methods=['GET'])
@admin_login_req
def auth_del(id=None):
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功!", "ok")
    return redirect(url_for('admin.auth_list', page=1))


# 角色管理(添加、列表)
@admin.route("/role/add/", methods=['GET', 'POST'])
@admin_login_req
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        print(data)
        role = Role(
            name=data['name'],
            auths=",".join(map(lambda v: str(v), data['auths']))  # 拼接成字符串
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功！", "ok")
        return redirect(url_for('admin.role_add'))
    return render_template('admin/role_add.html', form=form)


@admin.route("/role/list/<int:page>", methods=['GET'])
@admin_login_req
def role_list(page=None):
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        Role.addtime.desc()
    ).paginate(
        page=page, per_page=3
    )
    return render_template('admin/role_list.html', page_data=page_data)


# 删除角色
@admin.route("/role/del/<int:id>", methods=['GET'])
@admin_login_req
def role_del(id=None):
    role = Role.query.get_or_404(int(id))
    db.session.delete(role)
    db.session.commit()
    flash("删除角色成功！", 'ok')
    return redirect(url_for('admin.role_list', page=1))


# 修改角色
@admin.route('/role/edit/<int:id>', methods=['GET', 'POST'])
@admin_login_req
def role_edit(id=None):
    form = RoleForm()
    role = Role.query.get_or_404(id)
    if request.method == 'GET':
        auths = role.auths
        form.auths.data = list(map(lambda v: int(v), auths.split(",")))  # 转换成列表

    if form.validate_on_submit():
        data = form.data
        # 多选框赋值
        role.name = data['name']
        # 转换成以,分割开的字符串
        role.auths = ".".join(map(lambda v: str(v), data["auths"]))
        db.session.add(role)
        db.session.commit()
        flash("修改角色成功!", "ok")
        return redirect(url_for('admin.role_edit', id=id))
    return render_template('admin/role_edit.html', form=form, role=role)


# 管理员权限(添加、列表)
@admin.route("/admin/add/", methods=['GET', 'POST'])
@admin_login_req
def admin_add():
    form = AdminForm()
    from werkzeug.security import generate_password_hash
    if form.validate_on_submit():
        data = form.data
        admin = Admin(
            name=data["name"],
            pwd=generate_password_hash(data['pwd']),
            role_id=data["role_id"],
            is_super=1
        )
        db.session.add(admin)
        db.session.commit()
        flash("管理员用户添加成功！", 'ok')
        return redirect(url_for('admin.admin_add'))
    return render_template('admin/admin_add.html', form=form)


@admin.route("/admin/list/<int:page>", methods=['GET'])
@admin_login_req
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.join(
        Role
    ).filter(
        Role.id == Admin.role_id,
    ).order_by(
        Admin.addtime.desc()
    ).paginate(
        page=page, per_page=3
    )
    return render_template('admin/admin_list.html', page_data=page_data)



