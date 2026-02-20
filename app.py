from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from functools import wraps

# делаем конфиг для приложения фласки
app = Flask(__name__)
app.config['SECRET_KEY'] = 'v3x4sm!p4ss'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ----------------------
# DATABASE MODELS
# ----------------------
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    users = db.relationship('User', backref='role', lazy=True)

    @staticmethod
    def get_defaults():
        return [
            {'name': 'admin', 'description': 'Полный доступ ко всем функциям'},
            {'name': 'engineer', 'description': 'Инженер — доступ к техническим хранилищам'},
            {'name': 'analyst', 'description': 'Аналитик — доступ к аналитическим данным'},
            {'name': 'user', 'description': 'Обычный пользователь'},
        ]


# Many-to-many: User <-> Group
user_group = db.Table('user_group',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    members = db.relationship('User', secondary=user_group, backref='groups', lazy='dynamic')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    containers = db.relationship('Container', backref='owner', lazy=True)
    passwords = db.relationship('Password', backref='owner', lazy=True)

    def is_admin(self):
        return self.role and self.role.name == 'admin'


class Container(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    icon = db.Column(db.String(10), default='🔐')
    color = db.Column(db.String(20), default='#6366f1')
    parent_id = db.Column(db.Integer, db.ForeignKey('container.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_shared = db.Column(db.Boolean, default=False)

    children = db.relationship('Container',
                               backref=db.backref('parent', remote_side=[id]),
                               lazy='dynamic')
    passwords = db.relationship('Password', backref='container', lazy=True)
    access_rules = db.relationship('ContainerAccess', backref='container', lazy=True, cascade='all, delete-orphan')


class ContainerAccess(db.Model):
    """Grants read access to a container for a specific user OR group."""
    id = db.Column(db.Integer, primary_key=True)
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    can_write = db.Column(db.Boolean, default=False)
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])
    group = db.relationship('Group', foreign_keys=[group_id])
    granter = db.relationship('User', foreign_keys=[granted_by])


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    login = db.Column(db.String(150))
    password = db.Column(db.String(255))
    url = db.Column(db.String(300))
    notes = db.Column(db.Text)
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    audit_logs = db.relationship('AuditLog', backref='password_entry', lazy=True, cascade='all, delete-orphan')


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_id = db.Column(db.Integer, db.ForeignKey('password.id'), nullable=True)
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash("Доступ запрещён", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


def log_action(action, password_id=None, container_id=None, details=None):
    entry = AuditLog(
        password_id=password_id,
        container_id=container_id,
        user_id=current_user.id,
        action=action,
        details=details
    )
    db.session.add(entry)


def can_access_container(container, user=None):
    """Check if user has access to a container (owner or via access rules)."""
    if user is None:
        user = current_user
    if user.is_admin():
        return True
    if container.user_id == user.id:
        return True
    # Check direct user access
    user_access = ContainerAccess.query.filter_by(
        container_id=container.id, user_id=user.id
    ).first()
    if user_access:
        return True
    # Check group access
    user_group_ids = [g.id for g in user.groups]
    if user_group_ids:
        group_access = ContainerAccess.query.filter(
            ContainerAccess.container_id == container.id,
            ContainerAccess.group_id.in_(user_group_ids)
        ).first()
        if group_access:
            return True
    return False


def get_shared_containers(user):
    """Get containers shared with user (not owned by user)."""
    # Direct user access
    direct = db.session.query(Container).join(
        ContainerAccess, ContainerAccess.container_id == Container.id
    ).filter(
        ContainerAccess.user_id == user.id,
        Container.user_id != user.id
    ).all()

    # Group access
    user_group_ids = [g.id for g in user.groups]
    group_shared = []
    if user_group_ids:
        group_shared = db.session.query(Container).join(
            ContainerAccess, ContainerAccess.container_id == Container.id
        ).filter(
            ContainerAccess.group_id.in_(user_group_ids),
            Container.user_id != user.id
        ).all()

    all_shared = list({c.id: c for c in direct + group_shared}.values())
    return all_shared


# ----------------------
# ROUTES — AUTH
# ----------------------

@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Пользователь уже существует", "danger")
            return redirect(url_for("register"))
        default_role = Role.query.filter_by(name='user').first()
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password,
                        role_id=default_role.id if default_role else None)
        db.session.add(new_user)
        db.session.commit()
        flash("Аккаунт создан! Войдите.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Неверный логин или пароль", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ----------------------
# ROUTES — PROFILE
# ----------------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_pass = request.form.get("current_password")
        new_pass = request.form.get("new_password")
        confirm_pass = request.form.get("confirm_password")

        if not bcrypt.check_password_hash(current_user.password, current_pass):
            flash("Текущий пароль неверен", "danger")
            return redirect(url_for("profile"))
        if new_pass != confirm_pass:
            flash("Пароли не совпадают", "danger")
            return redirect(url_for("profile"))
        if len(new_pass) < 6:
            flash("Пароль должен быть не менее 6 символов", "danger")
            return redirect(url_for("profile"))

        current_user.password = bcrypt.generate_password_hash(new_pass).decode('utf-8')
        db.session.commit()
        flash("Пароль успешно изменён", "success")
        return redirect(url_for("profile"))

    # Recent audit logs for current user
    recent_logs = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc()).limit(20).all()
    return render_template("profile.html", logs=recent_logs)


# ----------------------
# ROUTES — DASHBOARD
# ----------------------

@app.route("/dashboard")
@login_required
def dashboard():
    root_containers = Container.query.filter_by(user_id=current_user.id, parent_id=None).all()
    shared_containers = get_shared_containers(current_user)
    shared_root = [c for c in shared_containers if c.parent_id is None]
    total_passwords = Password.query.filter_by(user_id=current_user.id).count()
    total_containers = Container.query.filter_by(user_id=current_user.id).count()
    return render_template("dashboard.html",
                           containers=root_containers,
                           shared_containers=shared_root,
                           current_container=None,
                           subcontainers=[],
                           passwords=[],
                           total_passwords=total_passwords,
                           total_containers=total_containers)


@app.route("/container/<int:container_id>")
@login_required
def open_container(container_id):
    container = Container.query.get_or_404(container_id)

    if not can_access_container(container):
        flash("У вас нет доступа к этой папке", "danger")
        return redirect(url_for("dashboard"))

    log_action("view_container", container_id=container_id,
               details=f"Открыт контейнер: {container.name}")
    db.session.commit()

    root_containers = Container.query.filter_by(user_id=current_user.id, parent_id=None).all()
    shared_containers = get_shared_containers(current_user)
    shared_root = [c for c in shared_containers if c.parent_id is None]
    subcontainers = Container.query.filter_by(parent_id=container_id).all()
    # Filter subcontainers by access
    subcontainers = [c for c in subcontainers if can_access_container(c)]
    passwords = Password.query.filter_by(container_id=container_id).all()
    total_passwords = Password.query.filter_by(user_id=current_user.id).count()
    total_containers = Container.query.filter_by(user_id=current_user.id).count()

    # Access rules for container owner
    access_rules = []
    all_users = []
    all_groups = []
    is_owner = container.user_id == current_user.id
    if is_owner:
        access_rules = ContainerAccess.query.filter_by(container_id=container_id).all()
        all_users = User.query.filter(User.id != current_user.id).all()
        all_groups = Group.query.all()

    # Audit log for container
    container_logs = AuditLog.query.filter_by(container_id=container_id)\
        .order_by(AuditLog.timestamp.desc()).limit(30).all()

    # Breadcrumb
    breadcrumb = []
    cur = container
    while cur:
        breadcrumb.insert(0, cur)
        cur = cur.parent

    return render_template("dashboard.html",
                           current_container=container,
                           containers=root_containers,
                           shared_containers=shared_root,
                           subcontainers=subcontainers,
                           passwords=passwords,
                           breadcrumb=breadcrumb,
                           total_passwords=total_passwords,
                           total_containers=total_containers,
                           access_rules=access_rules,
                           all_users=all_users,
                           all_groups=all_groups,
                           is_owner=is_owner,
                           container_logs=container_logs)


# ----------------------
# ROUTES — CONTAINERS
# ----------------------

@app.route("/create_container", methods=["POST"])
@login_required
def create_container():
    name = request.form.get("name")
    parent_id = request.form.get("parent_id")
    icon = request.form.get("icon", "🔐")
    color = request.form.get("color", "#6366f1")

    if not name:
        flash("Введите название хранилища", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    new_container = Container(
        name=name, icon=icon, color=color,
        user_id=current_user.id,
        parent_id=parent_id if parent_id else None
    )
    db.session.add(new_container)
    db.session.flush()
    log_action("create_container", container_id=new_container.id,
               details=f"Создан контейнер: {name}")
    db.session.commit()

    if parent_id:
        return redirect(url_for("open_container", container_id=parent_id))
    return redirect(url_for("dashboard"))


@app.route("/delete_container/<int:container_id>")
@login_required
def delete_container(container_id):
    container = Container.query.get_or_404(container_id)
    if container.user_id != current_user.id and not current_user.is_admin():
        flash("У вас нет доступа", "danger")
        return redirect(url_for("dashboard"))

    parent_id = container.parent_id

    def delete_subcontainers(cont_id):
        subcontainers = Container.query.filter_by(parent_id=cont_id).all()
        for subcont in subcontainers:
            AuditLog.query.filter_by(container_id=subcont.id).delete()
            Password.query.filter_by(container_id=subcont.id).delete()
            delete_subcontainers(subcont.id)
            db.session.delete(subcont)

    AuditLog.query.filter_by(container_id=container_id).delete()
    Password.query.filter_by(container_id=container_id).delete()
    delete_subcontainers(container_id)
    db.session.delete(container)
    db.session.commit()

    flash("Хранилище удалено", "success")
    if parent_id:
        return redirect(url_for("open_container", container_id=parent_id))
    return redirect(url_for("dashboard"))


# ----------------------
# ROUTES — ACCESS CONTROL
# ----------------------

@app.route("/container/<int:container_id>/grant_access", methods=["POST"])
@login_required
def grant_access(container_id):
    container = Container.query.get_or_404(container_id)
    if container.user_id != current_user.id and not current_user.is_admin():
        flash("Нет прав", "danger")
        return redirect(url_for("open_container", container_id=container_id))

    access_type = request.form.get("access_type")  # 'user' or 'group'
    can_write = request.form.get("can_write") == "1"

    if access_type == "user":
        user_id = request.form.get("user_id")
        if not user_id:
            flash("Выберите пользователя", "danger")
            return redirect(url_for("open_container", container_id=container_id))
        existing = ContainerAccess.query.filter_by(container_id=container_id, user_id=user_id).first()
        if existing:
            flash("Доступ уже выдан", "warning")
            return redirect(url_for("open_container", container_id=container_id))
        access = ContainerAccess(container_id=container_id, user_id=int(user_id),
                                  can_write=can_write, granted_by=current_user.id)
        db.session.add(access)
        target_user = User.query.get(user_id)
        log_action("grant_access", container_id=container_id,
                   details=f"Выдан доступ пользователю: {target_user.username}")
    elif access_type == "group":
        group_id = request.form.get("group_id")
        if not group_id:
            flash("Выберите группу", "danger")
            return redirect(url_for("open_container", container_id=container_id))
        existing = ContainerAccess.query.filter_by(container_id=container_id, group_id=group_id).first()
        if existing:
            flash("Доступ для группы уже выдан", "warning")
            return redirect(url_for("open_container", container_id=container_id))
        access = ContainerAccess(container_id=container_id, group_id=int(group_id),
                                  can_write=can_write, granted_by=current_user.id)
        db.session.add(access)
        group = Group.query.get(group_id)
        log_action("grant_access", container_id=container_id,
                   details=f"Выдан доступ группе: {group.name}")

    db.session.commit()
    flash("Доступ выдан", "success")
    return redirect(url_for("open_container", container_id=container_id))


@app.route("/container/<int:container_id>/revoke_access/<int:access_id>")
@login_required
def revoke_access(container_id, access_id):
    container = Container.query.get_or_404(container_id)
    if container.user_id != current_user.id and not current_user.is_admin():
        flash("Нет прав", "danger")
        return redirect(url_for("open_container", container_id=container_id))

    access = ContainerAccess.query.get_or_404(access_id)
    log_action("revoke_access", container_id=container_id, details="Доступ отозван")
    db.session.delete(access)
    db.session.commit()
    flash("Доступ отозван", "success")
    return redirect(url_for("open_container", container_id=container_id))


# ----------------------
# ROUTES — PASSWORDS
# ----------------------

@app.route("/create_password", methods=["POST"])
@login_required
def create_password():
    title = request.form.get("title")
    login_field = request.form.get("login")
    password_field = request.form.get("password")
    url_field = request.form.get("url")
    notes_field = request.form.get("notes")
    container_id = request.form.get("container_id")

    if not title or not container_id:
        flash("Заполните обязательные поля", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    container = Container.query.get_or_404(container_id)
    if not can_access_container(container):
        flash("Нет прав", "danger")
        return redirect(url_for("dashboard"))

    new_pass = Password(title=title, login=login_field, password=password_field,
                        url=url_field, notes=notes_field,
                        container_id=container_id, user_id=current_user.id)
    db.session.add(new_pass)
    db.session.flush()
    log_action("create_password", password_id=new_pass.id, container_id=int(container_id),
               details=f"Создан пароль: {title}")
    db.session.commit()

    flash("Пароль сохранён", "success")
    return redirect(url_for("open_container", container_id=container_id))


@app.route("/view_password/<int:password_id>")
@login_required
def view_password(password_id):
    """Log password view event."""
    password = Password.query.get_or_404(password_id)
    container = Container.query.get(password.container_id)
    if not can_access_container(container):
        return jsonify({"error": "forbidden"}), 403
    log_action("view_password", password_id=password_id, container_id=password.container_id,
               details=f"Просмотрен пароль: {password.title}")
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/edit_password/<int:password_id>", methods=["POST"])
@login_required
def edit_password(password_id):
    password = Password.query.get_or_404(password_id)
    container = Container.query.get(password.container_id)
    if not can_access_container(container):
        flash("У вас нет доступа", "danger")
        return redirect(url_for("dashboard"))

    old_title = password.title
    password.title = request.form.get("title")
    password.login = request.form.get("login")
    password.password = request.form.get("password")
    password.url = request.form.get("url")
    password.notes = request.form.get("notes")
    log_action("edit_password", password_id=password_id, container_id=password.container_id,
               details=f"Изменён пароль: {old_title} → {password.title}")
    db.session.commit()

    flash("Пароль обновлён", "success")
    return redirect(url_for("open_container", container_id=password.container_id))


@app.route("/delete_password/<int:password_id>")
@login_required
def delete_password(password_id):
    password = Password.query.get_or_404(password_id)
    container = Container.query.get(password.container_id)
    if not can_access_container(container):
        flash("У вас нет доступа", "danger")
        return redirect(url_for("dashboard"))

    container_id = password.container_id
    log_action("delete_password", container_id=container_id,
               details=f"Удалён пароль: {password.title}")
    db.session.delete(password)
    db.session.commit()

    flash("Пароль удалён", "success")
    return redirect(url_for("open_container", container_id=container_id))


@app.route("/password/<int:password_id>/history")
@login_required
def password_history(password_id):
    password = Password.query.get_or_404(password_id)
    container = Container.query.get(password.container_id)
    if not can_access_container(container):
        flash("Нет доступа", "danger")
        return redirect(url_for("dashboard"))
    logs = AuditLog.query.filter_by(password_id=password_id)\
        .order_by(AuditLog.timestamp.desc()).all()
    return render_template("password_history.html", password=password, logs=logs)


# ----------------------
# ROUTES — ADMIN
# ----------------------

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    users = User.query.all()
    roles = Role.query.all()
    groups = Group.query.all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    root_containers = Container.query.filter_by(user_id=current_user.id, parent_id=None).all()
    shared_containers = get_shared_containers(current_user)
    shared_root = [c for c in shared_containers if c.parent_id is None]
    return render_template("admin.html", users=users, roles=roles,
                           groups=groups, recent_logs=recent_logs,
                           containers=root_containers,
                           shared_containers=shared_root,
                           current_container=None)


@app.route("/admin/set_role", methods=["POST"])
@login_required
@admin_required
def admin_set_role():
    user_id = request.form.get("user_id")
    role_id = request.form.get("role_id")
    user = User.query.get_or_404(user_id)
    user.role_id = int(role_id) if role_id else None
    db.session.commit()
    flash(f"Роль пользователя {user.username} обновлена", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/set_group", methods=["POST"])
@login_required
@admin_required
def admin_set_group():
    user_id = request.form.get("user_id")
    group_ids = request.form.getlist("group_ids")
    user = User.query.get_or_404(user_id)
    user.groups.clear()
    for gid in group_ids:
        group = Group.query.get(int(gid))
        if group:
            user.groups.append(group)
    db.session.commit()
    flash(f"Группы пользователя {user.username} обновлены", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/create_group", methods=["POST"])
@login_required
@admin_required
def admin_create_group():
    name = request.form.get("name")
    description = request.form.get("description", "")
    if not name:
        flash("Введите название группы", "danger")
        return redirect(url_for("admin_panel"))
    if Group.query.filter_by(name=name).first():
        flash("Группа уже существует", "warning")
        return redirect(url_for("admin_panel"))
    group = Group(name=name, description=description)
    db.session.add(group)
    db.session.commit()
    flash(f"Группа '{name}' создана", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete_group/<int:group_id>")
@login_required
@admin_required
def admin_delete_group(group_id):
    group = Group.query.get_or_404(group_id)
    db.session.delete(group)
    db.session.commit()
    flash("Группа удалена", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/toggle_user/<int:user_id>")
@login_required
@admin_required
def admin_toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Нельзя деактивировать себя", "danger")
        return redirect(url_for("admin_panel"))
    user.is_active = not user.is_active
    db.session.commit()
    status = "активирован" if user.is_active else "деактивирован"
    flash(f"Пользователь {user.username} {status}", "success")
    return redirect(url_for("admin_panel"))


if __name__ == "__main__":
    app.run(debug=True)