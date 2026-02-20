"""
init_db.py — Инициализация базы данных Vault.
Запустите этот скрипт один раз перед первым запуском приложения.

Использование:
    python init_db.py
    python init_db.py --admin-user admin --admin-pass MySecretPass123
"""

import argparse
from app import app, db, bcrypt, Role, User, Group

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "Admin@1234"


def init_db(admin_username=DEFAULT_ADMIN_USERNAME, admin_password=DEFAULT_ADMIN_PASSWORD):
    with app.app_context():
        db.create_all()
        print("✓ Таблицы созданы")

        # Create default roles
        for role_data in Role.get_defaults():
            if not Role.query.filter_by(name=role_data['name']).first():
                role = Role(**role_data)
                db.session.add(role)
                print(f"  + Роль: {role_data['name']}")
        db.session.commit()

        # Create default groups
        default_groups = [
            {"name": "engineering", "description": "Инженеры и разработчики"},
            {"name": "analytics", "description": "Аналитики данных"},
            {"name": "management", "description": "Руководство"},
        ]
        for g in default_groups:
            if not Group.query.filter_by(name=g['name']).first():
                group = Group(**g)
                db.session.add(group)
                print(f"  + Группа: {g['name']}")
        db.session.commit()

        # Create admin user
        if not User.query.filter_by(username=admin_username).first():
            admin_role = Role.query.filter_by(name='admin').first()
            hashed = bcrypt.generate_password_hash(admin_password).decode('utf-8')
            admin = User(
                username=admin_username,
                password=hashed,
                role_id=admin_role.id if admin_role else None
            )
            db.session.add(admin)
            db.session.commit()
            print(f"\n✓ Администратор создан:")
            print(f"  Логин:  {admin_username}")
            print(f"  Пароль: {admin_password}")
            print(f"\n  ⚠  Смените пароль после первого входа!")
        else:
            print(f"\n⚠  Пользователь '{admin_username}' уже существует, пропускаем.")

        print("\n✓ Инициализация завершена. Запустите: python app.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vault — инициализация БД")
    parser.add_argument("--admin-user", default=DEFAULT_ADMIN_USERNAME,
                        help=f"Имя администратора (по умолчанию: {DEFAULT_ADMIN_USERNAME})")
    parser.add_argument("--admin-pass", default=DEFAULT_ADMIN_PASSWORD,
                        help="Пароль администратора")
    args = parser.parse_args()
    init_db(args.admin_user, args.admin_pass)