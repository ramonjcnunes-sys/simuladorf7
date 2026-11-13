"""Uso no console do contêiner: python manage_users.py create admin --admin"""
import argparse
import getpass
import re
from argon2 import PasswordHasher
from db import connect, init_db

ph = PasswordHasher()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gestão segura dos usuários F7')
    commands = parser.add_subparsers(dest='cmd', required=True)
    create = commands.add_parser('create')
    create.add_argument('username')
    create.add_argument('--admin', action='store_true')
    disable = commands.add_parser('disable')
    disable.add_argument('username')
    reset = commands.add_parser('reset-password')
    reset.add_argument('username')
    args = parser.parse_args()
    init_db()
    if args.cmd == 'create':
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,64}', args.username):
            parser.error('Usuário inválido')
        pwd = getpass.getpass('Senha (mínimo 12 caracteres): ')
        if len(pwd) < 12:
            parser.error('Senha precisa ter pelo menos 12 caracteres')
        with connect() as conn, conn.cursor() as cur:
            cur.execute('INSERT INTO users(username,password_hash,is_admin) VALUES (%s,%s,%s)',
                        (args.username, ph.hash(pwd), args.admin))
        print('Usuário criado.')
    elif args.cmd == 'disable':
        with connect() as conn, conn.cursor() as cur:
            cur.execute('UPDATE users SET is_active=FALSE, session_version=session_version+1 WHERE username=%s', (args.username,))
            cur.execute('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=%s)', (args.username,))
            if cur.rowcount == 0:
                print('Sessões revogadas; confirme se o usuário existe.')
        print('Bloqueio concluído.')
    elif args.cmd == 'reset-password':
        pwd = getpass.getpass('Nova senha (mínimo 12 caracteres): ')
        if len(pwd) < 12:
            parser.error('Senha precisa ter pelo menos 12 caracteres')
        with connect() as conn, conn.cursor() as cur:
            cur.execute('UPDATE users SET password_hash=%s, session_version=session_version+1 WHERE username=%s RETURNING id', (ph.hash(pwd), args.username))
            row = cur.fetchone()
            if not row:
                parser.error('Usuário não encontrado')
            cur.execute('DELETE FROM sessions WHERE user_id=%s', (row[0],))
        print('Senha redefinida e sessões revogadas.')
