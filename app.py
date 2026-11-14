"""Acesso protegido ao HTML do simulador F7 Mirar Prime."""
import hashlib
import html
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher, exceptions as argon_exc
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from db import connect, init_db

ph = PasswordHasher()
COOKIE = 'f7_session'
LOGIN_CSRF_COOKIE = '__Host-f7_login_csrf'
TTL_HOURS = 12
# Limitação simples para uma instância (em escala, usar Redis ou rate-limit no proxy).
attempts = defaultdict(deque)

@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

@app.middleware('http')
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    if request.url.scheme == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

def hash_token(value):
    return hashlib.sha256(value.encode()).hexdigest()

def current_user(request):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    with connect() as conn, conn.cursor() as cur:
        cur.execute('''SELECT u.id, u.username, u.is_admin, s.csrf_token
                       FROM sessions s JOIN users u ON s.user_id=u.id
                       WHERE s.token_hash=%s AND s.expires_at>now()
                         AND u.is_active=TRUE AND s.session_version=u.session_version''',
                    (hash_token(token),))
        return cur.fetchone()

def safe_html(text):
    return html.escape(str(text), quote=True)

def origin_allowed(request):
    origin = request.headers.get('origin')
    if not origin:
        # Alguns clientes legítimos não enviam Origin; SameSite=Strict ainda ajuda.
        return True
    from urllib.parse import urlsplit
    expected = os.environ.get('PUBLIC_ORIGIN', '').rstrip('/')
    if not expected:
        return False  # configurar PUBLIC_ORIGIN antes de ativar POSTs
    try:
        return urlsplit(origin).scheme == 'https' and origin.rstrip('/') == expected
    except ValueError:
        return False

def page(title, body):
    return f'''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{safe_html(title)} | F7 Mirar Prime</title>
<style>:root{{--azul:#071A37;--ouro:#DDA943}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;background:#f3f6fa;font:16px Arial,sans-serif;color:#15283f}}header{{padding:22px 30px;background:var(--azul);color:white;border-bottom:3px solid var(--ouro)}}header b{{letter-spacing:.5px}}main{{width:min(510px,calc(100% - 32px));margin:55px auto;padding:30px;background:white;border-radius:12px;box-shadow:0 6px 24px #071A3714}}h1{{font-size:24px}}label{{display:block;margin:15px 0 6px;font-weight:bold}}input{{width:100%;font:inherit;padding:12px;border:1px solid #cbd5e1;border-radius:6px}}button{{border:0;border-radius:6px;background:var(--azul);color:white;padding:12px 18px;font:inherit;cursor:pointer;margin-top:15px}}a{{color:#123f77}}.error{{background:#fff2f2;color:#9b1b1b;padding:10px;border-radius:6px}}.muted{{color:#657386;font-size:14px}}.row{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}</style></head>
<body><header><b>F7 MIRAR PRIME</b> · Área restrita</header><main>{body}</main></body></html>'''

def login_view(error=''):
    # Token CSRF exclusivo do formulário de login. O prefixo __Host- impede
    # que outro subdomínio defina esse cookie para o domínio principal.
    csrf = secrets.token_urlsafe(32)
    msg = '<p class="error">Usuário ou senha inválidos.</p>' if error else ''
    body = f'''<h1>Entrar no simulador</h1><p class="muted">Acesso exclusivo para usuários autorizados.</p>{msg}
<form method="post" action="/login"><input type="hidden" name="login_csrf" value="{safe_html(csrf)}">
<label for="username">Usuário</label><input required id="username" name="username" autocomplete="username" maxlength="64">
<label for="password">Senha</label><input required type="password" id="password" name="password" autocomplete="current-password">
<button type="submit">Entrar</button></form>'''
    response = HTMLResponse(page('Entrar', body))
    response.set_cookie(LOGIN_CSRF_COOKIE, csrf, max_age=900, httponly=True,
                        secure=True, samesite='strict', path='/')
    return response


@app.get('/health')
def health():
    return {'status':'ok'}

@app.get('/login')
def login(request: Request):
    if current_user(request):
        return RedirectResponse('/', status_code=303)
    return login_view()

@app.post('/login')
def do_login(request: Request, username: str = Form(...), password: str = Form(...),
             login_csrf: str = Form(...)):
    # A validação CSRF não depende de cabeçalhos Origin que podem variar
    # entre navegadores e proxies. É obrigatória para todos os logins.
    expected_csrf = request.cookies.get(LOGIN_CSRF_COOKIE, '')
    if not expected_csrf or not secrets.compare_digest(expected_csrf, login_csrf):
        return Response('Formulário expirado. Recarregue a página de login.',
                        status_code=403, media_type='text/plain')
    key = (request.client.host if request.client else '', username.casefold())
    history = attempts[key]
    now = time.monotonic()
    while history and history[0] < now - 900:
        history.popleft()
    if len(history) >= 5:
        return HTMLResponse(page('Acesso temporariamente limitado', '<h1>Muitas tentativas</h1><p>Tente novamente após 15 minutos.</p>'), status_code=429)
    username = username.strip()
    with connect() as conn, conn.cursor() as cur:
        cur.execute('SELECT id,password_hash,session_version FROM users WHERE username=%s AND is_active=TRUE', (username,))
        user = cur.fetchone()
        valid = False
        if user:
            try:
                valid = ph.verify(user[1], password)
            except (argon_exc.VerifyMismatchError, argon_exc.VerificationError, argon_exc.InvalidHashError):
                pass
        if not valid:
            history.append(now)
            return login_view(error='1')
        attempts.pop(key, None)
        raw_token = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        expiry = datetime.now(timezone.utc) + timedelta(hours=TTL_HOURS)
        cur.execute('INSERT INTO sessions(token_hash,user_id,csrf_token,session_version,expires_at) VALUES (%s,%s,%s,%s,%s)',
                    (hash_token(raw_token), user[0], csrf, user[2], expiry))
        cur.execute('DELETE FROM sessions WHERE expires_at < now()')
    resp = RedirectResponse('/', status_code=303)
    resp.set_cookie(COOKIE, raw_token, max_age=TTL_HOURS*3600, httponly=True, secure=True, samesite='strict', path='/')
    resp.delete_cookie(LOGIN_CSRF_COOKIE, path='/')
    return resp

@app.get('/')
def simulator(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse('/login', status_code=303)
    content = Path(__file__).with_name('index.html').read_text(encoding='utf-8')
    logout = f'''<div style="display:flex;align-items:center;margin-left:auto;gap:12px;color:white;font:13px Arial,sans-serif">
<span>{safe_html(user[1])}</span>{'<a href="/admin" style="color:#DDA943">Usuários</a>' if user[2] else ''}
<form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf" value="{safe_html(user[3])}"><button type="submit" style="border:1px solid #DDA943;background:transparent;color:white;padding:7px 12px;cursor:pointer">Sair</button></form></div>'''
    # Acrescenta controle de logout sem reescrever regras de negócio/JS originais.
    content = content.replace('</header>', logout + '</header>', 1)
    return HTMLResponse(content)

@app.post('/logout')
def logout(request: Request, csrf: str = Form(...)):
    # A sessão e o token CSRF da sessão são obrigatórios.
    # Não depender do cabeçalho Origin, que pode variar atrás do proxy.
    user = current_user(request)
    if not user or not secrets.compare_digest(user[3], csrf):
        return Response(status_code=403)
    token = request.cookies.get(COOKIE)
    with connect() as conn, conn.cursor() as cur:
        cur.execute('DELETE FROM sessions WHERE token_hash=%s', (hash_token(token),))
    response = RedirectResponse('/login', status_code=303)
    response.delete_cookie(COOKIE, path='/')
    return response

@app.get('/admin')
def admin(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse('/login', status_code=303)
    if not user[2]:
        return Response(status_code=403)
    with connect() as conn, conn.cursor() as cur:
        cur.execute('SELECT id,username,is_admin,is_active FROM users ORDER BY id')
        rows = cur.fetchall()
    list_rows = ''.join(f'''<tr><td style="padding:8px">{safe_html(r[1])}</td><td>{'Administrador' if r[2] else 'Vendedor'}</td>
<td>{'Ativo' if r[3] else 'Bloqueado'}</td><td><form method="post" action="/admin/toggle" style="margin:0"><input type="hidden" name="csrf" value="{safe_html(user[3])}"><input type="hidden" name="user_id" value="{r[0]}"><button type="submit">{'Bloquear' if r[3] else 'Ativar'}</button></form></td></tr>''' for r in rows)
    body = f'''<h1>Gerenciar usuários</h1><a href="/">Voltar ao simulador</a><h2>Novo usuário</h2>
<form method="post" action="/admin/create" autocomplete="off"><input type="hidden" name="csrf" value="{safe_html(user[3])}"><label>Usuário</label><input required name="username" autocomplete="off" minlength="3" maxlength="64" pattern="[a-zA-Z0-9_.-]+"><label>Senha inicial (mínimo 12 caracteres)</label><input required type="password" name="password" autocomplete="new-password" minlength="12"><button>Cadastrar vendedor</button></form>
<h2>Usuários existentes</h2><table style="width:100%;font-size:13px"><thead><tr><th>Usuário</th><th>Perfil</th><th>Status</th><th>Ação</th></tr></thead><tbody>{list_rows}</tbody></table>
<p class="muted">O bloqueio revoga as sessões existentes. Para redefinir uma senha, use o comando administrativo do servidor.</p>'''
    return HTMLResponse(page('Gerenciar usuários', body))

def require_admin_and_csrf(request, csrf):
    # Exige sessão de administrador e CSRF vinculado à sessão.
    user = current_user(request)
    if not user or not user[2] or not secrets.compare_digest(user[3], csrf):
        return None
    return user

@app.post('/admin/create')
def admin_create(request: Request, csrf: str = Form(...), username: str = Form(...), password: str = Form(...)):
    if not require_admin_and_csrf(request, csrf):
        return Response(status_code=403)
    import re
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,64}', username) or len(password) < 12:
        return HTMLResponse(page('Erro', '<p>Usuário inválido ou senha curta.</p><a href="/admin">Voltar</a>'), status_code=400)
    with connect() as conn, conn.cursor() as cur:
        cur.execute('SELECT 1 FROM users WHERE username=%s', (username,))
        if cur.fetchone():
            return HTMLResponse(page('Erro', '<p>Esse usuário já existe.</p><a href="/admin">Voltar</a>'), status_code=409)
        cur.execute('INSERT INTO users(username,password_hash) VALUES(%s,%s)', (username, ph.hash(password)))
    return RedirectResponse('/admin', status_code=303)

@app.post('/admin/toggle')
def admin_toggle(request: Request, csrf: str = Form(...), user_id: int = Form(...)):
    admin_user = require_admin_and_csrf(request, csrf)
    if not admin_user:
        return Response(status_code=403)
    if user_id == admin_user[0]:
        return HTMLResponse(page('Erro', '<p>Não é possível bloquear sua própria conta.</p><a href="/admin">Voltar</a>'), status_code=400)
    with connect() as conn, conn.cursor() as cur:
        cur.execute('UPDATE users SET is_active=NOT is_active, session_version=session_version+1 WHERE id=%s RETURNING id', (user_id,))
        if not cur.fetchone():
            return Response(status_code=404)
        cur.execute('DELETE FROM sessions WHERE user_id=%s', (user_id,))
    return RedirectResponse('/admin', status_code=303)