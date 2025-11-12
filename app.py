# app.py
import os
import logging
import bcrypt
from datetime import timedelta, datetime
from urllib.parse import urlparse, urljoin

from flask import (
    Flask, render_template, redirect, url_for, request, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin, LoginManager, login_user, logout_user,
    current_user, login_required
)
from sqlalchemy import or_, and_, func
from sqlalchemy.exc import IntegrityError

# =========================================
# APP & CONFIG
# =========================================
app = Flask(__name__)

# Segurança e Sessão
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave_super_segura_brain_2025')

# Banco de Dados
basedir = os.path.abspath(os.path.dirname(__file__))
db_url = os.environ.get('DATABASE_URL')
# compatibilidade antiga do Heroku
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or ('sqlite:///' + os.path.join(basedir, 'brain.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cookies / Sessão
# Em dev (sem HTTPS), você pode setar APP_SECURE_COOKIES=0 pra não quebrar cookie SameSite=None
_secure_cookies_env = os.environ.get('APP_SECURE_COOKIES', '1').strip()
SECURE_COOKIES = _secure_cookies_env not in ('0', 'false', 'False', 'no', 'NO')

app.config.update(
    SESSION_COOKIE_NAME='brain_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None' if SECURE_COOKIES else 'Lax',
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),

    # Flask-Login "lembrar-me"
    REMEMBER_COOKIE_DURATION=timedelta(days=30),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='None' if SECURE_COOKIES else 'Lax',
    REMEMBER_COOKIE_SECURE=SECURE_COOKIES,
)

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'loginentrar'
login_manager.login_message = 'Faça login para continuar.'
login_manager.login_message_category = 'info'

# Logging básico
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)
log = logging.getLogger(__name__)

BCRYPT_ROUNDS = 12


# =========================================
# MODELOS
# =========================================
class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuario'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    senha_hash = db.Column(db.String(200), nullable=False)
    turma = db.Column(db.String(50))
    dias_seguidos = db.Column(db.Integer, default=1)
    minutos_relaxados = db.Column(db.Integer, default=0)

    def get_id(self):
        return str(self.id_usuario)

    def set_senha(self, senha: str):
        self.senha_hash = bcrypt.hashpw(
            senha.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        ).decode('utf-8')

    def verificar_senha(self, senha: str) -> bool:
        if not self.senha_hash:
            return False
        try:
            return bcrypt.checkpw(senha.encode('utf-8'), self.senha_hash.encode('utf-8'))
        except ValueError:
            return False


class Conversa(db.Model):
    __tablename__ = 'conversa'
    id_conversa = db.Column(db.Integer, primary_key=True)
    usuario1_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False, index=True)
    usuario2_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False, index=True)
    ultima_atualizacao = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class Mensagem(db.Model):
    __tablename__ = 'mensagem'
    id_mensagem = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.Text, nullable=False)
    data_envio = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    conversa_id = db.Column(db.Integer, db.ForeignKey('conversa.id_conversa'), nullable=False, index=True)
    remetente_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False, index=True)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))


# =========================================
# HELPERS
# =========================================
def conversa_to_viewtuple(conversa: Conversa):
    """Retorna tupla (contato_dict, ultima_atualizacao) sem lazy-load."""
    meu_id = getattr(current_user, 'id_usuario', None)
    if meu_id is None:
        # não logado; fallback defensivo
        return ({"id_usuario": 0, "nome": "[usuário]", "turma": None, "email": ""}, conversa.ultima_atualizacao)

    outro_id = conversa.usuario2_id if conversa.usuario1_id == meu_id else conversa.usuario1_id
    contato = db.session.get(Usuario, outro_id)
    if not contato:
        return ({"id_usuario": 0, "nome": "[usuário removido]", "turma": None, "email": ""}, conversa.ultima_atualizacao)

    return (
        {
            "id_usuario": contato.id_usuario,
            "nome": contato.nome,
            "turma": contato.turma,
            "email": contato.email
        },
        conversa.ultima_atualizacao
    )


def mensagem_to_viewdict(msg: Mensagem):
    return {
        "id_mensagem": msg.id_mensagem,
        "texto": msg.texto,
        "data_envio": msg.data_envio,
        "remetente_id": msg.remetente_id
    }


def is_safe_url(target):
    # Evita open redirect no parâmetro "next"
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in ('http', 'https') and host_url.netloc == redirect_url.netloc


# =========================================
# ROTAS
# =========================================
@app.route('/')
def inicio():
    if not current_user.is_authenticated:
        return render_template('index.html', current_user=current_user, title="Bem-vindo")

    dados_dinamicos = {
        'dias_seguidos': current_user.dias_seguidos or 0,
        'dia_atual_na_semana': datetime.utcnow().isoweekday() % 7 + 1,  # 1..7
        'dias_proxima_prova': 7,  # placeholder
        'minutos_relaxados_semana': current_user.minutos_relaxados or 0
    }
    return render_template('index.html', dados_dinamicos=dados_dinamicos, current_user=current_user, title="Brain Boost")


# ---------- Auth ----------
@app.route('/registroentrar')
def registroentrar():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    return render_template('registro1.html', title="Criar Conta")


@app.route('/loginentrar')
def loginentrar():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    return render_template('login1.html', title="Fazer Login")


@app.route('/registro', methods=['POST'])
def registro():
    nome = (request.form.get('nome') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    senha = request.form.get('senha') or ''

    if not nome or not email or not senha:
        flash('Por favor, preencha todos os campos.', 'warning')
        return redirect(url_for('registroentrar'))
    if len(senha) < 6:
        flash('A senha deve ter pelo menos 6 caracteres.', 'warning')
        return redirect(url_for('registroentrar'))

    novo = Usuario(nome=nome, email=email)
    novo.set_senha(senha)

    try:
        db.session.add(novo)
        db.session.commit()
        login_user(novo, remember=True)
        flash(f'Bem-vindo(a), {novo.nome}!', 'success')
        return redirect(url_for('inicio'))
    except IntegrityError:
        db.session.rollback()
        flash('Esse email já está cadastrado!', 'warning')
        return redirect(url_for('registroentrar'))
    except Exception as e:
        db.session.rollback()
        log.exception("[REGISTRO] erro inesperado")
        flash('Erro ao registrar. Tente novamente.', 'danger')
        return redirect(url_for('registroentrar'))


@app.route('/login', methods=['POST'])
def login():
    email = (request.form.get('email') or "").strip().lower()
    senha = request.form.get('senha') or ""
    remember_me = bool(request.form.get('remember_me'))

    usuario = Usuario.query.filter_by(email=email).first()
    if usuario and usuario.verificar_senha(senha):
        login_user(usuario, remember=remember_me)
        flash(f'Olá, {usuario.nome}!', 'success')
        next_page = request.args.get('next')
        if next_page and is_safe_url(next_page):
            return redirect(next_page)
        return redirect(url_for('inicio'))

    flash('E-mail ou senha inválidos.', 'danger')
    return redirect(url_for('loginentrar'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('inicio'))


# ---------- Perfil ----------
@app.route('/perfil')
@login_required
def perfil():
    return render_template('editar_perfil.html', usuario=current_user, title="Meu Perfil")


@app.route('/perfil/editar', methods=['POST'])
@login_required
def editar_usuario():
    novo_nome = (request.form.get('nome') or "").strip()
    novo_email = (request.form.get('email') or "").strip().lower()
    nova_turma = (request.form.get('turma') or "").strip()
    senha_atual = request.form.get('senha_atual') or ""
    nova_senha = request.form.get('nova_senha') or ""
    confirmar_senha = request.form.get('confirmar_senha') or ""

    if not novo_nome or not novo_email:
        flash('Nome e E-mail são obrigatórios.', 'warning')
        return redirect(url_for('perfil'))

    if not current_user.verificar_senha(senha_atual):
        flash('Senha atual incorreta.', 'danger')
        return redirect(url_for('perfil'))

    email_existente = Usuario.query.filter(
        and_(Usuario.email == novo_email, Usuario.id_usuario != current_user.id_usuario)
    ).first()
    if email_existente:
        flash('Este e-mail já está em uso.', 'warning')
        return redirect(url_for('perfil'))

    if nova_senha or confirmar_senha:
        if nova_senha != confirmar_senha:
            flash('A nova senha e a confirmação não coincidem.', 'danger')
            return redirect(url_for('perfil'))
        if len(nova_senha) < 6:
            flash('A nova senha deve ter pelo menos 6 caracteres.', 'warning')
            return redirect(url_for('perfil'))
        current_user.set_senha(nova_senha)
        flash('Senha atualizada!', 'success')

    current_user.nome = novo_nome
    current_user.email = novo_email
    current_user.turma = nova_turma or None

    try:
        db.session.commit()
        if not nova_senha:
            flash('Perfil atualizado!', 'success')
    except Exception:
        db.session.rollback()
        log.exception("[PERFIL] erro ao salvar alterações")
        flash('Erro ao salvar alterações.', 'danger')

    return redirect(url_for('perfil'))


# ---------- Outras telas ----------
@app.route('/quizboost')
@login_required
def quizboost():
    flash('Tela de Jogos em construção!', 'info')
    return render_template("link8.html", title="Jogos")


@app.route('/calendario')
@login_required
def calendario():
    flash('Agenda e Calendário em construção!', 'info')
    return render_template("calendario.html", title="Agenda")


@app.route('/relaxar')
@login_required
def relaxar():
    try:
        current_user.minutos_relaxados = (current_user.minutos_relaxados or 0) + 5
        db.session.commit()
        flash('Parabéns! Você relaxou por 5 minutos!', 'success')
    except Exception:
        db.session.rollback()
        log.exception("[RELAXAR] erro ao registrar relaxamento")
        flash('Não consegui registrar seu relaxamento agora.', 'warning')
    return render_template("link6.html", title="Relaxar")


# ---------- Chat ----------
@app.route('/chattodos')
@login_required
def chattodos():
    termo_busca = (request.args.get('busca') or "").strip()
    termo_normalizado = termo_busca.lower()

    # Conversas do usuário
    conversas = (Conversa.query
                 .filter(or_(
                     Conversa.usuario1_id == current_user.id_usuario,
                     Conversa.usuario2_id == current_user.id_usuario
                 ))
                 .order_by(Conversa.ultima_atualizacao.desc())
                 .all())

    conversas_formatadas = [conversa_to_viewtuple(c) for c in conversas]

    usuarios_busca = []
    if termo_busca:
        # Compatível com SQLite e Postgres: normaliza ambos lados com lower()
        usuarios_encontrados = (Usuario.query
            .filter(
                and_(
                    Usuario.id_usuario != current_user.id_usuario,
                    or_(
                        func.lower(Usuario.nome).like(f"%{termo_normalizado}%"),
                        func.lower(Usuario.email).like(f"%{termo_normalizado}%")
                    )
                )
            )
            .order_by(Usuario.nome.asc())
            .all()
        )
        usuarios_busca = [{
            "id_usuario": u.id_usuario,
            "nome": u.nome,
            "email": u.email
        } for u in usuarios_encontrados]

    return render_template(
        'chatsearch.html',
        conversas=conversas_formatadas,
        usuarios_busca=usuarios_busca,
        termo_busca=termo_busca,
        title="Mensagens"
    )


@app.route('/chat/criar/<int:receptor_id>')
@login_required
def criar_chat(receptor_id):
    if receptor_id == current_user.id_usuario:
        flash('Você não pode iniciar um chat consigo mesmo.', 'danger')
        return redirect(url_for('chattodos'))

    receptor = db.session.get(Usuario, receptor_id)
    if not receptor:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('chattodos'))

    ids = sorted([current_user.id_usuario, receptor_id])

    conversa = (Conversa.query
                .filter(and_(Conversa.usuario1_id == ids[0],
                             Conversa.usuario2_id == ids[1]))
                .first())

    if not conversa:
        conversa = Conversa(usuario1_id=ids[0], usuario2_id=ids[1])
        db.session.add(conversa)
        db.session.commit()

    return redirect(url_for('chat_conversa', conversa_id=conversa.id_conversa))


@app.route('/chat/<int:conversa_id>', methods=['GET', 'POST'])
@login_required
def chat_conversa(conversa_id):
    conversa = db.session.get(Conversa, conversa_id)
    if not conversa:
        flash('Conversa não encontrada.', 'danger')
        return redirect(url_for('chattodos'))

    if current_user.id_usuario not in (conversa.usuario1_id, conversa.usuario2_id):
        flash('Acesso negado a esta conversa.', 'danger')
        return redirect(url_for('chattodos'))

    # Outro usuário (como dict)
    outro_id = conversa.usuario2_id if conversa.usuario1_id == current_user.id_usuario else conversa.usuario1_id
    outro = db.session.get(Usuario, outro_id)
    outro_usuario = {
        "id_usuario": outro.id_usuario if outro else 0,
        "nome": outro.nome if outro else "[usuário removido]",
        "email": outro.email if outro else ""
    }

    if request.method == 'POST':
        texto = (request.form.get('mensagem') or "").strip()
        if texto:
            nova = Mensagem(texto=texto, conversa_id=conversa_id, remetente_id=current_user.id_usuario)
            conversa.ultima_atualizacao = datetime.utcnow()
            try:
                db.session.add(nova)
                db.session.commit()
                return redirect(url_for('chat_conversa', conversa_id=conversa_id))
            except Exception:
                db.session.rollback()
                log.exception("[CHAT POST] erro ao enviar mensagem")
                flash('Não foi possível enviar a mensagem agora.', 'warning')
        else:
            flash('A mensagem não pode estar vazia.', 'warning')

    msgs = (Mensagem.query
            .filter_by(conversa_id=conversa_id)
            .order_by(Mensagem.data_envio.asc())
            .all())
    mensagens = [mensagem_to_viewdict(m) for m in msgs]

    return render_template(
        'chat.html',
        conversa_id=conversa_id,
        mensagens=mensagens,
        outro_usuario=outro_usuario,
        current_user=current_user,
        title=f"Chat com {outro_usuario['nome']}"
    )


# =========================================
# MAIN
# =========================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Em produção, use um servidor WSGI (gunicorn/uwsgi). Debug somente em dev.
    app.run(debug=True)
