import os
import bcrypt
from datetime import timedelta, datetime
from flask import (
    Flask, render_template, redirect, url_for, request, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin, LoginManager, login_user,
    logout_user, current_user, login_required
)
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from random import randint 

# ==========================================================
# CONFIGURAÇÃO DO APP E BANCO
# ==========================================================
app = Flask(__name__)
# Chave secreta obrigatória para segurança de sessões e flashes
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave_super_segura_brain_2025') 

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'brain.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=5) 

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'loginentrar'
login_manager.login_message = 'Faça login para continuar.'
login_manager.login_message_category = 'info' 

BCRYPT_ROUNDS = 12


# ==========================================================
# MODELOS (ADICIONADO CAMPO 'turma')
# ==========================================================
class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuario'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    turma = db.Column(db.String(50), nullable=True) 
    dias_seguidos = db.Column(db.Integer, default=1)
    minutos_relaxados = db.Column(db.Integer, default=0)

    mensagens = db.relationship('Mensagem', backref='remetente', lazy=True)
    
    def get_id(self):
        return str(self.id_usuario)

    def set_senha(self, senha):
        self.senha_hash = bcrypt.hashpw(
            senha.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        ).decode('utf-8')

    def verificar_senha(self, senha):
        if not self.senha_hash: 
            return False
        try:
            return bcrypt.checkpw(senha.encode('utf-8'), self.senha_hash.encode('utf-8'))
        except ValueError:
            return False

class Conversa(db.Model):
    __tablename__ = 'conversa'
    id_conversa = db.Column(db.Integer, primary_key=True)
    usuario1_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    usuario2_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    ultima_atualizacao = db.Column(db.DateTime, default=datetime.utcnow)

    usuario1 = db.relationship('Usuario', foreign_keys=[usuario1_id])
    usuario2 = db.relationship('Usuario', foreign_keys=[usuario2_id])
    mensagens = db.relationship('Mensagem', backref='conversa', lazy='dynamic')


class Mensagem(db.Model):
    __tablename__ = 'mensagem'
    id_mensagem = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.Text, nullable=False)
    data_envio = db.Column(db.DateTime, default=datetime.utcnow)
    
    conversa_id = db.Column(db.Integer, db.ForeignKey('conversa.id_conversa'), nullable=False)
    remetente_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    # Usando db.session.get (mais moderno e seguro que query.get)
    return db.session.get(Usuario, int(user_id)) 

# ==========================================================
# ROTAS PRINCIPAIS E DE NAVEGAÇÃO
# ==========================================================

@app.route('/')
def inicio():
    if not current_user.is_authenticated:
        # Assumindo que você tem um template index.html para o estado deslogado
        return render_template('index.html', current_user=current_user, title="Bem-vindo")
    
    dados_dinamicos = {
        'dias_seguidos': current_user.dias_seguidos, 
        'dia_atual_na_semana': randint(1, 7), 
        'dias_proxima_prova': randint(1, 30), 
        'minutos_relaxados_semana': current_user.minutos_relaxados
    }
    # Assumindo que você tem um template index.html para o estado logado
    return render_template('index.html', dados_dinamicos=dados_dinamicos, current_user=current_user, title="Brain Boost")

# ... (Rotas de registro, login, logout e perfil omitidas por serem longas e não relacionadas ao erro) ...

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
    nome = request.form.get('nome')
    email = request.form.get('email')
    senha = request.form.get('senha')
    
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
        flash('Ocorreu um erro ao tentar registrar o usuário.', 'danger')
        print(f"Erro no registro: {e}")
        return redirect(url_for('registroentrar'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    senha = request.form.get('senha')
    remember_me = request.form.get('remember_me')
    
    usuario = Usuario.query.filter_by(email=email).first()

    if usuario and usuario.verificar_senha(senha):
        login_user(usuario, remember=bool(remember_me)) 
        flash(f'Login bem-sucedido. Olá, {usuario.nome}!', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('inicio'))
    else:
        flash('E-mail ou senha inválidos.', 'danger')
        return redirect(url_for('loginentrar'))

@app.route('/logout')
@login_required 
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('inicio'))

@app.route('/perfil')
@login_required 
def perfil():
    return render_template('editar_perfil.html', usuario=current_user, title="Meu Perfil")


@app.route('/perfil/editar', methods=['POST'])
@login_required
def editar_usuario():
    novo_nome = request.form.get('nome')
    novo_email = request.form.get('email')
    nova_turma = request.form.get('turma')
    senha_atual = request.form.get('senha_atual')
    nova_senha = request.form.get('nova_senha')
    confirmar_senha = request.form.get('confirmar_senha')
    
    if not novo_nome or not novo_email:
        flash('Nome e E-mail são obrigatórios.', 'warning')
        return redirect(url_for('perfil'))
    
    if not senha_atual or not current_user.verificar_senha(senha_atual):
        flash('Senha atual incorreta. Nenhuma alteração foi salva.', 'danger')
        return redirect(url_for('perfil'))

    email_existente = Usuario.query.filter(
        Usuario.email == novo_email, Usuario.id_usuario != current_user.id_usuario
    ).first()
    
    if email_existente:
        flash('Este e-mail já está sendo usado por outra conta.', 'warning')
        return redirect(url_for('perfil')) 
        
    if nova_senha or confirmar_senha:
        if nova_senha != confirmar_senha:
            flash('A nova senha e a confirmação não coincidem.', 'danger')
            return redirect(url_for('perfil'))
        if len(nova_senha) < 6:
            flash('A nova senha deve ter pelo menos 6 caracteres.', 'warning')
            return redirect(url_for('perfil'))
        
        current_user.set_senha(nova_senha)
        flash('Senha atualizada com sucesso!', 'success')
        
    current_user.nome = novo_nome
    current_user.email = novo_email
    current_user.turma = nova_turma
    
    try:
        db.session.commit()
        if not nova_senha:
            flash('Perfil (Nome/Email/Turma) atualizado com sucesso!', 'success')
    except Exception:
        db.session.rollback()
        flash('Ocorreu um erro ao tentar salvar as alterações.', 'danger')
        
    return redirect(url_for('perfil'))

# ==========================================================
# ROTAS AUXILIARES E CHAT
# ==========================================================

@app.route('/quizboost')
@login_required
def quizboost():
    flash('Tela de Jogos (QuizBoost) em construção!', 'info')
    return render_template("link8.html")

@app.route('/calendario')
@login_required
def calendario():
    flash('Agenda e Calendário em construção!', 'info')
    return render_template("calendario.html")

@app.route('/relaxar')
@login_required
def relaxar():
    current_user.minutos_relaxados += 5 
    db.session.commit()
    flash('Parabéns! Você relaxou por 5 minutos!', 'success')
    return render_template("link6.html")

# --- ROTAS DE CHAT ---

@app.route('/chattodos')
@login_required
def chattodos():
    termo_busca = request.args.get('busca')
    
    # 1. Obter conversas existentes
    conversas_query = Conversa.query.filter(
        or_(
            Conversa.usuario1_id == current_user.id_usuario,
            Conversa.usuario2_id == current_user.id_usuario
        )
    ).order_by(Conversa.ultima_atualizacao.desc()).all()
    
    conversas_formatadas = []
    for conversa in conversas_query:
        if conversa.usuario1_id == current_user.id_usuario:
            contato = conversa.usuario2
        else:
            contato = conversa.usuario1
            
        conversas_formatadas.append((contato, conversa.ultima_atualizacao))
    
    # 2. Lógica de busca de USUÁRIOS
    usuarios_encontrados = []
    if termo_busca:
        usuarios_encontrados = Usuario.query.filter(
            Usuario.id_usuario != current_user.id_usuario,
            or_(
                Usuario.nome.ilike(f'%{termo_busca}%'),
                Usuario.email.ilike(f'%{termo_busca}%')
            )
        ).all()

    # Renderiza 'chatsearch.html' (Seu template da lista de chats)
    return render_template('chatsearch.html', 
                           conversas=conversas_formatadas, 
                           usuarios_encontrados=usuarios_encontrados, 
                           termo_busca=termo_busca,
                           title="Mensagens")

@app.route('/chat/criar/<int:receptor_id>')
@login_required
def criar_chat(receptor_id):
    if receptor_id == current_user.id_usuario:
        flash('Você não pode iniciar um chat consigo mesmo.', 'danger')
        return redirect(url_for('chattodos'))

    # Usando db.session.get (mais moderno e recomendado)
    receptor = db.session.get(Usuario, receptor_id)
    if not receptor:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('chattodos'))
    
    ids = sorted([current_user.id_usuario, receptor_id])

    conversa = Conversa.query.filter(
        Conversa.usuario1_id == ids[0],
        Conversa.usuario2_id == ids[1]
    ).first()
    
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

    if current_user.id_usuario not in [conversa.usuario1_id, conversa.usuario2_id]:
        flash('Acesso negado a esta conversa.', 'danger')
        return redirect(url_for('chattodos'))

    # Variável correta usada no template (outro_usuario)
    outro_usuario = conversa.usuario2 if conversa.usuario1_id == current_user.id_usuario else conversa.usuario1
    
    if request.method == 'POST':
        texto = request.form.get('mensagem')
        if texto and texto.strip():
            nova_mensagem = Mensagem(
                texto=texto.strip(),
                conversa_id=conversa_id,
                remetente_id=current_user.id_usuario
            )
            conversa.ultima_atualizacao = datetime.utcnow()
            
            db.session.add(nova_mensagem)
            db.session.commit()
            
            return redirect(url_for('chat_conversa', conversa_id=conversa_id))
        else:
            flash('A mensagem não pode estar vazia.', 'warning')
            
    mensagens = conversa.mensagens.order_by(Mensagem.data_envio.asc()).all()

    # IMPORTANTE: A variável passada é 'outro_usuario'
    return render_template('chat.html', 
                           conversa=conversa, 
                           mensagens=mensagens, 
                           outro_usuario=outro_usuario, # Variável correta
                           title=f"Chat com {outro_usuario.nome}")

# ==========================================================
# EXECUÇÃO
# ==========================================================
if __name__ == '__main__':
    with app.app_context():
        # Cria as tabelas do DB (garanta que o arquivo brain.db não exista se o modelo foi alterado)
        db.create_all() 
    app.run(debug=True)