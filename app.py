import os
import bcrypt 
import random
from datetime import date, time, timedelta, datetime
from flask import (
    Flask, render_template, redirect, url_for, request, flash, session, 
    Blueprint 
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
from sqlalchemy import func 
# Removi as imports de werkzeug.security, pois agora estamos usando bcrypt diretamente.

# ==========================================================
# ⚙️ CONFIGURAÇÃO DO FLASK, BANCO DE DADOS E LOGIN
# ==========================================================

app = Flask(__name__)

# Configuração de Segurança e Banco de Dados
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', 'chave_super_segura_brain_2025'
)
# Usando o caminho absoluto do arquivo db para melhor compatibilidade
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'brain.db')
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração da Sessão (Pode precisar de limpeza se for o problema)
app.config['SESSION_TYPE'] = 'filesystem' 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=5)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'loginentrar' 
login_manager.login_message_category = 'info'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'

# Inicializador do bcrypt
BCRYPT_ROUNDS = 12 

@login_manager.user_loader
def load_user(user_id):
    """Carrega o usuário dado o ID da sessão."""
    return Usuario.query.get(int(user_id))

# ==========================================================
# 📦 MODELOS DO BANCO DE DADOS 
# ==========================================================

class Usuario(db.Model, UserMixin): 
    __tablename__ = 'usuario'
    id_usuario = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    nome = db.Column(db.String(250), nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    # Coluna adicionada que causou o erro:
    turma = db.Column(db.String(100), nullable=True) 
    sessoes = db.relationship('SessaoEstudos', backref='usuario', cascade="all, delete-orphan")

    def get_id(self): return str(self.id_usuario)
    
    def set_senha(self, senha): 
        self.senha_hash = bcrypt.hashpw(
            senha.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        ).decode('utf-8')
        
    def verificar_senha(self, senha): 
        # Garante que senha_hash não é None antes de tentar decodificar
        if not self.senha_hash: return False
        return bcrypt.checkpw(senha.encode('utf-8'), self.senha_hash.encode('utf-8'))
        
    def __repr__(self): return f'<Usuário {self.nome}>'

class SessaoEstudos(db.Model):
    __tablename__ = 'sessao_estudos'
    id_sessao = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    tempo_total = db.Column(db.Time, nullable=False) 
    data_inicio = db.Column(db.Date, nullable=False)
    data_fim = db.Column(db.Date, nullable=False)
    quizzes = db.relationship('Quiz', backref='sessao', cascade="all, delete-orphan")
    vestibulares = db.relationship('Vestibular', backref='sessao', cascade="all, delete-orphan")
    meditacoes = db.relationship('Meditacao', backref='sessao', cascade="all, delete-orphan")
    materiais = db.relationship('MaterialDidatico', backref='sessao', cascade="all, delete-orphan")
    def __repr__(self): return f'<Sessão {self.id_sessao} - Usuário {self.id_usuario}>'

class Quiz(db.Model):
    __tablename__ = 'quiz'
    id_quiz = db.Column(db.Integer, primary_key=True)
    id_sessao = db.Column(db.Integer, db.ForeignKey('sessao_estudos.id_sessao'), nullable=False)
    perguntas = db.Column(db.String(250), nullable=False)
    respostas = db.Column(db.String(250), nullable=False)

class MateriaQuiz(db.Model):
    __tablename__ = 'materia_quiz'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    def __repr__(self): return f'<Materia {self.nome}>'

class PerguntaQuiz(db.Model):
    __tablename__ = 'pergunta_quiz'
    id = db.Column(db.Integer, primary_key=True)
    id_materia = db.Column(db.Integer, db.ForeignKey('materia_quiz.id'), nullable=False)
    texto_pergunta = db.Column(db.Text, nullable=False)
    opcao_a = db.Column(db.Text, nullable=False)
    opcao_b = db.Column(db.Text, nullable=False)
    opcao_c = db.Column(db.Text, nullable=False)
    opcao_d = db.Column(db.Text, nullable=False)
    resposta_correta = db.Column(db.String(1), nullable=False) 
    materia = db.relationship('MateriaQuiz', backref=db.backref('perguntas_quiz', lazy=True))
    def __repr__(self): return f'<Pergunta {self.id} de {self.materia.nome}>'

class Vestibular(db.Model):
    __tablename__ = 'vestibular'
    id_vestibular = db.Column(db.Integer, primary_key=True)
    id_sessao = db.Column(db.Integer, db.ForeignKey('sessao_estudos.id_sessao'), nullable=False)
    nome = db.Column(db.String(250), nullable=False)
    ano = db.Column(db.Integer, nullable=False)
    instituicao = db.Column(db.String(250), nullable=False)
    materia = db.Column(db.String(250), nullable=False)
    descricao = db.Column(db.String(250), nullable=False)
    questoes = db.Column(db.Integer, nullable=False)
    respostas = db.Column(db.Integer, nullable=False)

class Meditacao(db.Model):
    __tablename__ = 'meditacao'
    id_meditacao = db.Column(db.Integer, primary_key=True)
    id_sessao = db.Column(db.Integer, db.ForeignKey('sessao_estudos.id_sessao'), nullable=False)
    caminho_arquivo = db.Column(db.String(255), nullable=False)
    duracao = db.Column(db.Time, nullable=False) 
    descricao = db.Column(db.String(250), nullable=False)
    titulo = db.Column(db.String(250), nullable=False)

class MaterialDidatico(db.Model):
    __tablename__ = 'material_didatico'
    id_material = db.Column(db.Integer, primary_key=True)
    id_sessao = db.Column(db.Integer, db.ForeignKey('sessao_estudos.id_sessao'), nullable=False)
    materia = db.Column(db.String(250), nullable=False)
    formato = db.Column(db.String(20), nullable=False)
    anotacoes = db.relationship('Anotacao', backref='material', cascade="all, delete-orphan")

class Anotacao(db.Model):
    __tablename__ = 'anotacoes'
    id_anotacoes = db.Column(db.Integer, primary_key=True)
    id_material = db.Column(db.Integer, db.ForeignKey('material_didatico.id_material'))
    titulo = db.Column(db.String(50))
    sumario = db.Column(db.String(250))
    anotacoes = db.Column(db.String(500))

# ==========================================================
# 🏠 ROTAS PRINCIPAIS (Dashboard e Auth)
# ==========================================================

@app.route('/')
def inicio():
    """Rota principal/Dashboard."""
    
    if not current_user.is_authenticated:
        return render_template('inicio.html', title='Brain Boost')

    # --- SIMULAÇÃO DE DADOS DINÂMICOS ---
    
    # 1. Streak (dias seguidos) - Lógica de exemplo
    dias_seguidos_simulados = 5 
    dia_atual_na_semana = datetime.now().weekday() + 1 # 1 (Seg) a 7 (Dom)
    
    # 2. Próxima Prova (Vestibular) - Lógica de exemplo
    proxima_prova = Vestibular.query.filter(
        Vestibular.id_sessao.in_(
            db.session.query(SessaoEstudos.id_sessao).filter(SessaoEstudos.id_usuario == current_user.id_usuario)
        )
    ).order_by(Vestibular.id_vestibular.desc()).first() 

    dias_proxima_prova = 20 # Mockado
    # if proxima_prova: lógica de cálculo de data aqui

    
    # 3. CÁLCULO DE MINUTOS DE RELAXAMENTO (Tratamento para SQLite TIME)
    semana_passada = date.today() - timedelta(days=7)
    
    relax_durations = db.session.query(
        Meditacao.duracao
    ).join(SessaoEstudos).filter(
        SessaoEstudos.id_usuario == current_user.id_usuario,
        SessaoEstudos.data_fim >= semana_passada
    ).all()
    
    total_seconds = 0
    for duration in relax_durations:
        duration_time = duration[0]
        if duration_time:
            if isinstance(duration_time, time):
                t = duration_time
            else: 
                try:
                    # Tenta parsing como string 'HH:MM:SS' ou 'HH:MM'
                    t_str = str(duration_time).split('.')[0] # Remove milissegundos se houver
                    if len(t_str.split(':')) == 2: t_str += ':00' # Adiciona segundos se faltar
                    t = datetime.strptime(t_str, '%H:%M:%S').time()
                except ValueError:
                    continue 

            total_seconds += t.hour * 3600 + t.minute * 60 + t.second

    minutos_relaxados_semana = int(total_seconds / 60)
    
    dados_dinamicos = {
        'dias_seguidos': dias_seguidos_simulados,
        'dia_atual_na_semana': dia_atual_na_semana,
        'mensagens_nao_lidas': 2, 
        'dias_proxima_prova': dias_proxima_prova,
        'minutos_relaxados_semana': minutos_relaxados_semana
    }
    
    return render_template('index.html', title=f'Dashboard - {current_user.nome}', dados_dinamicos=dados_dinamicos)


@app.route('/registroentrar')
def registroentrar():
    """Renderiza a página de registro."""
    if current_user.is_authenticated: return redirect(url_for('inicio')) 
    return render_template("registro1.html", title="Criar Perfil")

@app.route('/loginentrar')
def loginentrar():
    """Renderiza a página de login."""
    if current_user.is_authenticated: return redirect(url_for('inicio'))
    return render_template("login1.html", title="Login")

@app.route('/registro', methods=['POST'])
def registro():
    """Processa o cadastro de um novo usuário."""
    nome = request.form.get('nome')
    email = request.form.get('email')
    senha = request.form.get('senha')
    
    if not all([nome, email, senha]):
        flash('Todos os campos são obrigatórios.', 'danger')
        return redirect(url_for('registroentrar'))

    if Usuario.query.filter_by(email=email).first():
        flash('E-mail já cadastrado. Tente fazer login.', 'warning')
        return redirect(url_for('registroentrar'))

    novo_usuario = Usuario(nome=nome, email=email)
    novo_usuario.set_senha(senha)

    try:
        db.session.add(novo_usuario)
        db.session.commit()
        login_user(novo_usuario)
        flash('Cadastro realizado com sucesso! Bem-vindo(a)!', 'success')
        return redirect(url_for('inicio'))
    except Exception as e:
        db.session.rollback()
        # Removido o print para manter o código limpo, mas mantenha para debug se necessário
        flash('Erro interno ao registrar. Tente novamente.', 'danger')
        return redirect(url_for('registroentrar'))


@app.route('/login', methods=['POST'])
def login():
    """Processa o login do usuário."""
    email = request.form.get('email')
    senha = request.form.get('senha')

    usuario = Usuario.query.filter_by(email=email).first()

    if usuario and usuario.verificar_senha(senha):
        login_user(usuario, remember=True) 
        flash(f'Login efetuado com sucesso! Bem-vindo(a), {usuario.nome}!', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('inicio')) 
    else:
        flash('E-mail ou senha inválidos.', 'danger')
        return redirect(url_for('loginentrar'))

@app.route('/logout')
@login_required 
def logout():
    """Faz o logout do usuário."""
    logout_user()
    flash('Você foi desconectado(a).', 'success')
    return redirect(url_for('inicio'))

# ==========================================================
# 🧩 ROTAS PROTEGIDAS (CRUD Aprimorado)
# ==========================================================
@app.route("/perfil")
@login_required
def perfil():
    """Rota de atalho para edição de perfil."""
    return redirect(url_for('editar_usuario', id_usuario=current_user.id_usuario))


@app.route('/usuario/editar/<int:id_usuario>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id_usuario):
    """Edita o perfil do usuário logado."""
    if id_usuario != current_user.id_usuario:
        flash('Você não tem permissão para editar este perfil.', 'danger')
        return redirect(url_for('inicio'))
    
    usuario = Usuario.query.get_or_404(id_usuario)

    if request.method == 'POST':
        # 1. Atualizar informações básicas
        usuario.nome = request.form.get('nome', usuario.nome)
        usuario.email = request.form.get('email', usuario.email)
        usuario.turma = request.form.get('turma', usuario.turma)
        
        # 2. Lógica de atualização de SENHA
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')

        if nova_senha: 
            if not senha_atual:
                flash('Você deve informar a senha atual para alterar a senha.', 'danger')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))
                
            if not usuario.verificar_senha(senha_atual):
                flash('Senha atual incorreta.', 'danger')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))
            
            if len(nova_senha) < 6:
                flash('A nova senha deve ter no mínimo 6 caracteres.', 'danger')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))

            if nova_senha == confirmar_senha:
                usuario.set_senha(nova_senha)
                flash('Perfil e senha atualizados com sucesso!', 'success')
            else:
                 flash('A nova senha e a confirmação não coincidem.', 'danger')
                 return redirect(url_for('editar_usuario', id_usuario=id_usuario))
        else:
             flash('Perfil atualizado com sucesso!', 'success')
        
        # 3. Commit ao banco de dados
        try:
            db.session.commit()
            return redirect(url_for('inicio'))
        except Exception:
            db.session.rollback()
            flash('Erro ao salvar as alterações. Tente novamente.', 'danger')

    return render_template('editar_perfil.html', usuario=usuario, title=f'Editar Perfil - {usuario.nome}')


@app.route('/usuario/deletar/<int:id_usuario>', methods=['POST'])
@login_required
def deletar_usuario(id_usuario):
    """Deleta o perfil do usuário logado."""
    if id_usuario != current_user.id_usuario:
        flash('Você não tem permissão para deletar este perfil.', 'danger')
        return redirect(url_for('inicio'))
    
    usuario = Usuario.query.get_or_404(id_usuario)
    nome = usuario.nome
    try:
        logout_user()
        db.session.delete(usuario)
        db.session.commit()
        flash(f'Usuário "{nome}" deletado. Sentiremos sua falta!', 'warning')
    except Exception:
        db.session.rollback()
        flash('Erro ao deletar o perfil.', 'danger')
    return redirect(url_for('inicio'))


@app.route('/sessao/adicionar/<int:id_usuario>', methods=['GET', 'POST'])
@login_required
def adicionar_sessao(id_usuario):
    """Adiciona uma nova sessão de estudos."""
    if id_usuario != current_user.id_usuario:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('inicio'))
    
    usuario = Usuario.query.get_or_404(id_usuario)
    if request.method == 'POST':
        try:
            tempo_total_str = request.form.get('tempo_total', '00:00:00')
            if len(tempo_total_str) < 8: tempo_total_str += ':00' 
            tempo_total = time.fromisoformat(tempo_total_str)
            data_inicio = date.fromisoformat(request.form['data_inicio'])
            data_fim = date.fromisoformat(request.form['data_fim'])

            nova = SessaoEstudos(
                id_usuario=id_usuario, tempo_total=tempo_total,
                data_inicio=data_inicio, data_fim=data_fim
            )
            db.session.add(nova)
            db.session.commit()
            flash('Sessão adicionada com sucesso!', 'success')
            return redirect(url_for('inicio'))
        except ValueError:
            db.session.rollback()
            flash('Erro de formato: Verifique se as datas e o tempo estão corretos (ex: 2024-01-01 e 01:30:00).', 'danger')
        except Exception as e:
            db.session.rollback()
            # print(f"Erro ao adicionar sessão: {e}") # Para debug
            flash(f'Erro ao adicionar sessão. Tente novamente.', 'danger')
    return render_template('adicionar_sessao.html', usuario=usuario, title='Nova Sessão')

@app.route('/relaxar', methods=['GET'])
@login_required
def relaxar():
    """Rota para a funcionalidade de relaxar/meditar."""
    return render_template("link6.html", title="Relaxar e Meditar")
@app.route('/quizboost')
def quizboost():
    return render_template("link8.html")

quiz_bp = Blueprint('quiz_bp', __name__, url_prefix='/quiz')

def inicializar_sessao_quiz(materia_nome):
    """Reinicia o estado do quiz para uma nova rodada."""
    session['quiz_materia'] = materia_nome
    session['quiz_perguntas_respondidas'] = 0
    session['quiz_respostas_corretas'] = 0
    session['quiz_ultima_pergunta_id'] = None
    session['quiz_progresso'] = [] 
    session.modified = True

@quiz_bp.route('/iniciar/<materia>', methods=['GET'])
@login_required
def quiz_iniciar(materia):
    """Carrega uma pergunta aleatória para a matéria especificada."""
    materia_obj = MateriaQuiz.query.filter(
        func.lower(MateriaQuiz.nome) == func.lower(materia)
    ).first()
    
    if not materia_obj:
        flash(f'Matéria "{materia}" não encontrada.', 'danger')
        return redirect(url_for('quiz_bp.escolher_quiz')) 

    # 1. Checa e inicializa/continua o quiz
    if session.get('quiz_materia') != materia_obj.nome:
        inicializar_sessao_quiz(materia_obj.nome)
        
    if session['quiz_perguntas_respondidas'] >= 10: 
          return redirect(url_for('quiz_bp.quiz_finalizado'))

    # 2. Busca uma pergunta aleatória que não seja a última respondida
    ultima_id = session.get('quiz_ultima_pergunta_id')
    
    perguntas_disponiveis = PerguntaQuiz.query.filter(
        PerguntaQuiz.id_materia == materia_obj.id
    )

    if ultima_id:
        perguntas_disponiveis = perguntas_disponiveis.filter(
            PerguntaQuiz.id != ultima_id
        )
        
    perguntas_list = perguntas_disponiveis.all()

    if not perguntas_list:
        perguntas_list = PerguntaQuiz.query.filter(
             PerguntaQuiz.id_materia == materia_obj.id
        ).all()
        if not perguntas_list:
             flash(f'Não há perguntas cadastradas para {materia_obj.nome}.', 'warning')
             return redirect(url_for('quiz_bp.escolher_quiz')) 

    pergunta_aleatoria = random.choice(perguntas_list)
    session['quiz_ultima_pergunta_id'] = pergunta_aleatoria.id 
    session.modified = True

    # 3. Recupera o feedback da sessão e limpa
    resultado_verificacao = session.pop('resultado_verificacao', None)
    resposta_usuario_selecionada = session.pop('resposta_usuario_selecionada', None)
    
    return render_template(
        'quiz-matematica.html', 
        pergunta=pergunta_aleatoria, 
        materia=materia_obj.nome,
        resultado_verificacao=resultado_verificacao, 
        resposta_usuario=resposta_usuario_selecionada,
        progresso_atual=session['quiz_perguntas_respondidas'],
        total_perguntas=10,
        title=f'Quiz - {materia_obj.nome}'
    )

@quiz_bp.route('/verificar/<int:pergunta_id>', methods=['POST'])
@login_required
def verificar_resposta(pergunta_id):
    """Verifica a resposta do usuário, atualiza a pontuação e redireciona."""
    pergunta = PerguntaQuiz.query.get_or_404(pergunta_id)
    resposta_usuario = request.form.get('resposta')
    
    # Verifica se a pergunta já foi respondida
    if pergunta_id in [p['id'] for p in session.get('quiz_progresso', [])]:
        flash('Você já respondeu a esta pergunta. Carregando a próxima...', 'info')
        return redirect(url_for('quiz_bp.quiz_iniciar', materia=pergunta.materia.nome.lower()))

    # 1. Verifica Resposta e dá feedback
    session['resposta_usuario_selecionada'] = resposta_usuario
    
    if resposta_usuario and resposta_usuario.lower() == pergunta.resposta_correta.lower():
        session['quiz_respostas_corretas'] += 1
        feedback_status = 'correta'
        flash('✅ Resposta Correta! Mandou bem!', 'success')
    else:
        feedback_status = 'incorreta'
        # opções são apenas para visualização de feedback, mas a resposta é dada via flash
        # opcoes = {'a': pergunta.opcao_a, 'b': pergunta.opcao_b, 'c': pergunta.opcao_c, 'd': pergunta.opcao_d}
        flash(f'❌ Resposta Incorreta. A certa era {pergunta.resposta_correta.upper()}.', 'danger')

    # 2. Atualiza a sessão do Quiz
    session['quiz_perguntas_respondidas'] += 1
    session['resultado_verificacao'] = feedback_status
    
    # Armazena o progresso completo
    session['quiz_progresso'] = session.get('quiz_progresso', []) + [{
        'id': pergunta_id, 
        'resultado': feedback_status,
        'resposta_usuario': resposta_usuario,
        'resposta_correta': pergunta.resposta_correta
    }]
    session.modified = True 

    # 3. Redireciona para a rota GET que carrega uma nova pergunta para a mesma matéria
    return redirect(url_for('quiz_bp.quiz_iniciar', materia=pergunta.materia.nome.lower()))

@quiz_bp.route('/finalizado')
@login_required
def quiz_finalizado():
    """Exibe os resultados finais do quiz."""
    materia = session.get('quiz_materia', 'Quiz')
    respondidas = session.get('quiz_perguntas_respondidas', 0)
    corretas = session.get('quiz_respostas_corretas', 0)
    progresso = session.get('quiz_progresso', [])

    # Limpa a sessão do quiz
    inicializar_sessao_quiz(None)
    
    return render_template(
        'quiz_finalizado.html',
        materia=materia,
        respondidas=respondidas,
        corretas=corretas,
        progresso=progresso,
        title=f'Resultado do Quiz - {materia}'
    )

app.register_blueprint(quiz_bp)

@app.route("/calendario")
def calendario():
    return render_template("calendario.html")
    
# ==========================================================
# 🧪 FUNÇÃO DE DADOS INICIAIS
# ==========================================================

def criar_dados_exemplo():
    """Cria dados de usuário, sessões e QUIZ DINÂMICO se o banco estiver vazio."""
    # A verificação precisa estar DENTRO do app_context
    if Usuario.query.count() == 0:
        # Cria usuário
        usuario = Usuario(nome='Miguel Brain', email='miguel@brain.com', turma='3º Ano B')
        usuario.set_senha('123')
        db.session.add(usuario)
        db.session.flush()

        # Cria sessões e meditações
        sessao_recente = SessaoEstudos(
            id_usuario=usuario.id_usuario,
            tempo_total=time(hour=1, minute=45),
            data_inicio=date.today() - timedelta(days=2),
            data_fim=date.today() - timedelta(days=1)
        )
        sessao_relax_1 = SessaoEstudos(
            id_usuario=usuario.id_usuario,
            tempo_total=time(hour=0, minute=10),
            data_inicio=date.today() - timedelta(days=3),
            data_fim=date.today() - timedelta(days=3)
        )
        sessao_relax_2 = SessaoEstudos(
            id_usuario=usuario.id_usuario,
            tempo_total=time(hour=0, minute=5),
            data_inicio=date.today() - timedelta(days=8), 
            data_fim=date.today() - timedelta(days=8)
        )
        
        meditacao_1 = Meditacao(sessao=sessao_recente, caminho_arquivo='meditacao1.mp3', duracao=time(hour=0, minute=15), descricao='Meditação de foco', titulo='Foco Total')
        meditacao_2 = Meditacao(sessao=sessao_relax_1, caminho_arquivo='meditacao2.mp3', duracao=time(hour=0, minute=30), descricao='Relaxamento Profundo', titulo='Calmaria')
        meditacao_3 = Meditacao(sessao=sessao_relax_2, caminho_arquivo='meditacao3.mp3', duracao=time(hour=0, minute=59), descricao='Relaxamento Profundo', titulo='Calmaria')
        
        

        quiz = Quiz(sessao=sessao_recente, perguntas='Qual é a capital do Brasil?', respostas='Brasília')
        material = MaterialDidatico(sessao=sessao_recente, materia='História', formato='PDF')
        anot = Anotacao(material=material, titulo='Brasil Colônia', sumario='Período colonial', anotacoes='Resumo.')
        
        
        db.session.flush()

        # --- DADOS DO QUIZ DINÂMICO ---
        mat_matematica = MateriaQuiz(nome='Matemática')
        mat_historia = MateriaQuiz(nome='História')
        db.session.add_all([mat_matematica, mat_historia])
        db.session.flush()
        
        perguntas_mat = [
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Qual é o valor de X na equação $2x + 5 = 15$?', opcao_a='2', opcao_b='5', opcao_c='10', opcao_d='20', resposta_correta='b'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='O que é um número primo?', opcao_a='Número divisível apenas por 1 e por ele mesmo.', opcao_b='Qualquer número maior que 1.', opcao_c='Qualquer número ímpar.', opcao_d='Números divisíveis por 2.', resposta_correta='a'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Qual é o valor de $x$ na equação exponencial $2^x = 64$?', opcao_a='4', opcao_b='5', opcao_c='6', opcao_d='8', resposta_correta='c'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Qual é a área de um círculo com raio de $5 \\text{ cm}$?', opcao_a='$10\\pi \\text{ cm}^2$', opcao_b='$25\\pi \\text{ cm}^2$', opcao_c='$50\\pi \\text{ cm}^2$', opcao_d='$100\\pi \\text{ cm}^2$', resposta_correta='b'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Qual é a raiz (zero) da função afim $f(x) = 3x - 9$?', opcao_a='$x=1$', opcao_b='$x=3$', opcao_c='$x=-3$', opcao_d='$x=0$', resposta_correta='b'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Ao lançar um dado padrão de 6 faces, qual é a probabilidade de tirar um número par?', opcao_a='$\\frac{1}{6}$', opcao_b='$\\frac{1}{3}$', opcao_c='$\\frac{1}{2}$', opcao_d='$\\frac{2}{3}$', resposta_correta='c'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Qual é o valor de $\\sin(90^\\circ)$?', opcao_a='0', opcao_b='1', opcao_c='$\\frac{1}{2}$', opcao_d='$\\frac{\\sqrt{3}}{2}$', resposta_correta='b'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Qual é o valor de $y$ no sistema linear: $x+y=7$ e $x-y=3$?', opcao_a='$y=2$', opcao_b='$y=4$', opcao_c='$y=5$', opcao_d='$y=7$', resposta_correta='a'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Qual é o discriminante $(\\Delta)$ da equação do segundo grau $x^2 + 5x + 6 = 0$?', opcao_a='1', opcao_b='13', opcao_c='49', opcao_d='-1', resposta_correta='a'),
            PerguntaQuiz(id_materia=mat_matematica.id, texto_pergunta='Um produto custa $R\\$500,00$. Se for aplicado um desconto de $20\\%$, qual será o novo preço?', opcao_a='$R\\$480,00$', opcao_b='$R\\$400,00$', opcao_c='$R\\$450,00$', opcao_d='$R\\$350,00$', resposta_correta='b')
        ]
        
        perguntas_hist = [
            PerguntaQuiz(id_materia=mat_historia.id, texto_pergunta='Qual país europeu iniciou a exploração do Brasil em 1500?', opcao_a='Espanha', opcao_b='Portugal', opcao_c='França', opcao_d='Inglaterra', resposta_correta='b'),
            PerguntaQuiz(id_materia=mat_historia.id, texto_pergunta='Quem proclamou a independência do Brasil em 1822?', opcao_a='Tiradentes', opcao_b='Princesa Isabel', opcao_c='Dom Pedro I', opcao_d='Marechal Deodoro', resposta_correta='c')
        ]
        
        db.session.add_all(perguntas_mat)
        db.session.add_all(perguntas_hist)
        db.session.commit()
        print('🧠 Dados de exemplo criados. Usuário: miguel@brain.com / Senha: 123')
    else:
        print('Banco de dados populado. Pulando criação de dados de exemplo.')


if __name__ == '__main__':
    # Bloco de inicialização: CRIA as tabelas (incluindo 'turma')
    with app.app_context():
        # Cria as tabelas se elas não existirem.
        db.create_all() 
        # Popula os dados de exemplo APENAS se não houver usuários.
        criar_dados_exemplo()

    # Se você ainda tiver problemas com o banco, tente limpar o cache de sessão
    # Deletar manualmente a pasta 'flask_session' (ou similar) se ela existir no seu diretório.
    app.run(debug=True)