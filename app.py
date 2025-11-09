import os
import bcrypt
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

# ==========================================
# CONFIG APP
# ==========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_super_segura_brain_2025'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'brain.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
BCRYPT_ROUNDS = 12
class Usuario(db.Model):
    __tablename__ = 'usuario'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(200), nullable=True)   # <<< IMPORTANTE

    def set_senha(self, senha):
        self.senha_hash = bcrypt.hashpw(
            senha.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        ).decode('utf-8')

    def verificar_senha(self, senha):
        return bcrypt.checkpw(
            senha.encode('utf-8'), self.senha_hash.encode('utf-8')
        )

class Conversa(db.Model):
    __tablename__ = 'conversa'
    id_conversa = db.Column(db.Integer, primary_key=True)
    usuario1_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    usuario2_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    ultima_atualizacao = db.Column(db.DateTime, default=datetime.utcnow)

class Mensagem(db.Model):
    __tablename__ = 'mensagem'
    id_mensagem = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.Text, nullable=False)
    data_envio = db.Column(db.DateTime, default=datetime.utcnow)
    conversa_id = db.Column(db.Integer, db.ForeignKey('conversa.id_conversa'), nullable=False)
    remetente_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)

# ==========================================
# MIDDLEWARE TOKEN
# ==========================================
def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        id_usuario = request.form.get("id_usuario")
        token = request.form.get("token")

        if not id_usuario or not token:
            return jsonify({"status": "erro", "mensagem": "id_usuario e token são obrigatórios"})

        usuario = Usuario.query.filter_by(id_usuario=id_usuario, token=token).first()
        if not usuario:
            return jsonify({"status": "erro", "mensagem": "Token inválido ou expirado"})

        return f(usuario, *args, **kwargs)
    return decorated

# ==========================================
# ROTAS
# ==========================================

@app.route('/registro', methods=['POST'])
def registro():
    nome = request.form.get('nome')
    email = request.form.get('email')
    senha = request.form.get('senha')

    if not nome or not email or not senha:
        return jsonify({"status": "erro", "mensagem": "Preencha tudo"})

    try:
        novo = Usuario(nome=nome, email=email)
        novo.set_senha(senha)
        db.session.add(novo)
        db.session.commit()
        return jsonify({"status": "ok", "mensagem": "Conta criada"})
    except IntegrityError:
        db.session.rollback()
        return jsonify({"status": "erro", "mensagem": "Email já existe"})

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get("email")
    senha = request.form.get("senha")

    usuario = Usuario.query.filter_by(email=email).first()

    if not usuario or not usuario.verificar_senha(senha):
        return jsonify({"status": "erro", "mensagem": "Credenciais inválidas"})

    usuario.token = secrets.token_hex(32)
    db.session.commit()

    return jsonify({
        "status": "ok",
        "id_usuario": usuario.id_usuario,
        "nome": usuario.nome,
        "token": usuario.token
    })

@app.route('/criar_conversa', methods=['POST'])
@token_required
def criar_conversa(usuario):
    receptor_id = request.form.get("receptor_id")

    ids = sorted([usuario.id_usuario, int(receptor_id)])
    conversa = Conversa.query.filter_by(usuario1_id=ids[0], usuario2_id=ids[1]).first()

    if not conversa:
        conversa = Conversa(usuario1_id=ids[0], usuario2_id=ids[1])
        db.session.add(conversa)
        db.session.commit()

    return jsonify({"status": "ok", "conversa_id": conversa.id_conversa})

@app.route('/enviar', methods=['POST'])
@token_required
def enviar(usuario):
    conversa_id = request.form.get("conversa_id")
    texto = request.form.get("texto")

    nova = Mensagem(texto=texto, conversa_id=conversa_id, remetente_id=usuario.id_usuario)
    db.session.add(nova)
    db.session.commit()
    return jsonify({"status": "ok"})

@app.route('/mensagens', methods=['POST'])
@token_required
def mensagens(usuario):
    conversa_id = request.form.get("conversa_id")
    msgs = Mensagem.query.filter_by(conversa_id=conversa_id).order_by(Mensagem.data_envio.asc()).all()

    return jsonify([
        {"remetente": m.remetente_id, "texto": m.texto, "data": m.data_envio.isoformat()}
        for m in msgs
    ])

# ==========================================
# EXECUTAR
# ==========================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
