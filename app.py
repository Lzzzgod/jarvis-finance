import base64
from io import BytesIO
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, session
from flask import jsonify
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from flask_mysqldb import MySQL
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
from functools import lru_cache
from flask_sslify import SSLify
from datetime import datetime, timedelta
from prophet import Prophet
from dotenv import load_dotenv
import plotly.graph_objs as go
import plotly.io as pio
import pandas as pd
import requests
import MySQLdb.cursors
import re
import bcrypt
import pyotp
import qrcode
import os
import secrets
import ssl
import logging
import json

app = Flask(__name__, static_folder='static')
sslify = SSLify(app)
app.secret_key = os.getenv('SECRET_KEY')
load_dotenv()
oauth = OAuth(app)

# ============================== DB CONNECTION ==============================
mysql = MySQL(app)

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_SSL_CA'] = os.getenv('MYSQL_SSL_CA')
app.config['MYSQL_SSL_DISABLED'] = os.getenv('MYSQL_SSL_DISABLED')

@app.route('/testar_conexao')
def testar_conexao():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM jv_user')
        resultado = cursor.fetchall()
        return 'Conexão ao banco de dados funcionando corretamente!'
    except Exception as e:
        return 'Erro ao conectar ao banco de dados: ' + str(e)



@app.route("/")
def index():
    print("Rota index hit")
    return render_template("index.html")
    
# ============================== LOGIN ==============================

@app.route('/login/', methods=['GET', 'POST'])
def login():
    print("Rota login hit")
    
    msg = ''
    
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']

        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM jv_user WHERE email_user = %s', (email,))
            account = cursor.fetchone()
            
            if account:
                # Fazendo o hash da senha
                stored_hash = account['senha_user']
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['email'] = account['email_user']
                    
                    # Verificando se o usuário possui MFA
                    cursor.execute('SELECT * FROM jv_mfa WHERE user_id = %s', (session['id'],))
                    mfa_account = cursor.fetchone()
                    
                    if mfa_account:
                        # Se possuir MFA, redireciona para a página de MFA
                        return redirect(url_for('mfa_code'))
                    else:
                        # Se não possuir MFA, redireciona para a página de adição do MFA na conta

                        return redirect(url_for('mfa_add'))
                else:
                    msg = 'Email ou senha, incorretos!'
                    return render_template('login.html', msg=msg)
            else:
                msg = 'Email ou senha, incorretos!'
                return render_template('login.html', msg=msg)
        except Exception as e:
            print("Erro ao executar cursor:", e)
            msg = 'Erro ao conectar ao banco de dados!'
            return render_template('login.html', msg=msg)
    
    return render_template('login.html', msg=msg)

# ============================== MFA ===============================

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    print("Rota mfa hit")
    if 'loggedin' in session:
        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM jv_mfa WHERE user_id = %s', (session['id'],))
            mfa_account = cursor.fetchone()

            if mfa_account:
                # Usuário já possui MFA, redireciona para a rota mfa_code
                return redirect(url_for('mfa_code'))
            else:
                # Usuário não possui MFA, gera uma chave secreta e mostra o código QR para configuração
                secret_key = pyotp.random_base32()
                qr_code_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=session['email'], issuer_name='Jarvis')
                qr_code_img = qrcode.make(qr_code_uri)  # Gera imagem do código QR

                # Converte objeto de imagem PIL em string base64
                buf = BytesIO()
                qr_code_img.save(buf, 'PNG')
                qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

                # Armazena o secret na sessao do user
                session['mfa_secret_key'] = secret_key

                return render_template('mfacreate.html', qr_code_b64=qr_code_b64)
        except Exception as e:
            print("Erro ao executar cursor:", e)
            return 'Erro ao conectar ao banco de dados!'
    else:
        return redirect(url_for('login'))
    
@app.route('/mfa_add', methods=['GET', 'POST'])
def mfa_add():
    if 'loggedin' in session:
        if request.method == 'POST':
            code = request.form.get('code')
            if not code:
                return 'Erro: código não fornecido', 400
            # Tras o secret na sessao
            secret_key = session.get('mfa_secret_key')
            # Verifica o codigo MFA
            totp = pyotp.TOTP(secret_key)
            if totp.verify(code):  # Valida o cod
                # se valido armazena no banco
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('INSERT INTO jv_mfa (user_id, secret_key) VALUES (%s, %s)', (session['id'], secret_key))
                mysql.connection.commit()
                # Remove o secret da sessao do user
                session.pop('mfa_secret_key', None)
                # Seta o status do MFA na sessao
                session['mfa_validated'] = True

                return redirect(url_for('home'))
            else:
                # Se  o código não for válido, redireciona para a página de configuração novamente
                return render_template('mfacreate.html', error='Código inválido')
        else:
            # Gera o secret _key e o código QRcode pra configurar
            secret_key = pyotp.random_base32()
            qr_code_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=session['email'], issuer_name='Jarvis')
            qr_code_img = qrcode.make(qr_code_uri)
            buf = BytesIO()
            qr_code_img.save(buf, 'PNG')
            qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            session['mfa_secret_key'] = secret_key

            return render_template('mfacreate.html', qr_code_b64=qr_code_b64)
    else:
        return redirect(url_for('login'))
    
@app.route('/mfa_code', methods=['GET', 'POST'])
def mfa_code():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM jv_mfa WHERE user_id = %s', (session['id'],))
        mfa_account = cursor.fetchone()
        
        if request.method == 'POST':
            code = request.form.get('mfa_code')
            if not code:
                msg = 'Erro: código não fornecido'
                return render_template('mfacode.html', msg=msg, mfa_account=mfa_account), 400

            secret_key = mfa_account['secret_key']

            # valida o MFA code
            totp = pyotp.TOTP(secret_key)
            if totp.verify(code, valid_window=5):  # checa se é valido no tempo, se valido armazena o status
                session['mfa_validated'] = True
                return redirect(url_for('home'))
            else:
                msg = 'Código inválido'
                return render_template('mfacode.html', msg=msg, mfa_account=mfa_account)
        else:
            return render_template('mfacode.html', mfa_account=mfa_account)
    else:
        return redirect(url_for('login'))

# ============================== GOOGLE CONN ===============================

@app.route('/google')
def google():

    GOOGLE_CLIENT_ID = '629125446306-ok7guc19anhrqnk419ea52nb29te6sk9.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'

    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
    redirect_uri = url_for('google_auth', _external=True)
    print(redirect_uri)
    session['nonce'] = generate_token()
    return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])

@app.route('/google/auth')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token, nonce=session['nonce'])
    session['user'] = user

    # Verificar se o usuário existe no banco de dados
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM jv_user WHERE email_user = %s', (user['email'],))
    account = cursor.fetchone()

    if account:
        # Verificar se o usuário possui MFA configurado
        cursor.execute('SELECT * FROM jv_mfa WHERE user_id = %s', (account['id'],))
        mfa_account = cursor.fetchone()

        if mfa_account:
            # Login do usuário
            session['loggedin'] = True
            session['id'] = account['id']
            session['email'] = account['email_user']
            return redirect(url_for('home'))
        else:
            # Redirecionar para a página de configuração do MFA
            return redirect(url_for('mfa_add'))
    else:
        # Criar uma nova conta para o usuário
        hashed_password = bcrypt.hashpw(user['email'], bcrypt.gensalt())
        cursor.execute('INSERT INTO jv_user (nome_user, senha_user, email_user, tel_user) VALUES (%s, %s, %s, %s)', (user['name'], hashed_password, user['email'], ''))
        mysql.connection.commit()
        session['loggedin'] = True
        session['id'] = cursor.lastrowid
        session['email'] = user['email']
        return redirect(url_for('mfa_add'))
    
@app.route('/check_session')
def check_session():
    return jsonify({'logged_in': 'loggedin' in session})
# ============================== HOME DO APP ===============================

@app.route('/home')
def home():
    if 'loggedin' in session and 'mfa_validated' in session and session['mfa_validated']:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT nome_user FROM jv_user WHERE id = %s', (session['id'],))
        user_name = cursor.fetchone()['nome_user']
        
        # Consulta as transações do usuário
        cursor.execute("SELECT * FROM jv_receitas WHERE id = %s", (session['id'],))
        receitas = cursor.fetchall()
        cursor.execute("SELECT * FROM jv_despesas WHERE id = %s", (session['id'],))
        despesas = cursor.fetchall()
        
        # Calcula o saldo geral
        saldo = sum(float(r['valor_rec']) for r in receitas) - sum(float(d['valor_des']) for d in despesas)
        
        # Renderiza a página com o saldo geral
        return render_template('home.html', username=user_name, saldo=saldo)
    else:
        return redirect(url_for('login'))

@app.route('/profile')
def profile():
    # Checa se o usuario esta logado
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM jv_user WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        username = account['nome_user']
        

        return render_template('profile.html', account=account, username=username)
    
    return redirect(url_for('login'))

# ============================== ALTERA DADOS PROFILE ===============================

@app.route('/alterar_senha', methods=['GET', 'POST'])
def alterar_senha():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Verificar se os campos estão vazios
        if not current_password or not new_password or not confirm_password:
            msg = 'Preencha todos os campos'
            return render_template('alterar_senha.html', msg=msg)

        # Verificar se as senhas novas são iguais
        if new_password != confirm_password:
            msg = 'Senhas novas não são iguais'
            return render_template('alterar_senha.html', msg=msg)

        # Verificar a complexidade da senha
        if len(new_password) < 8:
            msg = 'Senha deve ter pelo menos 8 caracteres'
            return render_template('alterar_senha.html', msg=msg)

        if not any(char.isupper() for char in new_password):
            msg = 'Senha deve ter pelo menos uma letra maiúscula'
            return render_template('alterar_senha.html', msg=msg)

        if not any(char.islower() for char in new_password):
            msg = 'Senha deve ter pelo menos uma letra minúscula'
            return render_template('alterar_senha.html', msg=msg)

        if not any(char.isdigit() for char in new_password):
            msg = 'Senha deve ter pelo menos um número'
            return render_template('alterar_senha.html', msg=msg)

        if not any(not char.isalnum() for char in new_password):
            msg = 'Senha deve ter pelo menos um caractere especial'
            return render_template('alterar_senha.html', msg=msg)

        # Atualizar senha do usuário
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('UPDATE jv_user SET senha_user = %s WHERE email_user = %s', (hashed_password, session['email']))
        mysql.connection.commit()
        cursor.close()
        mysql.connection.close()
        msg = '<span id="msg-sucesso" style="color: green;">Senha alterada com sucesso!</span>'
        return render_template('alterar_senha.html', msg=msg)

    return render_template('alterar_senha.html')


@app.route('/alterar_dados', methods=['GET', 'POST'])
def alterar_dados():
    if 'loggedin' in session and session['loggedin']:
        msg = ''
        if request.method == 'POST':
            nome = request.form.get('nome').strip()
            email = request.form.get('email').strip()
            telefone = request.form.get('telefone').strip()

            # Checagem dos campos
            if not nome or not email or not telefone:
                msg = 'Por favor preencha todos os campos!!'
            elif not re.match(r'[A-Za-z0-9\s]+', nome):
                msg = 'Nome deve conter apenas caracteres e números!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            elif len(telefone) < 14 or not re.match(r'^\([0-9]{2}\) [0-9]{4,5}-[0-9]{4}$', telefone):
                msg = 'Telefone inválido. Por favor, digite um telefone no formato (XX) XXXX-XXXX.'
            else:
                # Atualizar dados no banco
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('UPDATE jv_user SET nome_user = %s, email_user = %s, tel_user = %s WHERE id = %s', (nome, email, telefone, session['id']))
                mysql.connection.commit()
                msg = 'Dados alterados com sucesso!'

                # Cria um popup de confirmação e redirecione para a página de perfil
                return render_template('alterar_dados.html', msg=msg, account=cursor.fetchone(), popup=True)
            
        # get dados do banco
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM jv_user WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        return render_template('alterar_dados.html', msg=msg, account=account)
    else:
        return redirect(url_for('login'))

# ============================== LOGOUT ===============================

@app.route('/logout')
def logout():
    # remove os dados da sessao
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirecionar para login
    return redirect(url_for('login'))

# ============================== REGISTER ===============================

@app.route('/registrar', methods=['GET', 'POST'])
def register(): 
    print(request.form)  # Imprimir os dados recebidos
    msg = ''
    if request.method == 'POST' and 'nome' in request.form and 'password' in request.form and 'email' in request.form and 'telefone' in request.form and 'repass' in request.form:
        
        nome = request.form['nome']
        password = request.form['password']
        repassword = request.form['repass']
        email = request.form['email']
        telefone = request.form['telefone']

        if not nome or not password or not repassword or not email or not telefone:
            msg = 'Por favor preencha todos os campos!!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9\s]+', nome):
            msg = 'Nome deve conter apenas caracteres e números!'
        elif password != repassword:
            msg = 'Senhas não conferem. Por favor, digite a mesma senha novamente.'
        elif len(password) < 8:
            msg = 'Senha inválida. Por favor, digite uma senha com no mínimo 8 caracteres.'
        elif not re.match(r'^\([0-9]{2}\) [0-9]{4,5}-[0-9]{4}$', telefone):
            msg = 'Telefone inválido. Por favor, digite um telefone no formato (XX) XXXX-XXXX.'
        else:
            try:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                print("Cursor criado com sucesso!") 
                cursor.execute('SELECT * FROM jv_user WHERE email_user = %s', (email,))
                account = cursor.fetchone()

                if account:
                    msg = 'Este email já está cadastrado!'
                else:
                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    try:
                        print("INSERT query:", 'INSERT INTO jv_user (nome_user, senha_user, email_user, tel_user) VALUES (%s, %s, %s, %s)' % (nome, hashed_password, email, telefone))  # Debugging statement
                        cursor.execute('INSERT INTO jv_user (nome_user, senha_user, email_user, tel_user) VALUES (%s, %s, %s, %s)', (nome, hashed_password, email, telefone))
                        mysql.connection.commit()
                        msg = 'Registro efetuado com sucesso!'
                        return redirect(url_for('login')) 
                    except Exception as e:
                        print("Erro ao inserir dados:", e)
            except Exception as e:
                print("Erro ao executar cursor:", e)
    elif request.method == 'POST':
        msg = 'Por Favor preencha o Formulario!'
    return render_template('register.html', msg=msg)

# ============================== RECEITAS E DESPESAS ===============================
@app.route('/adicionar_receita', methods=['POST'])
def adicionar_receita():
    if 'loggedin' in session and 'id' in session:
        descricao_rec = request.form['descricao_rec']
        valor_rec = request.form['valor_rec']
        data_rec = request.form['data_rec']
        categoria = request.form['categoria']

        # Insere a receita no banco de dados
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO jv_receitas (id, descricao_rec, valor_rec, data_rec, categoria) VALUES (%s, %s, %s, %s, %s)", 
                    (session['id'], descricao_rec, valor_rec, data_rec, categoria))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('home'))
    else:
        # Se o usuário não estiver logado, redireciona para a página de login
        return redirect(url_for('login'))

@app.route('/adicionar_despesa', methods=['POST'])
def adicionar_despesa():
    if 'loggedin' in session and 'id' in session:
        descricao_des = request.form['descricao_des']
        valor_des = request.form['valor_des']
        data_des = request.form['data_des']
        categoria = request.form['categoria']

        # Insere a despesa no banco de dados
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO jv_despesas (id, descricao_des, valor_des, data_des, categoria) VALUES (%s, %s, %s, %s, %s)", 
                    (session['id'], descricao_des, valor_des, data_des, categoria))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('home'))
    else:
        # Se o usuário não estiver logado, redireciona para a página de login
        return redirect(url_for('login'))

@app.route('/relatorio')
def relatorio():
    if 'loggedin' in session and 'mfa_validated' in session and session['mfa_validated']:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Buscar receitas
        cur.execute("SELECT * FROM jv_receitas WHERE id = %s", (session['id'],))
        receitas = cur.fetchall()

        # Buscar despesas
        cur.execute("SELECT * FROM jv_despesas WHERE id = %s", (session['id'],))
        despesas = cur.fetchall()

        # Inicializar dicionários
        receitas_data = {}
        despesas_data = {}
        categorias_receitas_data = {}
        categorias_despesas_data = {}

        # Preparar dados para gráficos
        for item in receitas:
            if item['data_rec'] and item['valor_rec'] is not None:
                data = item['data_rec'].strftime('%Y-%m-%d') if isinstance(item['data_rec'], datetime) else str(item['data_rec'])
                valor = float(item['valor_rec'])
                receitas_data[data] = receitas_data.get(data, 0) + valor
                categoria = item['categoria'] if item['categoria'] else 'Sem categoria'
                categorias_receitas_data[categoria] = categorias_receitas_data.get(categoria, 0) + valor

        for item in despesas:
            if item['data_des'] and item['valor_des'] is not None:
                data = item['data_des'].strftime('%Y-%m-%d') if isinstance(item['data_des'], datetime) else str(item['data_des'])
                valor = float(item['valor_des'])
                despesas_data[data] = despesas_data.get(data, 0) + valor
                categoria = item['categoria'] if item['categoria'] else 'Sem categoria'
                categorias_despesas_data[categoria] = categorias_despesas_data.get(categoria, 0) + valor

        # Ordenar as datas
        receitas_data = dict(sorted(receitas_data.items()))
        despesas_data = dict(sorted(despesas_data.items()))

        # Preparar dados para o Prophet
        df = pd.DataFrame(list(receitas_data.items()), columns=['ds', 'y'])
        df['ds'] = pd.to_datetime(df['ds'])
        df['y'] = df['y'].astype(float)
        df = df.dropna()

        # Inicializar variáveis para o caso de não haver dados suficientes
        plot_json = "{}"
        previsao_proximo_mes = 0
        variacao_percentual = 0

        if not df.empty and len(df) >= 2:
            try:
                # Criar e treinar o modelo
                model = Prophet(yearly_seasonality=False,
                                weekly_seasonality=False,
                                daily_seasonality=True,
                                seasonality_mode='additive')
                model.fit(df)

                # Fazer previsões
                future = model.make_future_dataframe(periods=30)
                forecast = model.predict(future)

                # Criar gráfico com Plotly
                fig = go.Figure()

                # Dados históricos
                fig.add_trace(go.Scatter(x=df['ds'], y=df['y'], name='Dados históricos', mode='markers'))

                # Linha de previsão
                fig.add_trace(go.Scatter(x=forecast['ds'], y=forecast['yhat'], name='Previsão', line=dict(color='blue')))

                # Intervalo de confiança
                fig.add_trace(go.Scatter(
                    x=forecast['ds'].tolist() + forecast['ds'].tolist()[::-1],
                    y=forecast['yhat_upper'].tolist() + forecast['yhat_lower'].tolist()[::-1],
                    fill='toself',
                    fillcolor='rgba(144, 238, 144, 0.3)',
                    line=dict(color='rgba(255,255,255,0)'),
                    hoverinfo="skip",
                    showlegend=True,
                    name='Intervalo de confiança'
                ))

                fig.update_layout(
                    title='Previsão de Receitas',
                    xaxis_title='Data',
                    yaxis_title='Valor',
                    hovermode="x unified"
                )

                # Converter o gráfico para JSON
                plot_json = fig.to_json()

                # Calcular previsão para o próximo mês
                proximo_mes = forecast.iloc[-1]
                previsao_proximo_mes = proximo_mes['yhat']

                # Calcular variação percentual
                if len(df) > 0 and df['y'].iloc[-1] > 0:
                    variacao_percentual = ((previsao_proximo_mes - df['y'].iloc[-1]) / df['y'].iloc[-1]) * 100
                else:
                    variacao_percentual = 0

            except Exception as e:
                print(f"Erro na previsão: {e}")

        # Calcular métricas adicionais
        total_receitas = sum(receitas_data.values())
        total_despesas = sum(despesas_data.values())
        saldo = total_receitas - total_despesas

        # Calcular o saldo atual
        saldo_atual = sum(float(r['valor_rec']) for r in receitas) - sum(float(d['valor_des']) for d in despesas)

        cur.close()

        return render_template('relatorio.html',
                               receitas_data=receitas_data,
                               despesas_data=despesas_data,
                               categorias_receitas_data=categorias_receitas_data,
                               categorias_despesas_data=categorias_despesas_data,
                               plot_json=plot_json,
                               total_receitas=total_receitas,
                               total_despesas=total_despesas,
                               saldo=saldo,
                               saldo_atual=saldo_atual,
                               previsao_proximo_mes=previsao_proximo_mes,
                               variacao_percentual=variacao_percentual)
    else:
        return redirect(url_for('login'))
 # ============================== EXTRATO BANCARIO ===============================   
@app.route('/extrato')
def extrato():
    if 'loggedin' in session and 'mfa_validated' in session and session['mfa_validated']:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Buscar receitas
        cursor.execute("SELECT * FROM jv_receitas WHERE id = %s ORDER BY data_rec DESC", (session['id'],))
        receitas = cursor.fetchall()
        
        # Buscar despesas
        cursor.execute("SELECT * FROM jv_despesas WHERE id = %s ORDER BY data_des DESC", (session['id'],))
        despesas = cursor.fetchall()
        
        # Combinar receitas e despesas em uma única lista
        transacoes = []
        for receita in receitas:
            transacoes.append({
                'tipo': 'Receita',
                'descricao': receita['descricao_rec'],
                'valor': receita['valor_rec'],
                'data': receita['data_rec'],
                'categoria': receita['categoria']
            })
        for despesa in despesas:
            transacoes.append({
                'tipo': 'Despesa',
                'descricao': despesa['descricao_des'],
                'valor': despesa['valor_des'],
                'data': despesa['data_des'],
                'categoria': despesa['categoria']
            })
        
        # Ordenar transações por data (mais recente primeiro)
        transacoes.sort(key=lambda x: x['data'], reverse=True)
        
        # Buscar o nome do usuário do banco de dados
        cursor.execute('SELECT nome_user FROM jv_user WHERE id = %s', (session['id'],))
        user = cursor.fetchone()
        username = user['nome_user'] if user else 'Usuário'
        
        return render_template('extrato.html', transacoes=transacoes, username=username)
    else:
        return redirect(url_for('login'))
    
# ============================== OPEN FINANCE ===============================
#OPEN FINANCE CLASS
class PluggyAPI:
    BASE_URL = "https://api.pluggy.ai"

    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = self._get_access_token()
        

    def _get_access_token(self):
        """Obtém o token de acesso da API do Pluggy"""
        try:
            response = requests.post(
                f"{self.BASE_URL}/auth",
                json={
                    "clientId": self.client_id,
                    "clientSecret": self.client_secret
                }
            )
            response.raise_for_status()
            return response.json()["apiKey"]
        except requests.exceptions.RequestException as e:
            print(f"Erro ao obter token de acesso: {e}")
            raise

    def connect_token(self):
        """Cria um token de conexão"""
        try:
            payload = { }
            response = requests.post(
                f"{self.BASE_URL}/connect_token",
                headers={"X-API-KEY": self.access_token},
                json=payload
            )
            response.raise_for_status()

            # Debug: imprimir a resposta
            print(f"Resposta do Connect Token: {response.json()}")

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"Erro ao criar connect token: {e}")
            raise

    def list_connectors(self, page=1, page_size=10, name=None, countries=None, types=None):
        """Lista todos os conectores disponíveis com opções de filtro"""
        try:
            params = {
                'page': page,
                'pageSize': page_size
            }
            
            if name:
                params['name'] = name
            if countries:
                params['countries'] = countries
            if types:
                params['types'] = types

            response = requests.get(
                f"{self.BASE_URL}/connectors",
                headers={"X-API-KEY": self.access_token},
                params=params
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erro ao listar conectores: {e}")
            raise

    def get_connector(self, connector_id):
        """Obtém informações detalhadas de um conector específico"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/connectors/{connector_id}",
                headers={"X-API-KEY": self.access_token}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erro ao obter conector: {e}")
            raise

    def create_item(self, connector_id, parameters=None):
        """Cria um novo item (conexão com instituição financeira)"""
        try:
            payload = {
                "connectorId": connector_id,
                "parameters": parameters or {}
            }
            response = requests.post(
                f"{self.BASE_URL}/items",
                headers={"X-API-KEY": self.access_token},
                json=payload
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erro ao criar item: {e}")
            raise

# Inicialize o cliente Pluggy
pluggy_client = PluggyAPI(
    client_id=os.getenv('PLUGGY_CLIENT_ID'),
    client_secret=os.getenv('PLUGGY_CLIENT_SECRET')
    
)

@app.route('/connector_credentials', methods=['GET'])
def get_connector_credentials(connector_id):
    url = f"https://api.pluggy.ai/connectors/{connector_id}"
    
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-API-KEY": pluggy_client.access_token
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()  # Retorna as credenciais necessárias
    else:
        raise Exception(f"Erro ao buscar credenciais do conector: {response.text}")
    
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/list_connectors', methods=['GET'])
def list_connectors():
    if 'loggedin' in session:
        try:
            # Fetch connectors from Pluggy API
            connectors = pluggy_client.list_connectors(countries='BR')
            connectors_data = connectors.get('results', [])
            
            logging.debug(f"Conectores recebidos: {connectors_data}")

            # Salvar conectores no banco de dados
            if connectors_data:
                for connector in connectors_data:
                    store_connector_in_db(connector)

            return jsonify({
                'status': 'success',
                'connectors': connectors_data
            })
        except Exception as e:
            logging.error(f"Erro ao buscar conectores: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
    return jsonify({'error': 'Unauthorized'}), 401

def store_connector_in_db(connector):
    try:
        # Conectar ao banco de dados usando o MySQLdb
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Remover o 'Z' e ajustar a data para o formato compatível com MySQL
        created_at = connector['createdAt'].replace('T', ' ')[:-1]  # Substitui 'T' por espaço e remove 'Z'
        updated_at = connector['updatedAt'].replace('T', ' ')[:-1]  # Mesma coisa para a data de atualização

        logging.debug(f"Inserindo conector: {connector['id']}")

        # Inserir os dados do conector na tabela
        cursor.execute("""
            INSERT INTO jv_connectors (id, name, logo, institution_url, products, type, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            connector['id'],
            connector['name'],
            connector['imageUrl'],
            connector['institutionUrl'],
            json.dumps(connector['products']),  # Armazena a lista de produtos como JSON
            connector['type'],
            created_at,  # Usando o formato corrigido
            updated_at   # Usando o formato corrigido
        ))

        # Commit da transação
        mysql.connection.commit()
        logging.debug(f"Conector {connector['id']} inserido com sucesso.")

        # Fechar o cursor
        cursor.close()

    except MySQLdb.Error as err:
        logging.error(f"Erro ao conectar ou inserir dados no banco: {err}")
    finally:
        if cursor:
            cursor.close()

@app.route('/connect_token', methods=['GET'])
def get_connect_token():
    try:
        # Confirme se o ID do usuário está disponível na sessão
        if 'id' not in session:
            return jsonify({"error": "ID de sessão não definido"}), 400

        url = "https://api.pluggy.ai/connect_token"
        payload = {
            "options": {
                "clientUserId": str(session['id']),  # Convertendo o ID para string
                "webhookUrl": "https://www.jarvisfinance.xyz"
            }
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "X-API-KEY": pluggy_client.access_token  # Certifique-se de que o token está correto
        }

        response = requests.post(url, json=payload, headers=headers)

        # Verifique se a resposta foi bem-sucedida
        response.raise_for_status()

        # Retorne a resposta da API como JSON
        return jsonify(response.json())

    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/create_item', methods=['POST'])
def create_item():
    # Verifica se o usuário está logado
    if 'loggedin' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    try:
        # Obtém os dados enviados pelo frontend
        data = request.json
        print('Dados recebidos no backend:', data)
        if not data:
            return jsonify({'status': 'error', 'message': 'Payload inválido'}), 400

        # Obtém o 'item_id' e 'connector_id' do JSON recebido
        item_id = data.get('id')  # Certifique-se de que o frontend envie o JSON correto
        connector_id = data.get('connector_id')  # Novo campo para o 'connector_id'
        
        if connector_id == 2:
            connector_id = 200

        if not item_id:
            return jsonify({'status': 'error', 'message': 'Item ID não encontrado no JSON'}), 400
        if not connector_id:
            return jsonify({'status': 'error', 'message': 'Connector ID não encontrado no JSON'}), 400

        # Obtém o ID do usuário logado
        user_id = session['id']

        # Armazena o item_id, client_user_id e connector_id no banco
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            INSERT INTO jv_items (item_id, client_user_id, connector_id)
            VALUES (%s, %s, %s)
        """, (item_id, user_id, connector_id))
        mysql.connection.commit()
        cursor.close()

        # Resposta de sucesso
        return jsonify({'status': 'success', 'message': 'Item e Connector associados ao usuário com sucesso!'}), 201

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Erro interno: {str(e)}'}), 500

@app.route('/delete_bank', methods=['DELETE'])
def delete_bank():
    try:
        logging.info("Recebendo solicitação para remover banco conectado.")
        
        # Obter o item_id do request JSON
        data = request.get_json()
        item_id = data.get('item_id')

        if not item_id:
            logging.error("ID do item não fornecido na solicitação.")
            return jsonify({'status': 'error', 'message': 'ID do item não fornecido'}), 400

        logging.debug(f"Item ID recebido: {item_id}")

        # Configurar a URL da API Pluggy
        url = f"https://api.pluggy.ai/items/{item_id}"
        headers = {
            "accept": "application/json",
            "X-API-KEY": pluggy_client.access_token  # Altere para sua chave correta
        }

        logging.debug(f"Enviando solicitação DELETE para Pluggy na URL: {url}")
        
        # Fazer a requisição DELETE na Pluggy
        response = requests.delete(url, headers=headers)

        if response.status_code in [200, 204]:  # Considere sucesso para 200 ou 204
            logging.info(f"Item {item_id} removido com sucesso da Pluggy. Resposta: {response.json()}")
            
            # Conectar ao banco de dados
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            logging.debug(f"Conectado ao banco de dados. Tentando remover contas associadas ao item {item_id}.")
            
            # Primeiro, removemos as contas associadas ao item
            cursor.execute("DELETE FROM jv_accounts WHERE item_id = %s", (item_id,))
            mysql.connection.commit()

            affected_rows = cursor.rowcount
            if affected_rows > 0:
                logging.info(f"{affected_rows} conta(s) removida(s) associada(s) ao item {item_id}.")
            else:
                logging.warning(f"Nenhuma conta encontrada para o item {item_id}.")

            # Agora, removemos o item da tabela jv_items
            logging.debug(f"Removendo item {item_id} da tabela jv_items.")
            cursor.execute("DELETE FROM jv_items WHERE item_id = %s", (item_id,))
            mysql.connection.commit()

            affected_rows = cursor.rowcount
            cursor.close()

            if affected_rows > 0:
                logging.info(f"Item {item_id} removido com sucesso do banco local.")
                return jsonify({'status': 'success', 'message': 'Banco removido com sucesso'}), 200
            else:
                logging.warning(f"Nenhum registro encontrado para o item {item_id} no banco local.")
                return jsonify({'status': 'warning', 'message': 'Banco removido da Pluggy, mas não encontrado no banco local'}), 200

        # Log e retorno detalhado do erro na API Pluggy
        logging.error(f"Erro inesperado na API Pluggy ao remover item {item_id}: {response.status_code} - {response.text}")
        return jsonify({'status': 'error', 'message': f"Erro na API Pluggy: {response.text}"}), 500

    except Exception as e:
        logging.exception(f"Erro ao deletar banco: {e}")
        return jsonify({'status': 'error', 'message': f"Erro interno: {e}"}), 500


@app.route('/connected_banks', methods=['GET'])
def connected_banks():
    print(pluggy_client.access_token)
    if 'loggedin' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    try:
        user_id = session['id']  # Obtém o ID do usuário logado
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Busca os item_ids relacionados ao usuário logado
        cursor.execute("""
            SELECT item_id FROM jv_items
            WHERE client_user_id = %s
        """, (user_id,))
        items = cursor.fetchall()
        cursor.close()
        
        if not items:
            return jsonify({'status': 'success', 'data': [], 'message': 'Nenhum banco conectado encontrado.'}), 200

        # Lista de itens com informações dos conectores
        connected_banks = []

        for item in items:
            item_id = item['item_id']
            # Aqui estamos passando o item_id obtido do banco para a API
            url = f"https://api.pluggy.ai/items/{item_id}"  # URL da API da Pluggy para obter os detalhes do item
            headers = {
                "accept": "application/json",
                "X-API-KEY": pluggy_client.access_token  # Substitua com a sua chave de API da Pluggy
            }

            # Faz a requisição para obter os detalhes do item na API da Pluggy
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                pluggy_item_data = response.json()
                
                # Adiciona os dados do item à lista de conectados
                connected_banks.append({
                    'item_id': item_id,
                    'status': pluggy_item_data.get('status', 'Status Desconhecido'),
                    'connector': {
                        'imageUrl': pluggy_item_data.get('connector', {}).get('imageUrl', None),
                        'name': pluggy_item_data.get('connector',{}).get('name', 'Banco Desconhecido'),
                        'institution_url': pluggy_item_data.get('connector',{}).get('institutionUrl', '#'),
                    }
                })
            else:
                connected_banks.append({'item_id': item_id, 'error': 'Erro ao buscar dados na Pluggy'})

        return jsonify({'status': 'success', 'data': connected_banks}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Erro interno: {str(e)}'}), 500

@app.route('/user_accounts', methods=['GET'])
def get_user_accounts():
    if 'loggedin' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    try:
        user_id = session['id']  # Obtém o ID do usuário logado
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Busca os item_ids relacionados ao usuário logado
        cursor.execute("""
            SELECT item_id FROM jv_items
            WHERE client_user_id = %s
        """, (user_id,))
        items = cursor.fetchall()

        if not items:
            cursor.close()
            return jsonify({'status': 'success', 'data': [], 'message': 'Nenhuma conta encontrada.'}), 200

        user_accounts = []

        for item in items:
            item_id = item['item_id']
            # Faz a requisição para obter as contas associadas ao item
            url = f"https://api.pluggy.ai/accounts?itemId={item_id}"
            headers = {
                "accept": "application/json",
                "X-API-KEY": pluggy_client.access_token  
            }

            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                accounts_data = response.json().get('results', [])
                
                # Adiciona cada conta encontrada à lista de contas do usuário
                for account in accounts_data:
                    account_id = account['id']
                    name = account.get('name', 'Conta Desconhecida')
                    balance = account.get('balance', 0.0)
                    currency = account.get('currencyCode', 'BRL')
                    created_at_raw = account.get('createdAt', None)
                    owner = account.get('owner', None)
                    account_type = account['type']
                    credit_data = account.get('creditData', {})

                    # Converte o campo created_at para o formato compatível com MySQL
                    created_at = None
                    if created_at_raw:
                        try:
                            created_at = datetime.strptime(created_at_raw, "%Y-%m-%dT%H:%M:%S.%fZ")
                        except ValueError:
                            # Caso o milissegundos não seja fornecido
                            created_at = datetime.strptime(created_at_raw, "%Y-%m-%dT%H:%M:%SZ")

                    # Insere os dados da conta na tabela jv_accounts
                    cursor.execute("""
                        INSERT INTO jv_accounts (account_id, item_id, type, name, balance, currency, created_at, owner)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        name = VALUES(name),
                        balance = VALUES(balance),
                        currency = VALUES(currency),
                        created_at = VALUES(created_at),
                        owner = VALUES(owner),
                        type = VALUES(type)
                    """, (account_id, item_id, account_type, name, balance, currency, created_at, owner))
                    
                    mysql.connection.commit()

                    # Adiciona ao retorno
                    user_accounts.append({
                        'account_id': account_id,
                        'item_id': item_id,
                        'type': account_type,
                        'name': name,
                        'balance': balance,
                        'currency': currency,
                        'created_at': created_at,
                        'owner': owner,
                        'creditData': credit_data
                    })
            else:
                user_accounts.append({'item_id': item_id, 'error': 'Erro ao buscar contas na Pluggy'})

        cursor.close()
        return jsonify({'status': 'success', 'data': user_accounts}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Erro interno: {str(e)}'}), 500

@app.route('/get_transactions/<item_id>', methods=['GET'])
def get_transactions(item_id):
    if 'loggedin' in session:
        try:
            from_date = request.args.get('from')
            to_date = request.args.get('to')
            headers = {"X-API-KEY": pluggy_client.access_token}
            params = {"itemId": item_id}
            if from_date:
                params["from"] = from_date
            if to_date:
                params["to"] = to_date

            response = requests.get(
                f"{pluggy_client.BASE_URL}/transactions",
                headers=headers,
                params=params
            )
            return jsonify(response.json())
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Unauthorized'}), 401

#PROCESSA TRANSAÇOES E ARMAZENA NA DB

# Função para processar transações e salvar no banco de dado

@app.route('/sync_transactions', methods=['GET'])
def sync_transactions():
    if 'loggedin' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    try:
        user_id = session['id']  # ID do usuário logado
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Buscar contas associadas ao usuário
        cursor.execute("""
            SELECT account_id FROM jv_accounts
            WHERE user_id = %s
        """, (user_id,))
        accounts = cursor.fetchall()

        if not accounts:
            cursor.close()
            return jsonify({'status': 'success', 'data': [], 'message': 'Nenhuma conta encontrada para sincronizar.'}), 200

        synced_transactions = []
        for account in accounts:
            account_id = account['account_id']

            # Requisição para obter transações do Pluggy
            url = f"https://api.pluggy.ai/transactions?accountId={account_id}"
            headers = {
                "accept": "application/json",
                "X-API-KEY": pluggy_client.access_token  # Token de API
            }
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                transactions = response.json().get('results', [])
                for transaction in transactions:
                    amount = transaction['amount']
                    transaction_type = 'receitas' if amount > 0 else 'despesas'
                    table_name = f"jv_{transaction_type}"

                    # Insere transações no banco
                    cursor.execute(f"""
                        INSERT INTO {table_name} (id, account_id, descricao, valor, data, categoria)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        valor = VALUES(valor),
                        categoria = VALUES(categoria)
                    """, (
                        user_id,
                        account_id,
                        transaction['description'],
                        abs(amount),
                        transaction['date'],
                        transaction.get('category', 'Outros')
                    ))

                    synced_transactions.append({
                        'account_id': account_id,
                        'description': transaction['description'],
                        'amount': amount,
                        'date': transaction['date'],
                        'category': transaction.get('category', 'Outros')
                    })

        mysql.connection.commit()
        cursor.close()
        return jsonify({'status': 'success', 'data': synced_transactions, 'message': 'Transações sincronizadas com sucesso!'}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Erro interno: {str(e)}'}), 500

    

# Rota para atualizar transações
@app.route('/update_transactions/<item_id>', methods=['POST'])
def update_transactions(item_id):
    if 'loggedin' in session:
        try:
            client = pluggy_client()
            
            # Buscar novas transações
            transactions = client.fetch_transactions(item_id)
            
            # Processar e salvar as transações no banco de dados
            cursor = mysql.connection.cursor()
            
            for transaction in transactions:
                if transaction.amount > 0:
                    # É uma receita
                    cursor.execute("""
                        INSERT INTO jv_receitas (id, descricao_rec, valor_rec, data_rec, categoria)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        valor_rec = VALUES(valor_rec),
                        categoria = VALUES(categoria)
                    """, (
                        session['id'],
                        transaction.description,
                        transaction.amount,
                        transaction.date,
                        transaction.category
                    ))
                else:
                    # É uma despesa
                    cursor.execute("""
                        INSERT INTO jv_despesas (id, descricao_des, valor_des, data_des, categoria)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        valor_des = VALUES(valor_des),
                        categoria = VALUES(categoria)
                    """, (
                        session['id'],
                        transaction.description,
                        abs(transaction.amount),
                        transaction.date,
                        transaction.category
                    ))
            
            mysql.connection.commit()
            cursor.close()
            
            return jsonify({'success': True, 'message': 'Transações atualizadas com sucesso'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Unauthorized'}), 401

# Rota para buscar estatísticas das conexões
@app.route('/connection_stats') 
def connection_stats(): 
    if 'loggedin' in session: 
        try: 
            headers = {"X-API-KEY": pluggy_client.access_token} 
            items_response = requests.get( 
                f"{pluggy_client.BASE_URL}/items",  # Corrigido para usar BASE_URL 
                headers=headers 
            ) 
            items = items_response.json().get('results', []) 

            stats = { 
                'total_connections': len(items), 
                'active_connections': sum(1 for item in items if item['status'] == 'LOGIN_SUCCESS'), 
                'last_sync': max((item['updatedAt'] for item in items), default=None), 
                'connections': [] 
            } 

            for item in items: 
                connector_response = requests.get( 
                    f"{pluggy_client.BASE_URL}/connectors/{item['connectorId']}", 
                    headers=headers 
                ) 
                connector = connector_response.json() 
                stats['connections'].append({ 
                    'bank_name': connector['name'], 
                    'status': item['status'], 
                    'last_updated': item['updatedAt'], 
                    'error': item.get('error', None) 
                }) 

            return jsonify(stats) 
        except Exception as e: 
            return jsonify({'error': str(e)}), 500 
    return jsonify({'error': 'Unauthorized'}), 401 

@app.route('/validate_mfa/<item_id>', methods=['POST'])
def validate_mfa(item_id):
    try:
        mfa_token = request.json.get('token')
        if not mfa_token:
            return jsonify({
                "status": "error",
                "message": "Token MFA é obrigatório"
            }), 400

        headers = {"X-API-KEY": pluggy_client.access_token}
        response = requests.post(
            f"{pluggy_client.base_url}/items/{item_id}/mfa", 
            headers=headers,
            json={"token": mfa_token}
        )
        
        return jsonify({
            "status": "success",
            "result": response.json()
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route('/connectors')
def get_connectors():
    try:
        connectors = pluggy_client.list_connectors()
        return jsonify(connectors)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/test_connection')
def test_connection():
    try:
        # Tenta obter o token de acesso
        access_token = pluggy_client.access_token
        
        # Tenta listar os conectores (primeira página)
        connectors_response = pluggy_client.list_connectors(page=1, page_size=5)
        
        return jsonify({
            "status": "success",
            "message": "Conexão com Pluggy bem-sucedida",
            "access_token": access_token,
            "page_info": {
                "current_page": connectors_response.get('page'),
                "total_pages": connectors_response.get('totalPages'),
                "total_items": connectors_response.get('total')
            },
            "connectors": connectors_response.get('results', [])
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Erro ao conectar com Pluggy",
            "error": str(e)
        }), 500
    
@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        event = request.json
        
        if event['event'] == 'item/created':
            # Processar novo item criado
            item_id = event['item']['id']
            sync_transactions(item_id)
        
        elif event['event'] == 'item/updated':
            # Processar item atualizado
            item_id = event['item']['id']
            sync_transactions(item_id)
        
        elif event['event'] == 'item/deleted':
            # Processar item removido
            pass
        
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/open_finance')
def open_finance():
    if 'loggedin' in session:
        return render_template('open_finance.html')
    return redirect(url_for('login'))

# ============================== CLASSES ===============================

class Despesa:
    def __init__(self, id_des, id, descricao_des, valor_des, data_des):
        self.id_des = id_des
        self.id = id
        self.descricao_des = descricao_des
        self.valor_des = valor_des
        self.data_des = data_des

    @classmethod
    def get_all(cls):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM jv_despesas")
        despesas = cursor.fetchall()
        cursor.close()
        return [cls(**despesa) for despesa in despesas]

class Receita:
    def __init__(self, id_rec, id, descricao_rec, valor_rec, data_rec):
        self.id_rec = id_rec
        self.id = id
        self.descricao_rec = descricao_rec
        self.valor_rec = valor_rec
        self.data_rec = data_rec

    @classmethod
    def get_all(cls):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM jv_receitas")
        receitas = cursor.fetchall()
        cursor.close()
        return [cls(**receita) for receita in receitas]


# ============================== CHAMADA DO APP ==============================
if __name__ == '__main__':
    # Configurações de segurança adicionais
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)