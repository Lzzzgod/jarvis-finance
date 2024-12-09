# Jarvis Finance
**JARVIS: Just an Advisor for Reliable Income Strategies**

Bem-vindo à sua ferramenta de gerenciamento financeiro! Com este aplicativo, você pode acompanhar receitas, despesas, balanços financeiros e muito mais.  
Acesse o web app diretamente em: [https://jarvisfinance.xyz/](https://jarvisfinance.xyz/)

---

## Pré-requisitos
Antes de iniciar, certifique-se de ter o seguinte instalado em sua máquina:
- **Python 3.8+**
- **Pip** (gerenciador de pacotes do Python)
- **Virtualenv** (opcional, mas recomendado para criar um ambiente virtual isolado)
- **MySQL** (ou qualquer outro banco de dados compatível)

---

## Configuração do Ambiente

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/Lzzzgod/jarvis-finance
   cd jarvis-finance
   ```
2. **Crie um ambiente virtual (opcional, mas recomendado):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```
3. **Instale as dependências:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Configure o banco de dados:**
   - Crie um banco de dados MySQL com o nome de sua escolha.
   - Configure o arquivo `config.py` com suas credenciais de banco de dados. Exemplo:
     ```python
     DB_HOST = 'localhost'
     DB_USER = 'seu_usuario'
     DB_PASSWORD = 'sua_senha'
     DB_NAME = 'nome_do_banco'
     ```
5. **Inicialize o banco de dados:**
   Execute os scripts SQL fornecidos no repositório para criar as tabelas necessárias:
   ```bash
   mysql -u seu_usuario -p nome_do_banco < scripts/setup.sql
   ```
6. **Inicie o servidor Flask:**
   ```bash
   flask run
   ```
   Por padrão, a aplicação será acessível em: [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## Como usar

### Login e Cadastro
1. Acesse a aplicação pelo navegador no link: [http://127.0.0.1:5000](http://127.0.0.1:5000).
2. Faça login com suas credenciais ou cadastre-se na plataforma.

### Principais Funcionalidades
- **Dashboard**: Veja o resumo das receitas, despesas, balanço e saldo de contas conectadas.
- **Relatórios**: Acompanhe gráficos detalhados de fluxo de caixa e balanço mensal.
- **Previsões**: Analise projeções para os próximos 60 dias.
- **Extrato**: Consulte transações categorizadas em receitas e despesas.
- **Gestão de Contas**: Conecte-se a novas contas bancárias e gerencie contas existentes.

---

## Configuração do Ambiente de Produção

1. Instale um servidor WSGI como Gunicorn:
   ```bash
   pip install gunicorn
   ```
2. Configure um servidor web como **Nginx** para servir a aplicação.
3. Ajuste o arquivo `.env` com as variáveis de ambiente de produção (como chaves de API, banco de dados etc.).

---

## Contribuindo
Contribuições são bem-vindas! Siga os passos abaixo para contribuir:

1. Crie um fork do repositório.
2. Faça as alterações no código no seu fork.
3. Envie um pull request com uma descrição detalhada das mudanças.

---

## Licença
© 2024 Jarvis Advisor. Todos os direitos reservados.
