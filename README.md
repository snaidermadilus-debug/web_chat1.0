____________________________________
# Chat Grupal com Segurança Avançada

Este projeto é uma aplicação de chat em tempo real que roda em servidor local ou rede, permitindo comunicação entre múltiplos usuários diretamente pelo navegador, sem necessidade de aplicativos externos.

O sistema permite criar grupos de conversa públicos ou privados, com suporte a senha, sessões seguras e proteção contra uso indevido de nomes.

Funcionalidades principais:
- Chat em tempo real via navegador
- Criação de grupos públicos e privados
- Proteção de nomes por dispositivo
- Grupos com senha criptografada
- Sessões seguras com token
- Remoção automática de usuários inativos
- Recuperação de acesso por token temporário

Tecnologias utilizadas:
- Python
- Flask
- Flask-SocketIO
- HTML, CSS e JavaScript
- Banco de dados local (SQLite)


Co-authored-by: Nome <email>


```bash
git clone https://github.com/snaidermadilus-debug/web_chat1.0.git && cd web_chat1.0 && python -m pip install --upgrade pip && pip install Flask==2.3.3 Flask-SocketIO==5.3.4 bcrypt==4.0.1 python-socketio==5.9.0 && python app.py