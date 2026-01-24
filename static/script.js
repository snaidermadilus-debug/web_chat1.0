const socket = io({
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  transports: ['polling']
});

// Estado
const appState = {
  currentGroup: '',
  currentUser: '',
  sessionToken: '',
  deviceId: '',
  isPrivate: false,
  heartbeatInterval: null
};

// Gerar Device ID
function getDeviceId() {
  let deviceId = localStorage.getItem('chat_device_id');
  if (!deviceId) {
    deviceId = 'device_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    localStorage.setItem('chat_device_id', deviceId);
  }
  return deviceId;
}

// Inicialização
document.addEventListener('DOMContentLoaded', () => {
  appState.deviceId = getDeviceId();
  console.log('Device ID:', appState.deviceId);
  
  setupEventListeners();
  restoreSession();
  
  // Botão Começar na tela inicial
  const btnStart = document.querySelector('.btn-start');
  if (btnStart) {
    btnStart.addEventListener('click', showAuthOptions);
  }
});

// Listeners
function setupEventListeners() {
  socket.on('connect', () => {
    console.log('✅ Conectado');
    showMessage('Conectado', 'success');
  });
  
  socket.on('disconnect', () => {
    console.log('❌ Desconectado');
    stopHeartbeat();
  });
  
  socket.on('group_result', handleGroupResult);
  socket.on('receive_message', handleNewMessage);
  socket.on('user_count_update', handleUserCountUpdate);
  socket.on('recovery_result', handleRecoveryResult);
  socket.on('recovery_verified', handleRecoveryVerified);
  socket.on('left_group', handleLeftGroup);
  
  // Input de mensagem
  const messageInput = document.getElementById('message-input');
  if (messageInput) {
    messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        sendMessage();
      }
    });
  }
}

// Heartbeat
function startHeartbeat() {
  if (appState.heartbeatInterval) clearInterval(appState.heartbeatInterval);
  
  appState.heartbeatInterval = setInterval(() => {
    if (appState.currentGroup && appState.sessionToken && socket.connected) {
      socket.emit('heartbeat', {
        session_token: appState.sessionToken,
        device_id: appState.deviceId
      });
    }
  }, 30000);
}

function stopHeartbeat() {
  if (appState.heartbeatInterval) {
    clearInterval(appState.heartbeatInterval);
    appState.heartbeatInterval = null;
  }
}

// Handlers
function handleGroupResult(data) {
  if (!data.success) {
    showMessage(data.msg, 'error');
    return;
  }
  
  appState.currentGroup = data.grupo_id;
  appState.currentUser = data.usuario;
  appState.sessionToken = data.session_token;
  appState.isPrivate = data.is_private || false;
  
  if (data.device_id) {
    appState.deviceId = data.device_id;
  }
  
  saveSession();
  showChatScreen();
  updateHeader();
  
  if (data.historico && data.historico.length > 0) {
    loadHistory(data.historico);
  }
  
  showMessage(data.message || 'Conectado!', 'success');
  startHeartbeat();
}

function handleNewMessage(data) {
  if (data.grupo_id !== appState.currentGroup) return;
  
  addMessageToChat(data.usuario, data.msg, data.timestamp);
  
  setTimeout(() => {
    const chat = document.getElementById('chat-messages');
    if (chat) chat.scrollTop = chat.scrollHeight;
  }, 100);
}

function handleUserCountUpdate(data) {
  if (data.grupo_id === appState.currentGroup) {
    updateUserCount(data.count);
  }
}

function handleRecoveryResult(data) {
  if (!data.success) {
    showMessage(data.msg, 'error');
    return;
  }
  
  const resultEl = document.getElementById('recovery-result');
  if (resultEl) {
    resultEl.innerHTML = `<div class="token-display">
      <strong>✅ Token:</strong><br>
      <div class="token-value">${data.token}</div>
      <small>Expira em 5 minutos</small>
    </div>`;
  }
  
  const tokenSection = document.getElementById('token-section');
  if (tokenSection) tokenSection.style.display = 'block';
}

function handleRecoveryVerified(data) {
  if (!data.success) {
    showMessage(data.msg, 'error');
    return;
  }
  
  appState.currentGroup = data.grupo_id;
  appState.currentUser = data.usuario;
  appState.sessionToken = data.session_token;
  appState.deviceId = data.device_id;
  
  saveSession();
  
  socket.emit('join_group', {
    grupo_id: appState.currentGroup,
    usuario: appState.currentUser,
    session_token: appState.sessionToken,
    device_id: appState.deviceId
  });
}

function handleLeftGroup(data) {
  if (data.success) {
    resetChat();
    showAuthOptions();
    showMessage(data.message || 'Você saiu', 'info');
  }
}

// ========== FUNÇÕES DE NAVEGAÇÃO (TODOS OS BOTÕES) ==========

function showAuthOptions() {
  hideAllScreens();
  document.getElementById('auth-options').style.display = 'block';
  stopHeartbeat();
}

function showCreateForm() {
  hideAllScreens();
  document.getElementById('create-form').style.display = 'block';
}

function showJoinForm() {
  hideAllScreens();
  document.getElementById('join-form').style.display = 'block';
}

function showRecoveryForm() {
  hideAllScreens();
  document.getElementById('recovery-form').style.display = 'block';
}

function showChatScreen() {
  hideAllScreens();
  const chatContainer = document.getElementById('chat-container');
  if (chatContainer) {
    chatContainer.style.display = 'flex';
    chatContainer.style.cssText = `
      display: flex !important;
      height: 100vh !important;
      width: 100vw !important;
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      bottom: 0 !important;
      z-index: 1000 !important;
      background: #121212 !important;
    `;
  }
}

function hideAllScreens() {
  const screens = [
    'server-screen',
    'auth-options',
    'create-form',
    'join-form',
    'recovery-form',
    'chat-container'
  ];
  
  screens.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.style.display = 'none';
      if (id === 'chat-container') {
        el.removeAttribute('style');
      }
    }
  });
}

// BOTÕES DE VOLTAR (ESSENCIAIS)
function backToMain() {
  hideAllScreens();
  document.getElementById('server-screen').style.display = 'block';
}

function backToAuth() {
  hideAllScreens();
  document.getElementById('auth-options').style.display = 'block';
}

// ========== FUNÇÕES DE AÇÃO ==========

function createGroup() {
  const grupo = document.getElementById('create-grupo').value.trim();
  const nome = document.getElementById('create-nome').value.trim();
  const password = document.getElementById('create-password').value;
  const isPrivate = document.getElementById('create-private').checked;
  
  if (!grupo || !nome) {
    showMessage('Preencha os campos', 'error');
    return;
  }
  
  socket.emit('create_group', {
    grupo_id: grupo,
    usuario: nome,
    password: password,
    private: isPrivate,
    device_id: appState.deviceId
  });
}

function joinGroup() {
  const grupo = document.getElementById('join-grupo').value.trim();
  const nome = document.getElementById('join-nome').value.trim();
  const password = document.getElementById('join-password').value;
  
  if (!grupo || !nome) {
    showMessage('Preencha os campos', 'error');
    return;
  }
  
  socket.emit('join_group', {
    grupo_id: grupo,
    usuario: nome,
    password: password,
    session_token: appState.sessionToken,
    device_id: appState.deviceId
  });
}

function requestRecovery() {
  const grupo = document.getElementById('recover-grupo').value.trim();
  const nome = document.getElementById('recover-nome').value.trim();
  
  if (!grupo || !nome) {
    showMessage('Preencha os campos', 'error');
    return;
  }
  
  socket.emit('request_recovery', {
    grupo_id: grupo,
    usuario: nome,
    device_id: appState.deviceId
  });
}

function verifyRecovery() {
  const token = document.getElementById('recover-token').value.trim();
  const grupo = document.getElementById('recover-grupo').value.trim();
  const nome = document.getElementById('recover-nome').value.trim();
  
  if (!token || !grupo || !nome) {
    showMessage('Preencha todos os campos', 'error');
    return;
  }
  
  socket.emit('verify_recovery', {
    token: token,
    grupo_id: grupo,
    usuario: nome,
    device_id: appState.deviceId
  });
}

function sendMessage() {
  const input = document.getElementById('message-input');
  if (!input) return;
  
  const msg = input.value.trim();
  if (!msg) return;
  
  socket.emit('send_message', {
    grupo_id: appState.currentGroup,
    usuario: appState.currentUser,
    session_token: appState.sessionToken,
    device_id: appState.deviceId,
    msg: msg
  });
  
  input.value = '';
  input.focus();
}

function addMessageToChat(usuario, msg, timestamp) {
  const chat = document.getElementById('chat-messages');
  if (!chat) return;
  
  const isMe = usuario === appState.currentUser;
  const messageElement = document.createElement('div');
  messageElement.className = `message ${isMe ? 'me' : 'other'}`;
  
  const time = formatTime(timestamp);
  messageElement.innerHTML = `
    <div class="message-sender">${escapeHtml(usuario)}${isMe ? ' (você)' : ''}</div>
    <div class="message-content">${escapeHtml(msg)}</div>
    <div class="message-time">${time}</div>
  `;
  
  chat.appendChild(messageElement);
}

function loadHistory(history) {
  const chat = document.getElementById('chat-messages');
  if (!chat) return;
  
  chat.innerHTML = '';
  history.forEach(item => {
    addMessageToChat(item.user, item.msg, item.time);
  });
}

function leaveGroup() {
  if (!appState.currentGroup) return;
  
  if (confirm('Sair do grupo?')) {
    socket.emit('leave_group', {
      grupo_id: appState.currentGroup,
      session_token: appState.sessionToken,
      device_id: appState.deviceId
    });
  }
}

function resetChat() {
  appState.currentGroup = '';
  appState.currentUser = '';
  appState.sessionToken = '';
  appState.isPrivate = false;
  
  const chat = document.getElementById('chat-messages');
  if (chat) chat.innerHTML = '';
  
  localStorage.removeItem('chat_session');
  stopHeartbeat();
}

function updateHeader() {
  const grupoEl = document.getElementById('header-grupo');
  const userEl = document.getElementById('header-user');
  
  if (grupoEl) grupoEl.textContent = appState.currentGroup;
  if (userEl) userEl.textContent = appState.currentUser;
}

function updateUserCount(count) {
  const countEl = document.getElementById('header-count');
  if (countEl) countEl.textContent = `● ${count} online`;
}

// Session
function saveSession() {
  localStorage.setItem('chat_session', JSON.stringify({
    grupo_id: appState.currentGroup,
    usuario: appState.currentUser,
    session_token: appState.sessionToken,
    device_id: appState.deviceId,
    timestamp: Date.now()
  }));
}

function restoreSession() {
  try {
    const saved = localStorage.getItem('chat_session');
    if (saved) {
      const data = JSON.parse(saved);
      const age = Date.now() - data.timestamp;
      
      if (age < 24 * 60 * 60 * 1000) {
        appState.currentGroup = data.grupo_id;
        appState.currentUser = data.usuario;
        appState.sessionToken = data.session_token;
        appState.deviceId = data.device_id || getDeviceId();
        
        showAuthOptions();
      } else {
        localStorage.removeItem('chat_session');
      }
    }
  } catch (e) {
    localStorage.removeItem('chat_session');
  }
}

// Utils
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatTime(timestamp) {
  try {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('pt-BR', { 
      hour: '2-digit', 
      minute: '2-digit',
      hour12: false
    });
  } catch (e) {
    return '--:--';
  }
}

function showMessage(msg, type = 'info') {
  const errorEl = document.getElementById('auth-error');
  if (errorEl) {
    errorEl.textContent = msg;
    errorEl.style.display = 'block';
    errorEl.style.color = type === 'error' ? '#e53e3e' : 
                         type === 'success' ? '#38a169' : '#4299e1';
    
    setTimeout(() => {
      errorEl.style.display = 'none';
    }, 5000);
  }
}

console.log('💬 Chat carregado - Todos os botões funcionando!');
