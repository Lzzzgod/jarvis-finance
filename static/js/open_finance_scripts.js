let selectedConnectorId = null;

// Inicializa a conexão com a API da Pluggy
async function initializeConnection() {
    try {
        const response = await fetch('/create_connect_token');
        const data = await response.json();
        if (data.status === 'success') {
            showConnectionModal();
            loadBanks();
        }
    } catch (error) {
        console.error('Erro ao inicializar conexão:', error);
    }
}

// Exibe o modal de conexão
function showConnectionModal() {
    document.getElementById('connectionModal').style.display = 'block';
}

// Exibe o modal de status
function showStatusModal() {
    document.getElementById('statusModal').style.display = 'block';
}

// Carrega os bancos da API da Pluggy
async function loadBanks() {
    try {
        const response = await fetch('/list_connectors');
        const data = await response.json();
        
        if (response.status === 401) {
            window.location.href = '/login';
            return;
        }

        if (data.status === 'success') {
            console.log(data.connectors); // Verifique os dados aqui
            displayBanks(data.connectors);
        } else {
            throw new Error(data.message || 'Erro ao carregar bancos');
        }
    } catch (error) {
        console.error('Erro ao carregar bancos:', error);
        const bankList = document.getElementById('bank-list');
        if (bankList) {
            bankList.innerHTML = `
                <div class="error-message">
                    Erro ao carregar lista de bancos. Por favor, tente novamente.
                </div>
            `;
        }
    }
}

function displayBanks(banks) {
    const bankList = document.getElementById('bank-list');
    if (bankList) {
        bankList.innerHTML = banks.map(bank => `
            <div class="bank-item" data-connector-id="${bank.id}" onclick="selectBank(this)">
                <img src="${bank.imageUrl}" alt="${bank.name}">
                <p>${bank.name}</p>
            </div>
        `).join('');
    } else {
        console.error('Elemento com ID "bank-list" não encontrado.');
    }
}

function selectBank(element) {
    // Remove a classe 'selected' de todos os itens
    document.querySelectorAll('.bank-item').forEach(item => {
        item.classList.remove('selected');
    });

    // Adiciona a classe 'selected' ao item clicado
    element.classList.add('selected');
    
    // Armazena o ID do conector selecionado
    selectedConnectorId = element.getAttribute('data-connector-id');

    // Mostra a seção de consentimento
    document.getElementById('consentStep').style.display = 'block';

    // Habilita o botão "Continuar" se um banco foi selecionado
    document.getElementById('nextStep').disabled = true; // Inicialmente desabilitado
}

// Adiciona evento de clique ao botão "Continuar"
document.getElementById('nextStep').addEventListener('click', function() {
    if (selectedConnectorId) {
        connectBank(selectedConnectorId);
    } else {
        alert('Por favor, selecione um banco antes de continuar.');
    }
});


// Função para conectar ao banco
async function connectBank(connectorId) {
    // Verifique se o checkbox de consentimento está marcado
    if (!document.getElementById('consentCheck').checked) {
        alert('Por favor, aceite os termos de uso e privacidade.');
        return;
    }

    try {
        const response = await fetch('/create_item', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                connectorId, 
                consentAccepted: document.getElementById('consentCheck').checked // Envia a escolha do consentimento
            })
        });
        const data = await response.json();
        console.log(data)
        if (data.status === 'success') {
            // Redireciona para o widget de conexão da Pluggy
            window.open(`https://api.pluggy.ai/connect?accessToken=${data.accessToken}`, '_blank');
            hideModals(); // Esconde os modais
        } else {
            alert('Erro ao criar a conexão: ' + data.message);
        }
    } catch (error) {
        console.error('Erro ao conectar banco:', error);
        hideModals(); // Esconde os modais em caso de erro
    }
}

// Sincroniza transações
async function syncTransactions(itemId) {
    try {
        const response = await fetch(`/sync_transactions/${itemId}`, {
            method: 'POST'
        });
        const data = await response.json();
        if (data.status === 'success') {
            console.log('Transações sincronizadas com sucesso');
        }
    } catch (error) {
        console.error('Erro ao sincronizar transações:', error);
    }
}

// Esconde todos os modais
function hideModals() {
    document.getElementById('connectionModal').style.display = 'none';
    document.getElementById('statusModal').style.display = 'none';
}

// Carrega os bancos conectados
async function loadConnectedBanks() {
    try {
        const response = await fetch('/get_connected_banks');
        const data = await response.json();
        
        if (data.error) {
            console.error('Erro ao carregar bancos conectados:', data.error);
            return;
        }

        const connectedBankList = document.getElementById('connected-bank-list');
        connectedBankList.innerHTML = data.map(bank => `
            <div class="connected-bank-item">
                <img src="${bank.imageUrl}" alt="${bank.name}">
                <p>${bank.name}</p>
                <button onclick="removeConnection('${bank.id}')">Remover</button>
            </div>
        `).join('');
    } catch (error) {
        console.error('Erro ao carregar bancos conectados:', error);
    }
}

// Remove uma conexão de banco
async function removeConnection(itemId) {
    if (confirm('Tem certeza que deseja remover esta conexão?')) {
        try {
            const response = await fetch(`/remove_connection/${itemId}`, {
                method: 'DELETE'
            });
            const data = await response.json();
            if (data.success) {
                loadConnectedBanks(); // Atualiza a lista de bancos conectados
            } else {
                alert('Erro ao remover a conexão: ' + data.error);
            }
        } catch (error) {
            console.error('Erro ao remover conexão:', error);
        }
    }
}

// Função para fechar o modal
function closeModal() {
    document.getElementById('connectionModal').style.display = 'none';
}

// Adiciona evento de clique ao botão de fechar
document.querySelector('.close').addEventListener('click', closeModal);

// Fechar o modal se clicar fora dele
window.addEventListener('click', function(event) {
    const modal = document.getElementById('connectionModal');
    if (event.target === modal) {
        closeModal();
    }
});

// Adiciona evento de clique ao checkbox de consentimento
document.getElementById('consentCheck').addEventListener('change', function() {
    // Habilita o botão "Continuar" se o checkbox estiver marcado
    document.getElementById('nextStep').disabled = !this.checked;
});

// Inicializa a conexão quando a página é carregada
document.addEventListener('DOMContentLoaded', initializeConnection);