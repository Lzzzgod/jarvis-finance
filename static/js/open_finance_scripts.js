function fetchConnectToken() {
    return fetch('/connect_token')
        .then(response => response.json())
        .then((data) => {
        console.log(data);  // Depuração
        if (data.accessToken) {
            return data.accessToken;  // Retorne o accessToken em vez de connect_token
        } else {
            throw new Error("Token não encontrado na resposta.");
        }
    })
        .catch((error) => console.error('Erro ao obter o connect token:', error));
}

document.getElementById('connectButton').addEventListener('click', () => {
    fetchConnectToken().then((connectToken) => {
        const pluggyConnect = new PluggyConnect({
            connectToken: connectToken,
            includeSandbox: true,
            allowConnectInBackground: true,
            products: ["IDENTITY", "ACCOUNTS", "TRANSACTIONS", "CREDIT_CARDS"],

            onSuccess: (itemData) => {
                console.log('Debug itemData:', itemData);
                
                // Prepara o JSON apenas com as informações necessárias
                const payload = {
                    id: itemData.item.id, // Extrai apenas o ID do item
                    connector_id: itemData.item.connector.id
                };
                console.log('Payload enviado:', payload);
                // Envia o JSON simplificado para o backend
                fetch('/create_item', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(payload), // Envia apenas o payload simplificado
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'error') {
                        alert('Erro: ' + data.message);
                    } else {
                        alert('Dados processados com sucesso!');
                    }
                })
                .catch(error => {
                    console.error('Erro ao enviar dados:', error);
                    alert('Erro ao enviar dados para o backend.');
                });
            },
            onError: (error) => {
                console.error('Erro na conexão com Pluggy:', error);
                alert('Erro na conexão com Pluggy: ' + error.message);
            },
        });

        pluggyConnect.init();
    });
});

//GET CONNECTED BANKS
// Função para exibir contas associadas a um banco

// Função para exibir contas associadas a um banco
function fetchAccountsForBank(item_id, container) {
    fetch(`/user_accounts`)  // Requisição para obter contas associadas ao usuário
        .then(response => response.json())
        .then(data => {
            console.log(data);  // Verificando se os dados estão corretos

            if (data.status === 'success' && Array.isArray(data.data)) {
                // Filtra as contas que pertencem ao item_id do banco atual
                const accounts = data.data.filter(account => account.item_id === item_id);
                console.log('Contas para o banco:', accounts); // Verificando as contas filtradas

                // Se existirem contas, separa em categorias
                const checkingAccounts = accounts.filter(account => account.type === 'BANK');  // Alterado para 'BANK' para contas correntes
                const creditCards = accounts.filter(account => account.type === 'CREDIT');  // Cartões de Crédito
                console.log('Contas Correntes:', checkingAccounts); // Verificando as contas correntes
                console.log('Cartões de Crédito:', creditCards); // Verificando os cartões de crédito

                // Criação dos containers separados para as contas correntes e cartões de crédito
                const bankContent = document.createElement('div');
                bankContent.className = 'bank-content';

                // Exibe contas correntes
                if (checkingAccounts.length > 0) {
                    const checkingContainer = document.createElement('div');
                    checkingContainer.className = 'checking-accounts-container';
                    checkingContainer.innerHTML = '<h5>Contas Correntes</h5>';

                    checkingAccounts.forEach(account => {
                        const accountItem = document.createElement('div');
                        accountItem.className = 'account-item';

                        // Verificando o saldo e o proprietário das contas correntes
                        const owner = account.owner || 'Proprietário Desconhecido';  // Caso o owner seja nulo
                        const balance = account.balance || 0.0;  // Caso o saldo seja nulo
                        const balanceFormatted = `${balance} `;

                        // Formatação das contas correntes
                        accountItem.innerHTML = `
                            <div class="account-header">
                                <span>${owner}</span>
                            </div>
                            <div class="account-details">
                                <p>Saldo: <strong>R$ ${balanceFormatted}</strong></p>
                            </div>
                        `;
                        checkingContainer.appendChild(accountItem);
                    });
                    bankContent.appendChild(checkingContainer);
                } else {
                    console.log('Nenhuma conta corrente encontrada');
                }

                // Exibe cartões de crédito
                if (creditCards.length > 0) {
                    const creditContainer = document.createElement('div');
                    creditContainer.className = 'credit-cards-container';
                    creditContainer.innerHTML = '<h5>Cartões de Crédito</h5>';

                    creditCards.forEach(account => {
                        const accountItem = document.createElement('div');
                        accountItem.className = 'account-item';

                        // Verificando o saldo e o proprietário dos cartões de crédito
                        const owner = account.owner || 'Proprietário Desconhecido';  // Caso o owner seja nulo
                        const balance = account.balance || 0.0;  // Caso o saldo seja nulo
                        const balanceFormatted = `${balance} `;

                        // Formatação dos cartões de crédito
                        accountItem.innerHTML = `
                            <div class="account-header">
                                <strong>${account.name}</strong>
                            </div>
                            <div class="account-details">
                                <p>Limite Disponível:<strong>R$ ${balanceFormatted}</strong></p>
                                <p><strong> ${account.creditData.brand || 'Desconhecida'}</strong></p>
                                <p><strong>${account.creditData.level || 'Nível desconhecido'}</strong> </p>
                            </div>
                        `;
                        creditContainer.appendChild(accountItem);
                    });
                    bankContent.appendChild(creditContainer);
                } else {
                    console.log('Nenhum cartão de crédito encontrado');
                }

                // Caso não haja contas ou cartões
                if (checkingAccounts.length === 0 && creditCards.length === 0) {
                    bankContent.innerHTML = '<p>Nenhuma conta ou cartão encontrado.</p>';
                }

                container.appendChild(bankContent);
            } else {
                container.innerHTML = '<p>Erro ao carregar as contas.</p>';
            }
        })
        .catch(error => {
            console.error('Erro ao buscar contas:', error);
            container.innerHTML = '<p>Erro ao carregar as contas.</p>';
        });
}

// Função para buscar os bancos conectados
function fetchConnectedBanks() {
    fetch('/connected_banks')  // Requisição para obter os bancos conectados
        .then(response => response.json())
        .then(data => {
            const bankList = document.getElementById('bankList');
            bankList.innerHTML = '';  // Limpa a lista antes de adicionar novos itens

            if (data.status === 'success' && Array.isArray(data.data)) {
                data.data.forEach(item => {
                    const bankItem = document.createElement('div');
                    bankItem.className = 'bank-item';

                    // Exibe logo e detalhes do banco
                    bankItem.innerHTML = `
                        <div class="bank-header">
                            <img src="${item.connector?.imageUrl || 'default_logo_url'}" 
                                 alt="${item.connector?.name || 'Banco Desconhecido'} Logo" 
                                 class="bank-logo" />
                            <h4>${item.connector?.name || 'Banco Desconhecido'}</h4>
                        </div>
                        <div class="accounts-list"></div>
                        <button class="delete-bank" onclick="deleteBank('${item.item_id}')">X</button>
                    `;

                    // Seleciona o container para exibir as contas
                    const accountsList = bankItem.querySelector('.accounts-list');

                    // Chama a função para exibir as contas associadas ao item
                    fetchAccountsForBank(item.item_id, accountsList);

                    // Adiciona o item à lista
                    bankList.appendChild(bankItem);
                });
            } else {
                bankList.innerHTML = `<p>Erro: Nenhum banco conectado encontrado.</p>`;
            }
        })
        .catch(error => {
            console.error('Erro ao buscar bancos conectados:', error);
            const bankList = document.getElementById('bankList');
            bankList.innerHTML = `<p>Erro ao carregar bancos conectados.</p>`;
        });
}
function deleteBank(item_id) {
    if (!confirm('Tem certeza de que deseja excluir este banco?')) {
        return; // Cancela a exclusão se o usuário não confirmar
    }

    fetch('/delete_bank', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item_id })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Banco removido com sucesso!');
                fetchConnectedBanks(); // Recarrega a lista de bancos
            } else {
                alert(`Erro ao remover banco: ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Erro ao deletar banco:', error);
            alert('Erro ao excluir banco. Por favor, tente novamente mais tarde.');
        });
}

function syncTransactions() {
    if (!confirm('Deseja sincronizar suas transações agora?')) {
        return; // Cancela a sincronização se o usuário não confirmar
    }

    fetch('/sync_transactions', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Transações sincronizadas com sucesso!');
                fetchConnectedBanks(); // Ou outra função para recarregar os dados, se necessário
            } else {
                alert(`Erro ao sincronizar transações: ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Erro ao sincronizar transações:', error);
            alert('Erro ao sincronizar transações. Por favor, tente novamente mais tarde.');
        });
}


// Chama a função ao carregar a página
document.addEventListener('DOMContentLoaded', () => {
    fetchConnectedBanks(); // Carrega os bancos conectados
    fetchAccountsForBank(); // Carrega as contas dos bancos
    syncTransactions(); // Sincroniza as transações ao carregar a página
});