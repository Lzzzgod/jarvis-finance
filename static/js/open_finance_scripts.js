document.getElementById('connectButton').addEventListener('click', () => {
    initializePluggyWidget();
});

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
            onSuccess: (itemData) => {
                console.log('Conexão bem-sucedida com Pluggy!', itemData);
            },
            onError: (error) => {
                console.error('Erro na conexão com Pluggy:', error);
            }
        });
        pluggyConnect.init();
    });
});