document.addEventListener('DOMContentLoaded', function() {
  
    // Selecionar os elementos
    var receitaBtn = document.getElementById('receitaBtn');
    var despesaBtn = document.getElementById('despesaBtn');
    var receitaModal = document.getElementById('receitaModal');
    var despesaModal = document.getElementById('despesaModal');
    var closeButtons = document.getElementsByClassName('close');
  
  
    // Função para abrir modal
    function openModal(modal) {
        console.log("Opening modal:", modal);
        if (modal) {
            modal.style.display = 'block';
        } else {
            console.error("Modal is null");
        }
    }
  
    // Função para fechar modal
    function closeModal(modal) {
        console.log("Closing modal:", modal);
        if (modal) {
            modal.style.display = 'none';
        } else {
            console.error("Modal is null");
        }
    }
  
    // Event listener para o botão de receita
    if (receitaBtn) {
        receitaBtn.addEventListener('click', function() {
            console.log("Receita button clicked");
            openModal(receitaModal);
        });
    } else {
        console.error("Receita button not found");
    }
  
    // Event listener para o botão de despesa
    if (despesaBtn) {
        despesaBtn.addEventListener('click', function() {
            console.log("Despesa button clicked");
            openModal(despesaModal);
        });
    } else {
        console.error("Despesa button not found");
    }
  
    // Event listeners para os botões de fechar
    Array.from(closeButtons).forEach(function(button) {
        button.addEventListener('click', function() {
            closeModal(this.closest('.modal'));
        });
    });
  
    // Fechar o modal se clicar fora dele
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            closeModal(event.target);
        }
    });
  });

  document.addEventListener("DOMContentLoaded", function() {
    const inputPergunta = document.getElementById("input-pergunta");
    const respostaArea = document.getElementById("resposta-area");
    const btnPergunta = document.getElementById("btn-pergunta");
    const sugestoesContainer = document.getElementById("sugestoes");
    const graficoContainer = document.getElementById("grafico-container"); // Contêiner do gráfico

    // Sugestões pré-definidas
    const sugestoes = [
        'Exiba o gasto obtido pela categoria "Transporte"',
        'Qual foi a receita total do mês passado?',
        'Mostre as despesas do último ano',
        'Mostre as despesas do último mês',
        'Mostre o gasto mensal por categoria',
        'Qual é a previsão de gastos para os próximos 30 dias?',
        'Quais sao as maiores despesas',
        'Quais sao as maiores receitas'
    ];

    // Função para mostrar sugestões
    inputPergunta.addEventListener("input", function() {
        const valorAtual = inputPergunta.value.toLowerCase();
        sugestoesContainer.innerHTML = ''; // Limpa sugestões anteriores
        sugestoesContainer.style.display = 'none'; // Oculta as sugestões inicialmente

        if (valorAtual) {
            const listaSugestoes = sugestoes.filter(sugestao => sugestao.toLowerCase().includes(valorAtual));
            
            listaSugestoes.forEach(sugestao => {
                const divSugestao = document.createElement('div');
                divSugestao.classList.add('sugestao-item');
                divSugestao.textContent = sugestao;
                
                 // Adiciona um evento de clique para preencher o input com a sugestão
                divSugestao.addEventListener('click', function() {
                    inputPergunta.value = sugestao; // Preenche o input com a sugestão
                    sugestoesContainer.innerHTML = ''; // Limpa as sugestões
                    sugestoesContainer.style.display = 'none'; // Oculta as sugestões
                });

                sugestoesContainer.appendChild(divSugestao);
            });

            if (listaSugestoes.length > 0) {
                sugestoesContainer.style.display = 'block'; // Mostra as sugestões se houver
            }
        }
    });

    // Enviar consulta ao backend
    btnPergunta.addEventListener("click", function() {
        const pergunta = inputPergunta.value;

        // Chamar a rota do backend
        fetch('/iq', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ pergunta })
        })
        .then(response => response.json())
        .then(data => {
            respostaArea.innerHTML = data.resposta; // Exibe a resposta na área

            // Limpar campos de input e sugestões
            inputPergunta.value = '';
            sugestoesContainer.innerHTML = '';
            sugestoesContainer.style.display = 'none';

            // Verificar se o gráfico foi retornado
            if (data.grafico) {
                const { x, y, type, title } = data.grafico;

                // Layout para o gráfico
                const layout = {
                    title: title,
                    xaxis: { title: "Meses" },
                    yaxis: { title: "Valor (R$)", tickformat: "R$,.2f" }, // Formatar os valores em R$
                    template: "plotly_dark" // Usar tema dark
                };

                // Plotando o gráfico
                Plotly.newPlot(graficoContainer, [{
                    x: x,
                    y: y,
                    type: type,
                    marker: { color: 'orange' } // Definindo cor do gráfico
                }], layout);
            } else {
                graficoContainer.innerHTML = ''; // Limpar o gráfico caso não haja resposta gráfica
            }
        })
        .catch(error => {
            console.error('Erro:', error);
        });
    });
});