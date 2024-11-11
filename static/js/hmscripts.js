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

 