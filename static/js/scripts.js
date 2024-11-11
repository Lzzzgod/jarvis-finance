let carouselIndex = 0;
let carouselItems = document.querySelectorAll('.carousel-item');
let dots = document.querySelectorAll('.dot');

// Inicializar Carrosel
carouselItems[carouselIndex].classList.add('active');
dots[carouselIndex].classList.add('active');

// Listener dots
dots.forEach((dot, index) => {
  dot.addEventListener('click', () => {
    carouselIndex = index;
    updateCarousel();
  });
});

// Atualizar a função do carrosel
function updateCarousel() {
  carouselItems.forEach((item) => item.classList.remove('active'));
  dots.forEach((dot) => dot.classList.remove('active'));
  carouselItems[carouselIndex].classList.add('active');
  dots[carouselIndex].classList.add('active');
}

// Auto play carrosel
setInterval(() => {
  carouselIndex = (carouselIndex + 1) % carouselItems.length;
  updateCarousel();
}, 3000);

$(document).ready(function() {
  $('#telefone').mask('(00) 00000-0000');
});

