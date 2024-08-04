document.addEventListener('DOMContentLoaded', () => {
    const slider = document.querySelector('.slider');
    const items = Array.from(slider.children);
    let currentIndex = 0;
  
    // Function to show a specific slide
    function showSlide(index) {
        slider.style.transform = `translateX(-${index * 100}%)`;
    }
  
    // Function to move to the next slide
    function nextSlide() {
        currentIndex = (currentIndex + 1) % items.length;
        showSlide(currentIndex);
        saveSlideIndex();
    }
  
    // Function to move to the previous slide
    function prevSlide() {
        currentIndex = (currentIndex - 1 + items.length) % items.length;
        showSlide(currentIndex);
        saveSlideIndex();
    }
  
    // Function to save the current slide index
    function saveSlideIndex() {
        localStorage.setItem('currentSlideIndex', currentIndex);
    }
  
    // Event listeners for next and previous buttons
    document.querySelector('.next').addEventListener('click', nextSlide);
    document.querySelector('.prev').addEventListener('click', prevSlide);
  
    // Restore the last viewed slide on page load
    const lastIndex = localStorage.getItem('currentSlideIndex');
    if (lastIndex !== null) {
        currentIndex = parseInt(lastIndex, 10);
        showSlide(currentIndex);
    } else {
        showSlide(currentIndex);
    }
  
    // Optional: Add touch swipe functionality
    let touchStartX = 0;
    let touchEndX = 0;
  
    slider.addEventListener('touchstart', e => {
        touchStartX = e.changedTouches[0].screenX;
    }, false);
  
    slider.addEventListener('touchend', e => {
        touchEndX = e.changedTouches[0].screenX;
        if (touchStartX - touchEndX > 50) {
            nextSlide();
        } else if (touchEndX - touchStartX > 50) {
            prevSlide();
        }
    }, false);
  
    // Store current index when navigating away
    const buttons = document.querySelectorAll('.button');
    buttons.forEach(button => {
        button.addEventListener('click', () => {
            saveSlideIndex();
        });
    });
  });