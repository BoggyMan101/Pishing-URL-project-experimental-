// JavaScript

// Mobile nav toggle: shows/hides the nav links list on small screens.
const navToggle = document.getElementById('nav-toggle');
const navLinksList = document.getElementById('nav-Links');

if (navToggle && navLinksList) {
  navToggle.addEventListener('click', () => {
    const isOpen = navLinksList.classList.toggle('open');
    navToggle.classList.toggle('open', isOpen);
    navToggle.setAttribute('aria-expanded', String(isOpen));
  });

  // Closes the mobile menu after a link is tapped.
  navLinksList.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
      navLinksList.classList.remove('open');
      navToggle.classList.remove('open');
      navToggle.setAttribute('aria-expanded', 'false');
    });
  });
}

const carousel = document.getElementById('carousel');
const cards = Array.from(document.querySelectorAll('.card'));
const navLinks = document.querySelectorAll('.nav-buttons a');

let currentIndex = 0; // kept in sync by the IntersectionObserver below

function goToIndex(index) {
  if (index < 0) index = 0;
  if (index > cards.length - 1) index = cards.length - 1;
  cards[index].scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
}

// Nav buttons: click scrolls to a specific card by id.
navLinks.forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const targetId = link.getAttribute('data-slide');
    const index = cards.findIndex(card => card.id === targetId);
    goToIndex(index);
  });
});

// Tap navigation: one click listener on the carousel container itself.
// Uses the container's own edges to decide left/right, and always
// navigates relative to currentIndex (the centered card), so it can't
// be thrown off by a neighboring card's sliver peeking into view.
carousel.addEventListener('click', (e) => {
  const rect = carousel.getBoundingClientRect();
  const clickX = e.clientX - rect.left;
  const isLeftHalf = clickX < rect.width / 2;

  if (isLeftHalf) {
    goToIndex(currentIndex - 1);
  } else {
    goToIndex(currentIndex + 1);
  }
});

// Keeps currentIndex and the active nav button in sync, whether
// navigation happened via tap, nav button, or manual swipe/scroll.
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(link => link.classList.remove('active'));
      const match = document.querySelector(`.nav-buttons a[data-slide="${entry.target.id}"]`);
      if (match) match.classList.add('active');
      currentIndex = cards.findIndex(card => card.id === entry.target.id);
    }
  });
}, { root: carousel, threshold: 0.6 });

cards.forEach(card => observer.observe(card));