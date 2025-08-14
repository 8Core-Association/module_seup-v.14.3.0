/**
 * Plaćena licenca
 * (c) 2025 8Core Association
 * Tomislav Galić <tomislav@8core.hr>
 * Marko Šimunović <marko@8core.hr>
 * Web: https://8core.hr
 * Kontakt: info@8core.hr | Tel: +385 099 851 0717
 * Sva prava pridržana. Ovaj softver je vlasnički i zaštićen je autorskim i srodnim pravima 
 * te ga je izričito zabranjeno umnožavati, distribuirati, mijenjati, objavljivati ili 
 * na drugi način eksploatirati bez pismenog odobrenja autora.
 * U skladu sa Zakonom o autorskom pravu i srodnim pravima 
 * (NN 167/03, 79/07, 80/11, 125/17), a osobito člancima 32. (pravo na umnožavanje), 35. 
 * (pravo na preradu i distribuciju) i 76. (kaznene odredbe), 
 * svako neovlašteno umnožavanje ili prerada ovog softvera smatra se prekršajem. 
 * Prema Kaznenom zakonu (NN 125/11, 144/12, 56/15), članak 228., stavak 1., 
 * prekršitelj se može kazniti novčanom kaznom ili zatvorom do jedne godine, 
 * a sud može izreći i dodatne mjere oduzimanja protivpravne imovinske koristi.
 * Bilo kakve izmjene, prijevodi, integracije ili dijeljenje koda bez izričitog pismenog 
 * odobrenja autora smatraju se kršenjem ugovora i zakona te će se pravno sankcionirati. 
 * Za sva pitanja, zahtjeve za licenciranjem ili dodatne informacije obratite se na info@8core.hr.
 */

/**
 * SEUP Modern JavaScript Enhancement
 * Provides dynamic interactions and animations
 */

class SEUPModern {
  constructor() {
    this.init();
  }

  init() {
    this.setupIntersectionObserver();
    this.setupParallaxEffect();
    this.setupDynamicStats();
    this.setupKeyboardNavigation();
    this.setupLoadingStates();
    this.setupAccessibility();
  }

  // Intersection Observer for scroll animations
  setupIntersectionObserver() {
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('animate-fade-in-up');
          
          // Staggered animation for action cards
          if (entry.target.classList.contains('seup-action-card')) {
            const index = Array.from(entry.target.parentNode.children).indexOf(entry.target);
            entry.target.style.animationDelay = `${index * 150}ms`;
          }
        }
      });
    }, observerOptions);

    // Observe elements
    document.querySelectorAll('.seup-action-card, .seup-stats').forEach(el => {
      observer.observe(el);
    });
  }

  // Parallax effect for floating elements
  setupParallaxEffect() {
    const floatingElements = document.querySelectorAll('.seup-floating-element');
    
    window.addEventListener('scroll', () => {
      const scrolled = window.pageYOffset;
      const rate = scrolled * -0.5;
      
      floatingElements.forEach((element, index) => {
        const speed = (index + 1) * 0.3;
        element.style.transform = `translateY(${rate * speed}px)`;
      });
    });
  }

  // Dynamic stats counter
  setupDynamicStats() {
    // Use real stats from PHP
    const realStats = window.seupStats || {};
    const stats = [
      { element: '.stat-predmeti', target: realStats.predmeti || 0, suffix: '' },
      { element: '.stat-dokumenti', target: realStats.dokumenti || 0, suffix: '' },
      { element: '.stat-korisnici', target: realStats.korisnici || 0, suffix: '' },
      { element: '.stat-ustanove', target: realStats.ustanove || 0, suffix: '' }
    ];

    const animateCounter = (element, target, suffix = '') => {
      let current = 0;
      const increment = target / 100;
      const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
          current = target;
          clearInterval(timer);
        }
        element.textContent = Math.floor(current).toLocaleString('hr-HR') + suffix;
      }, 20);
    };

    // Trigger animation when stats section is visible
    const statsObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          stats.forEach(stat => {
            const element = document.querySelector(stat.element);
            if (element) {
              animateCounter(element, stat.target, stat.suffix);
            }
          });
          statsObserver.unobserve(entry.target);
        }
      });
    });

    const statsSection = document.querySelector('.seup-stats');
    if (statsSection) {
      statsObserver.observe(statsSection);
    }
  }

  // Keyboard navigation
  setupKeyboardNavigation() {
    const actionCards = document.querySelectorAll('.seup-action-card');
    
    actionCards.forEach((card, index) => {
      card.setAttribute('tabindex', '0');
      
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          card.click();
        }
        
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
          e.preventDefault();
          const nextCard = actionCards[index + 1] || actionCards[0];
          nextCard.focus();
        }
        
        if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
          e.preventDefault();
          const prevCard = actionCards[index - 1] || actionCards[actionCards.length - 1];
          prevCard.focus();
        }
      });
    });
  }

  // Loading states for navigation
  setupLoadingStates() {
    const actionCards = document.querySelectorAll('.seup-action-card');
    
    actionCards.forEach(card => {
      card.addEventListener('click', (e) => {
        // Add loading state
        card.classList.add('seup-loading');
        
        // Create loading overlay
        const loadingOverlay = document.createElement('div');
        loadingOverlay.className = 'seup-loading-overlay';
        loadingOverlay.innerHTML = `
          <div class="seup-spinner"></div>
          <span>Učitavanje...</span>
        `;
        card.appendChild(loadingOverlay);
        
        // Remove loading state after navigation (fallback)
        setTimeout(() => {
          card.classList.remove('seup-loading');
          if (loadingOverlay.parentNode) {
            loadingOverlay.remove();
          }
        }, 2000);
      });
    });
  }

  // Accessibility enhancements
  setupAccessibility() {
    // Add ARIA labels
    document.querySelectorAll('.seup-action-card').forEach((card, index) => {
      const title = card.querySelector('.seup-action-title')?.textContent;
      const description = card.querySelector('.seup-action-description')?.textContent;
      
      if (title && description) {
        card.setAttribute('aria-label', `${title}: ${description}`);
        card.setAttribute('role', 'button');
      }
    });

    // Announce page changes for screen readers
    const announcer = document.createElement('div');
    announcer.setAttribute('aria-live', 'polite');
    announcer.setAttribute('aria-atomic', 'true');
    announcer.className = 'sr-only';
    document.body.appendChild(announcer);

    // Focus management
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        document.body.classList.add('keyboard-navigation');
      }
    });

    document.addEventListener('mousedown', () => {
      document.body.classList.remove('keyboard-navigation');
    });
  }

  // Utility method for smooth scrolling
  smoothScrollTo(target) {
    const element = document.querySelector(target);
    if (element) {
      element.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });
    }
  }

  // Method to update stats dynamically
  updateStats(newStats) {
    Object.entries(newStats).forEach(([key, value]) => {
      const element = document.querySelector(`.stat-${key}`);
      if (element) {
        this.animateCounter(element, value);
      }
    });
  }

  // Performance monitoring
  measurePerformance() {
    if ('performance' in window) {
      window.addEventListener('load', () => {
        const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
        console.log(`SEUP Page Load Time: ${loadTime}ms`);
      });
    }
  }
}

// Additional CSS for loading states and accessibility
const additionalStyles = `
.seup-loading-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(255, 255, 255, 0.9);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-2xl);
  z-index: 10;
}

.seup-spinner {
  width: 32px;
  height: 32px;
  border: 3px solid var(--primary-200);
  border-top: 3px solid var(--primary-600);
`;

// Inject additional styles
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalStyles;
document.head.appendChild(styleSheet);

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new SEUPModern();
});

// Export for potential external use
window.SEUPModern = SEUPModern;