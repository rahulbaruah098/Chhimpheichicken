// Hamburger + overlay
const hamburger = document.querySelector('.hamburger');
const overlay = document.querySelector('.overlay');
if (hamburger) {
  hamburger.addEventListener('click', () => {
    const expanded = hamburger.classList.toggle('active');
    hamburger.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    if (expanded) { overlay.hidden = false; requestAnimationFrame(() => overlay.classList.add('show')); }
    else { overlay.classList.remove('show'); setTimeout(() => overlay.hidden = true, 300); }
  });
}
overlay?.addEventListener('click', (e) => { if (e.target.classList.contains('overlay')) hamburger?.click(); });
// Slider
const slider = document.querySelector('.slider');
if (slider) {
  const slides = Array.from(slider.querySelectorAll('.slide'));
  const btnPrev = slider.querySelector('.prev');
  const btnNext = slider.querySelector('.next');
  const dotsWrap = slider.querySelector('.dots');
  let idx = 0;
  slides.forEach((_, i) => { const b = document.createElement('button'); b.addEventListener('click', () => go(i)); dotsWrap.appendChild(b); });
  function go(n){
    slides[idx].classList.remove('is-active'); dotsWrap.children[idx].classList.remove('active');
    idx = (n + slides.length) % slides.length; const el = slides[idx];
    el.classList.add('is-active'); dotsWrap.children[idx].classList.add('active');
    slides.forEach(s => { const v = s.querySelector('video'); if (v) v.pause(); });
    const v = el.querySelector('video'); if (v) v.play().catch(()=>{});
  }
  go(0); btnPrev.addEventListener('click', () => go(idx-1)); btnNext.addEventListener('click', () => go(idx+1));
  let auto = setInterval(()=>go(idx+1), 5000);
  slider.addEventListener('mouseenter', ()=>clearInterval(auto));
  slider.addEventListener('mouseleave', ()=>auto = setInterval(()=>go(idx+1), 5000));
  const io = new IntersectionObserver(entries => { entries.forEach(e => { if (!e.isIntersecting) clearInterval(auto); else auto = setInterval(()=>go(idx+1), 5000); }); });
  io.observe(slider);
}
// Reveal on scroll
const reveals = document.querySelectorAll('.reveal');
const ro = new IntersectionObserver((entries, obs)=>{
  entries.forEach(e=>{ if (e.isIntersecting) { e.target.style.animationDelay = (Math.random()*0.2)+'s'; e.target.classList.add('in'); obs.unobserve(e.target);} });
},{threshold:.1});
reveals.forEach(el=>ro.observe(el));
// AJAX add-to-cart feedback
document.addEventListener('submit', async (e) => {
  const form = e.target;
  if (form.matches('form.cart-add')) {
    e.preventDefault();
    const fd = new FormData(form);
    const res = await fetch(form.action, { method: "POST", body: fd });
    const data = await res.json();
    alert(data.ok ? "Added to cart!" : (data.msg||"Failed"));
  }
});

// ✅ Handle "Remove" from cart via AJAX too
document.addEventListener('submit', async (e) => {
  const form = e.target;
  if (form.action.includes('/api/cart/remove')) {
    e.preventDefault();
    const fd = new FormData(form);
    const res = await fetch(form.action, { method: "POST", body: fd });
    const data = await res.json();
    if (data.ok) { 
      // reload page to show updated cart
      location.reload();
    } else {
      alert(data.msg || "Failed to remove item");
    }
  }
});
