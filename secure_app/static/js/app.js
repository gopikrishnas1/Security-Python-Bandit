(function () {
  'use strict';

  // Short DOM selectors for convenience
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  /* Flash auto-dismiss */
  const flashBox = $('.flash-stack') || $('.flash-wrap');
  if (flashBox) setTimeout(() => flashBox.remove(), 4500);

  /* data-confirm (delegated) */
  function askConfirm(el) {
    const msg = el.getAttribute('data-confirm') || 'Are you sure?';
    return window.confirm(msg);
  }

  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-confirm]');
    if (!el) return;
    if (!askConfirm(el)) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, { capture: true });

  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (form.matches('[data-confirm]') && !askConfirm(form)) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }
  }, { capture: true });

  /* confirmDelete(formId) */
  window.confirmDelete = function (formId, message) {
    const form = document.getElementById(formId);
    if (!form) return false;
    if (window.confirm(message || 'Are you sure you want to delete this item? This cannot be undone.')) {
      form.submit();
    }
    return false;
  };

  /* Prevent double submits */
  document.addEventListener('submit', (e) => {
    const form = e.target;
    $$("button[type='submit'],input[type='submit']", form).forEach((btn) => {
      if (btn.disabled) return;
      btn.disabled = true;
      if (!btn.dataset.loadingSet) {
        btn.dataset.originalText = btn.textContent || '';
        btn.textContent = (btn.dataset.originalText || 'Working') + '…';
        btn.dataset.loadingSet = '1';
      }
    });
  }, { once: false });

  /* Image upload validate + preview */
  const ACCEPT = ['.jpg', '.jpeg', '.png', '.gif'];
  const MAX_BYTES = 2 * 1024 * 1024; // 2 MB

  // CHANGED: use Data URL (allowed by CSP img-src 'self' data:) 
  function validateAndPreview(input) {
    const file = input.files && input.files[0];
    const preview = document.getElementById('imgPreview');
    if (!preview) return;

    if (!file) {
      preview.removeAttribute('src');
      preview.style.display = 'none';
      return;
    }

    const ext = ('.' + (file.name.split('.').pop() || '')).toLowerCase();
    if (!ACCEPT.includes(ext)) {
      alert('Invalid file type. Allowed: JPG, PNG, GIF.');
      input.value = '';
      preview.style.display = 'none';
      return;
    }

    if (file.size > MAX_BYTES) {
      alert('File too large. Max 2MB.');
      input.value = '';
      preview.style.display = 'none';
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      preview.src = e.target.result;   
      preview.style.display = 'block';
    };
    reader.onerror = () => {
      input.value = '';
      preview.removeAttribute('src');
      preview.style.display = 'none';
    };
    reader.readAsDataURL(file);
  }

  document.addEventListener('DOMContentLoaded', () => {
    $$("input[type='file'][name='image']").forEach((inp) => {
      inp.addEventListener('change', () => validateAndPreview(inp));
    });
  });

  /* Quantity input clamping */
  function clampNumberInput(inp) {
    const min = inp.hasAttribute('min') ? parseInt(inp.getAttribute('min'), 10) : 0;
    const max = inp.hasAttribute('max') ? parseInt(inp.getAttribute('max'), 10) : null;
    let val = parseInt(inp.value || '', 10);
    if (Number.isNaN(val)) val = min;
    if (max !== null && !Number.isNaN(max)) val = Math.min(val, max);
    inp.value = Math.max(min, val);
  }

  $$("input[type='number'][name='qty'], input[type='number'][name='quantity']").forEach((inp) => {
    ['input', 'blur'].forEach(ev => inp.addEventListener(ev, () => clampNumberInput(inp)));
  });

  /* OTP input: digits only, 6 max */
  const otp = $("input[name='otp']");
  if (otp) otp.addEventListener('input', () => {
    otp.value = otp.value.replace(/\D+/g, '').slice(0, 6);
  });

  /* Remember last search query */
  const search = $("form.search input[name='q']");
  if (search) {
    const KEY = 'secureapp:lastSearch';
    if (!search.value) {
      const saved = localStorage.getItem(KEY);
      if (saved) search.value = saved;
    }
    search.addEventListener('change', () => localStorage.setItem(KEY, search.value));
  }

  /* Auth pages: show/hide + password match + OTP */
  $$('[data-toggle]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-toggle');
      const input = document.getElementById(id);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      btn.textContent = input.type === 'password' ? 'Show' : 'Hide';
      input.focus();
    });
  });

  const pass = $('#reg-pass');
  const conf = $('#reg-confirm');
  const hint = $('#pw-match');
  function checkMatch() {
    if (!pass || !conf || !hint) return;
    const mismatch = conf.value.length > 0 && pass.value !== conf.value;
    hint.style.display = mismatch ? '' : 'none';
  }
  if (pass && conf) {
    pass.addEventListener('input', checkMatch);
    conf.addEventListener('input', checkMatch);
  }

  const otpInput = $('#otp');
  const otpForm = $('#otp-form');
  if (otpInput) {
    otpInput.addEventListener('input', () => {
      const v = otpInput.value.replace(/\D+/g, '').slice(0, 6);
      if (otpInput.value !== v) otpInput.value = v;
      if (v.length === 6 && otpForm) otpForm.submit();
    });
    otpInput.focus();
  }

  function guard(formId, btnId) {
    const f = document.getElementById(formId);
    const b = document.getElementById(btnId);
    if (!f || !b) return;
    f.addEventListener('submit', () => {
      b.disabled = true;
      b.textContent = b.textContent.replace(/\u2026|\.+$/, '') + '…';
    });
  }
  guard('login-form', 'login-submit');
  guard('reg-form', 'reg-submit');
  guard('otp-form', 'otp-submit');

  /* Profile page: copy 2FA key to clipboard */
  document.addEventListener('DOMContentLoaded', () => {
    const copyBtn = document.getElementById('copy-key');
    const keyEl   = document.getElementById('b32-key');

    if (!copyBtn || !keyEl) return;

    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText((keyEl.textContent || '').trim());
        const oldText = copyBtn.textContent;
        copyBtn.textContent = 'Copied';
        setTimeout(() => { copyBtn.textContent = oldText; }, 900);
      } catch (err) {
        alert('Copy failed');
      }
    });
  });

  /* Admin Audit Page: JSON pretty print + Copy SID */
  document.addEventListener('DOMContentLoaded', () => {
    // Pretty print JSON in <pre class="code-block meta">
    document.querySelectorAll('.code-block.meta').forEach((el) => {
      const raw = el.getAttribute('data-json') || '';
      try {
        el.textContent = JSON.stringify(JSON.parse(raw), null, 2);
      } catch (e) {
        el.textContent = raw;
      }
    });

    // Copy Session ID buttons
    document.querySelectorAll('.copy-btn').forEach((btn) => {
      btn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(btn.getAttribute('data-copy'));
          const oldText = btn.textContent;
          btn.textContent = 'Copied';
          setTimeout(() => (btn.textContent = oldText), 900);
        } catch (err) {
          alert('Copy failed');
        }
      });
    });
  });

})();
