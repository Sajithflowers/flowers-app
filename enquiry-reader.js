/* Reads a pasted WhatsApp enquiry and fills the existing enquiry fields.
   Rule-based: phone patterns, dates and occasion words. Anything unsure is
   returned with flag 'check' so the form shows it in amber. */
(function (root) {
  const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
  const DAYS = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
  const OCCASIONS = [
    ['Wedding', /\bwedding|bride|bridal|nikah\b/i],
    ['Engagement', /\bengagement|engaged\b/i],
    ['Proposal', /\bpropos(al|e)|marry me\b/i],
    ['Birthday', /\bbirthday|bday\b/i],
    ['Anniversary', /\banniversary\b/i],
    ['Baby Shower', /\bbaby ?shower|gender reveal\b/i],
    ['Workshop', /\bworkshop|masterclass|class\b/i],
    ['Corporate', /\boffice|corporate|opening ceremony|launch|company|conference\b/i],
    ['Graduation', /\bgraduation\b/i],
    ['Funeral', /\bfuneral|condolence\b/i]
  ];
  const COUNTRY = { '971': 'UAE', '966': 'Saudi Arabia', '974': 'Qatar', '965': 'Kuwait', '973': 'Bahrain', '968': 'Oman',
    '91': 'India', '44': 'UK', '41': 'Switzerland', '33': 'France', '49': 'Germany', '1': 'USA/Canada', '7': 'Russia', '20': 'Egypt', '92': 'Pakistan', '63': 'Philippines' };

  const iso = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');

  function findPhone(text) {
    const m = text.match(/(\+|00)?\d[\d\s\-()]{7,}\d/g);
    if (!m) return null;
    const raw = m.sort((a, b) => b.replace(/\D/g, '').length - a.replace(/\D/g, '').length)[0];
    let digits = raw.replace(/\D/g, '');
    if (raw.trim().startsWith('00')) digits = digits.slice(2);
    let cc = '';
    if (/^\+|^00/.test(raw.trim())) cc = ['971', '966', '974', '965', '973', '968', '91', '44', '41', '33', '49', '20', '92', '63', '1', '7'].find(c => digits.startsWith(c)) || '';
    else if (/^05\d{8}$/.test(digits)) { cc = '971'; digits = '971' + digits.slice(1); }
    const rest = digits.slice(cc.length);
    const pretty = cc === '971' && rest.length === 9 ? '+971 ' + rest.slice(0, 2) + ' ' + rest.slice(2, 5) + ' ' + rest.slice(5) : '+' + (cc ? cc + ' ' + rest : digits);
    return { raw, digits, pretty, country: COUNTRY[cc] || '' };
  }

  function findName(text, phone) {
    const lab = text.match(/^\s*name\s*[-:–]\s*(.+)$/im);
    if (lab) return lab[1].trim();
    if (phone) {
      const line = text.split('\n').find(l => l.includes(phone.raw.trim().slice(0, 6)));
      if (line) {
        const before = line.split(phone.raw.trim().slice(0, 4))[0].replace(/(contact( person)?|mobile|tel|phone|number|no\.?)\s*$/i, '').replace(/[-:–|,\s]+$/, '').trim();
        if (before) return before;
      }
    }
    return '';
  }

  function findDate(text, now) {
    const t = text.toLowerCase();
    const at = (y, m, d) => { let x = new Date(y, m, d); if (x < new Date(now.getFullYear(), now.getMonth(), now.getDate())) x = new Date(y + 1, m, d); return x; };
    if (/\btoday|tonight\b/.test(t)) return { d: new Date(now), how: '"today"' };
    if (/\btomorrow\b/.test(t)) { const d = new Date(now); d.setDate(d.getDate() + 1); return { d, how: '"tomorrow"' }; }
    const mon = '(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\\.?';
    let m = t.match(new RegExp(mon + '\\s+(\\d{1,2})(st|nd|rd|th)?\\b'));
    if (m) return { d: at(now.getFullYear(), MONTHS.indexOf(m[1]), +m[2]), how: '"' + m[0].trim() + '"' };
    m = t.match(new RegExp('\\b(\\d{1,2})(st|nd|rd|th)?\\s+(of\\s+)?' + mon));
    if (m) return { d: at(now.getFullYear(), MONTHS.indexOf(m[4]), +m[1]), how: '"' + m[0].trim() + '"' };
    m = t.match(/\b(\d{1,2})[\/.](\d{1,2})([\/.](\d{2,4}))?\b/);
    if (m && +m[2] <= 12) return { d: at(m[4] ? (m[4].length === 2 ? 2000 + +m[4] : +m[4]) : now.getFullYear(), +m[2] - 1, +m[1]), how: '"' + m[0] + '"' };
    m = t.match(/\b(sunday|monday|tuesday|wednesday|thursday|friday|saturday)\b/);
    if (m) { const d = new Date(now); const add = (DAYS.indexOf(m[1]) - d.getDay() + 7) % 7 || 7; d.setDate(d.getDate() + add); return { d, how: '"' + m[1] + '"', check: true }; }
    return null;
  }

  function readEnquiry(text, now) {
    now = now || new Date();
    const phone = findPhone(text);
    const name = findName(text, phone);
    const date = findDate(text, now);
    const occ = OCCASIONS.find(([, re]) => re.test(text));
    const days = date ? Math.round((new Date(date.d.getFullYear(), date.d.getMonth(), date.d.getDate()) - new Date(now.getFullYear(), now.getMonth(), now.getDate())) / 864e5) : null;
    return {
      name: { v: name, check: !name || name.replace(/[^a-z]/gi, '').length < 3, why: !name ? 'No name found' : name.replace(/[^a-z]/gi, '').length < 3 ? 'Only "' + name + '" found, please complete' : 'Next to the number' },
      mobile: { v: phone ? phone.pretty : '', check: !phone, why: phone ? (phone.country ? phone.country + ' number' : 'Found in the message') : 'No number found' },
      occasion: { v: occ ? occ[0] : '', check: !occ, why: occ ? 'From "' + text.match(occ[1])[0] + '"' : 'Not clear, please choose' },
      enqDate: { v: iso(now), check: false, why: 'Today (when you pasted it)' },
      eventDate: { v: date ? iso(date.d) : '', check: !date || !!date.check, why: date ? 'From ' + date.how : 'No date found' },
      urgent: days != null && days <= 1,
      days
    };
  }
  root.readEnquiry = readEnquiry;
  if (typeof module !== 'undefined') module.exports = readEnquiry;
})(typeof window !== 'undefined' ? window : globalThis);

/* Screenshot → text, fully on the device (Tesseract, files in vendor/ocr).
   WhatsApp shows numbers in green on a light bubble, which the reader drops,
   so the image is enlarged and turned pure black-and-white first. */
(function (root) {
  let worker = null;
  function loadScript(src) {
    return new Promise((ok, bad) => { const s = document.createElement('script'); s.src = src; s.onload = ok; s.onerror = () => bad(new Error('reader files missing')); document.head.appendChild(s); });
  }
  function prep(file) {
    return new Promise((ok, bad) => {
      const url = URL.createObjectURL(file), im = new Image();
      im.onload = () => {
        const k = Math.max(1, Math.min(3, 1800 / im.width));
        const c = document.createElement('canvas'); c.width = Math.round(im.width * k); c.height = Math.round(im.height * k);
        const x = c.getContext('2d'); x.imageSmoothingQuality = 'high'; x.drawImage(im, 0, 0, c.width, c.height);
        const d = x.getImageData(0, 0, c.width, c.height), p = d.data;
        for (let i = 0; i < p.length; i += 4) { const v = Math.min(p[i], p[i + 1], p[i + 2]) < 150 ? 0 : 255; p[i] = p[i + 1] = p[i + 2] = v; }
        x.putImageData(d, 0, 0); URL.revokeObjectURL(url); ok(c);
      };
      im.onerror = () => { URL.revokeObjectURL(url); bad(new Error('not an image')); };
      im.src = url;
    });
  }
  async function readImage(file) {
    if (!root.Tesseract) await loadScript('vendor/ocr/tesseract.min.js');
    if (!worker) {
      const base = new URL('vendor/ocr/', location.href).href;
      worker = await root.Tesseract.createWorker('eng', 1, { workerPath: base + 'worker.min.js', corePath: base, langPath: base, workerBlobURL: false, gzip: true });
    }
    const r = await worker.recognize(await prep(file));
    return r.data.text;
  }
  root.readEnquiryImage = readImage;
})(window);
