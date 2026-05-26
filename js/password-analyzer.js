/*!
 * Password Security Analyzer  —  js/password-analyzer.js
 * george-condrea.com/tools
 *
 * All analysis runs 100% in the browser.
 * No password data is ever transmitted to any server.
 *
 * ─────────────────────────────────────────────────────────
 * SETUP STEPS (owner only):
 *
 * 1. STRIPE PAYMENT LINK
 *    a) Create a Stripe Payment Link in your Stripe Dashboard
 *    b) Under "Confirmation page" → choose "Redirect to URL"
 *    c) Set redirect to:
 *       https://george-condrea.com/password-analyzer.html?unlocked=1&sid={CHECKOUT_SESSION_ID}
 *    d) Paste the Payment Link URL below as PSA_CONFIG.STRIPE_LINK
 *
 * 2. KO-FI UNLOCK CODE (fallback path)
 *    a) Choose a secret code, e.g. "PSA-TOOLS-2025"
 *    b) Open browser console on any page and run:
 *       crypto.subtle.digest('SHA-256', new TextEncoder().encode('YOUR_CODE'))
 *         .then(b => console.log([...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')))
 *    c) Paste the resulting hex string as PSA_CONFIG.KOFI_CODE_HASH
 *    d) Create a Ko-fi Shop product, upload a .txt with your chosen code as the digital download
 * ─────────────────────────────────────────────────────────
 */
'use strict';

/* ════════════════════════════════════════════════════════════
   CONFIG  —  update these before going live
   ════════════════════════════════════════════════════════════ */
const PSA_CONFIG = {
  STRIPE_LINK:     'YOUR_STRIPE_PAYMENT_LINK_URL',   // ← paste Stripe Payment Link here
  KOFI_CODE_HASH:  'YOUR_SHA256_HASH_HERE',           // ← paste SHA-256 of your code here
  LS_KEY:          'psa_premium',
  PRICE_DISPLAY:   '£2.99',
};

/* ════════════════════════════════════════════════════════════
   TOP-1000 COMMON PASSWORDS  (embedded, O(1) lookup)
   ════════════════════════════════════════════════════════════ */
const COMMON_PASSWORDS = new Set([
  '123456','password','12345678','qwerty','123456789','12345','1234','111111',
  '1234567','dragon','123123','baseball','iloveyou','trustno1','letmein','monkey',
  'master','sunshine','ashley','bailey','passw0rd','shadow','123321','654321',
  'superman','qazwsx','michael','football','abc123','password1','password123',
  '1234567890','qwertyuiop','admin','welcome','login','admin123','root','pass',
  'test','hello','charlie','donald','password2','qwerty123','iloveyou1','princess',
  'rockyou','696969','mustang','computer','cheese','liverpool','ranger','solo',
  'soccer','tiger','thunder','matrix','fuckyou','1q2w3e4r','q1w2e3r4t5','qazxsw',
  '1qaz2wsx','1qaz','zxcvbnm','asdfghjkl','qwertyui','letmein1','pass123','test123',
  '123qwe','qwe123','abc1234','password01','password11','12341234','newpass',
  'changeme','secret','qwerty1','pa$$w0rd','P@ssw0rd','P@$$word','password!',
  'p@ssword','pa$$word','p@55word','passw0rd1','Passw0rd','Password1','Password123',
  'pass1234','pa55word','sunshine1','princess1','welcome1','welcome123','monkey123',
  'dragon1','master1','shadow1','hello123','letmein2','password2020','password2021',
  'password2022','password2023','password2024','password2025','starwars','batman',
  'superman1','spiderman','ironman','captain','harrypotter','hermione','alohomora',
  'hogwarts','gandalf','frodo','aragorn','legolas','tolkien','narnia','aslan',
  'hobbit','mordor','google','facebook','twitter','instagram','youtube','netflix',
  'amazon','apple123','microsoft','windows','office365','outlook','gmail','yahoo123',
  'hotmail','myspace','linkedin','reddit','discord','gaming123','gamer123',
  'playstation','xbox360','nintendo','minecraft','fortnite','roblox','steam123',
  'michael1','ashley1','jessica','jennifer','amanda','joshua','andrew','daniel',
  'david123','john123','james123','robert','william','richard','thomas','charles',
  'christopher','george','steven','brian','edward','mary123','elizabeth','sarah123',
  'karen','linda','barbara','patricia','football1','baseball1','basketball',
  'hockey123','soccer1','tennis123','summer','winter','spring','autumn','christmas',
  'halloween','birthday','monday','tuesday','wednesday','thursday','friday',
  'saturday','sunday','11111111','222222','333333','444444','555555','666666',
  '777777','888888','999999','000000','12121212','11223344','13579246','87654321',
  'aaaaaa','bbbbbb','zzzzzz','aaa111','aabbcc','112233','abcabc','abc123abc',
  'pass1','pass2','admin1','admin2','root123','toor','test1234','testing','demo',
  'sample','guest','user','user123','1234abcd','abcd1234','a1b2c3d4','abcd123',
  '123abc','love123','sexy','sex123','fuck123','shit','bitch','asshole','bastard',
  'cowboys','yankees','lakers','celtics','chelsea','arsenal','barcelona','madrid',
  'password0','0000','00000000','jordan23','nfl123','nba123','mlb123','nhl123',
  'letmein3','access','access1','access123','trustme','passpass','homerun',
  'godfrey','ginger','butter','cheese1','cookie','brownie','muffin','cupcake',
  'qweasd','asdzxc','poiuyt','lkjhgf','mnbvcx','zxcvbn','hunter2','hunter1',
  'hunter','sniper','eagle','falcon','hawk','shark','wolf','bear','panther',
  'cobra','viper','python','dragon123','phoenix','titan','atlas','zeus','apollo',
  'hermes','athena','ares','poseidon','hades','neptune','mercury','venus','mars',
  'saturn','jupiter','pluto','ranger1','maverick','goose','iceman','topgun',
  'america','england','germany','france','canada','australia','brazil','russia',
  'london','paris','berlin','tokyo','sydney','moscow','madrid','chicago',
  'newyork','losangeles','houston','phoenix','dallas','batman1','joker','harley',
  'penguin','riddler','scarecrow','nightwing','robin1','catwoman','superman2',
  'spiderman1','wolverine','cyclops','magneto','professor','xmen','avengers',
  'hulk','thanos','loki','odin','mjolnir','shield','hydra','stark','rogers',
  'targaryen','lannister','stark1','snow123','winter1','dragon2','dragons',
  'direwolf','kingslayer','cersei','daenerys','tyrion','arya','sansa',
  '!@#$%^&*','1111111111','0987654321','9876543210','00000000','11111111',
  '1111111','111111111','0000000','000000000','qqqqqqq','aaaaaaa','mmmmmmm',
  'pppppppp','zzzzzzzz','xxxxxxxx','vvvvvvvv','nnnnnnn','hhhhhhh',
  'realmadrид','realmadrid','liverp00l','m@nchester','ch3lsea','guns','roses',
]);

/* ════════════════════════════════════════════════════════════
   DOM CACHE
   ════════════════════════════════════════════════════════════ */
let D = {};   // will hold all DOM refs after DOMContentLoaded

/* ════════════════════════════════════════════════════════════
   STATE
   ════════════════════════════════════════════════════════════ */
let lastAnalysis   = null;
let hibpRanOnce    = false;

/* ════════════════════════════════════════════════════════════
   BOOT
   ════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  cacheDom();
  checkStripeReturn();
  applyPremiumState();
  updateStripeLink();
  bindEvents();
});

function cacheDom() {
  const g = id => document.getElementById(id);
  D = {
    input:           g('psa-input'),
    toggleVis:       g('psa-toggle-vis'),
    meterFill:       g('psa-meter-fill'),
    meterPct:        g('psa-meter-pct'),
    strengthLabel:   g('psa-strength-label'),
    resultsSection:  g('psa-results'),
    tipsSection:     g('psa-tips'),
    nistSection:     g('psa-nist'),
    commonWarn:      g('psa-common-warn'),
    entropyVal:      g('psa-entropy-val'),
    entropyDesc:     g('psa-entropy-desc'),
    crackList:       g('psa-crack-list'),
    compBars:        g('psa-comp-bars'),
    patternsWrap:    g('psa-patterns'),
    tipsList:        g('psa-tips-list'),
    nistList:        g('psa-nist-list'),
    // premium
    premiumCards:    document.querySelectorAll('.psa-pcard'),
    unlockPanel:     g('psa-unlock-panel'),
    alreadyUnlocked: g('psa-already-unlocked'),
    stripeBtn:       g('psa-stripe-btn'),
    kofiCode:        g('psa-kofi-code'),
    kofiSubmit:      g('psa-kofi-submit'),
    kofiError:       g('psa-kofi-error'),
    hibpBtn:         g('psa-hibp-btn'),
    hibpResult:      g('psa-hibp-result'),
    pdfBtn:          g('psa-pdf-btn'),
    compareSection:  g('psa-compare-section'),
    compareInput:    g('psa-compare-input'),
    compareOut:      g('psa-compare-out'),
  };
}

function updateStripeLink() {
  if (D.stripeBtn && PSA_CONFIG.STRIPE_LINK !== 'YOUR_STRIPE_PAYMENT_LINK_URL') {
    D.stripeBtn.href = PSA_CONFIG.STRIPE_LINK;
  }
}

/* ════════════════════════════════════════════════════════════
   EVENT BINDING
   ════════════════════════════════════════════════════════════ */
function bindEvents() {
  D.input.addEventListener('input', onPasswordInput);
  D.toggleVis.addEventListener('click', toggleVisibility);
  if (D.kofiSubmit) D.kofiSubmit.addEventListener('click', onKofiSubmit);
  if (D.hibpBtn)    D.hibpBtn.addEventListener('click', onHIBPCheck);
  if (D.pdfBtn)     D.pdfBtn.addEventListener('click', onGeneratePDF);
  if (D.compareInput) D.compareInput.addEventListener('input', onCompareInput);
}

function onPasswordInput() {
  const pwd = D.input.value;
  if (!pwd) { hideResults(); return; }
  lastAnalysis = analyzePassword(pwd);
  renderAll(lastAnalysis);
  showResults();
  hibpRanOnce = false;
}

function toggleVisibility() {
  const isPass = D.input.type === 'password';
  D.input.type = isPass ? 'text' : 'password';
  D.toggleVis.innerHTML = isPass
    ? '<i class="bi bi-eye-slash"></i>'
    : '<i class="bi bi-eye"></i>';
}

/* ════════════════════════════════════════════════════════════
   CORE ANALYSIS ENGINE
   ════════════════════════════════════════════════════════════ */
function analyzePassword(pwd) {
  const comp     = analyzeComposition(pwd);
  const entropy  = calcEntropy(pwd, comp);
  const level    = getStrengthLevel(entropy);
  const times    = calcCrackTimes(entropy);
  const patterns = detectPatterns(pwd);
  const isCommon = checkCommonPassword(pwd);
  const tips     = buildTips(pwd, comp, patterns, isCommon);
  const nist     = buildNIST(pwd, comp, patterns, isCommon);
  return { pwd, comp, entropy, level, times, patterns, isCommon, tips, nist };
}

/* Composition */
function analyzeComposition(pwd) {
  let upper = 0, lower = 0, digit = 0, symbol = 0;
  for (const ch of pwd) {
    if      (/[A-Z]/.test(ch)) upper++;
    else if (/[a-z]/.test(ch)) lower++;
    else if (/[0-9]/.test(ch)) digit++;
    else                       symbol++;
  }
  return { upper, lower, digit, symbol, length: pwd.length };
}

/* Entropy (Shannon: L × log2(pool)) */
function calcEntropy(pwd, comp) {
  if (!pwd.length) return 0;
  let pool = 0;
  if (comp.lower  > 0) pool += 26;
  if (comp.upper  > 0) pool += 26;
  if (comp.digit  > 0) pool += 10;
  if (comp.symbol > 0) pool += 32;
  if (pool === 0)  pool = 26;
  return pwd.length * Math.log2(pool);
}

/* Strength levels */
function getStrengthLevel(entropy) {
  if (entropy < 28)  return { n: 0, label: 'Very Weak',   color: '#dc3545', pct: 8   };
  if (entropy < 36)  return { n: 1, label: 'Weak',        color: '#fd7e14', pct: 28  };
  if (entropy < 60)  return { n: 2, label: 'Fair',        color: '#e8a800', pct: 54  };
  if (entropy < 100) return { n: 3, label: 'Strong',      color: '#0d6efd', pct: 80  };
  return                    { n: 4, label: 'Very Strong', color: '#198754', pct: 100 };
}

/* Crack times — brute-force worst case */
function calcCrackTimes(entropy) {
  const combos = Math.pow(2, entropy);
  return [
    { name: 'Online (throttled)',   speed: 10,    icon: 'bi-wifi',        time: formatTime(combos / 10)    },
    { name: 'Online (fast)',        speed: 1e4,   icon: 'bi-globe2',      time: formatTime(combos / 1e4)   },
    { name: 'Offline MD5',          speed: 1e10,  icon: 'bi-hdd-fill',    time: formatTime(combos / 1e10)  },
    { name: 'Offline bcrypt',       speed: 1e4,   icon: 'bi-lock-fill',   time: formatTime(combos / 1e4)   },
    { name: 'GPU cluster',          speed: 1e12,  icon: 'bi-cpu-fill',    time: formatTime(combos / 1e12)  },
  ];
}

function formatTime(seconds) {
  if (seconds < 0.001)   return 'Instant';
  if (seconds < 1)       return '< 1 second';
  if (seconds < 60)      return `${Math.round(seconds)} second${Math.round(seconds)===1?'':'s'}`;
  if (seconds < 3600)    return `${Math.round(seconds/60)} minute${Math.round(seconds/60)===1?'':'s'}`;
  if (seconds < 86400)   return `${Math.round(seconds/3600)} hour${Math.round(seconds/3600)===1?'':'s'}`;
  if (seconds < 2.592e6) return `${Math.round(seconds/86400)} day${Math.round(seconds/86400)===1?'':'s'}`;
  if (seconds < 3.156e7) return `${Math.round(seconds/2.592e6)} month${Math.round(seconds/2.592e6)===1?'':'s'}`;
  if (seconds < 3.156e9) return `${Math.round(seconds/3.156e7)} year${Math.round(seconds/3.156e7)===1?'':'s'}`;
  if (seconds < 3.156e11)return `${Math.round(seconds/3.156e9)} centur${Math.round(seconds/3.156e9)===1?'y':'ies'}`;
  return 'Longer than the age of the universe';
}

/* Pattern detection */
const KB_WALKS = [
  'qwertyuiop','qwerty','qwert','asdfghjkl','asdfgh','asdf','zxcvbnm','zxcvbn',
  'qazwsx','1qaz2wsx','1qaz','poiuytrewq','lkjhgfdsa','mnbvcxz',
  '1234567890','123456789','12345678','1234567','123456','12345','1234','123',
  '0987654321','987654321','87654321','7654321','654321','54321','4321','321',
  'abcdefghij','abcdefghi','abcdefgh','abcdefg','abcdef','abcde','abcd','abc',
];

function detectPatterns(pwd) {
  const lc = pwd.toLowerCase();
  const found = [];

  // Keyboard walks
  for (const w of KB_WALKS) {
    if (lc.includes(w)) {
      found.push(`Keyboard walk: "${w}"`);
      break;
    }
  }

  // Repeated chars (3+ same consecutively)
  const repMatch = pwd.match(/(.)\1{2,}/);
  if (repMatch) found.push(`Repeated chars: "${repMatch[0]}"`);

  // Ascending/descending sequential run (4+)
  let ascRun = 1, descRun = 1;
  for (let i = 1; i < pwd.length; i++) {
    const diff = pwd.charCodeAt(i) - pwd.charCodeAt(i - 1);
    ascRun  = diff === 1  ? ascRun + 1  : 1;
    descRun = diff === -1 ? descRun + 1 : 1;
    if (ascRun  >= 4) { found.push('Sequential ascending characters'); break; }
    if (descRun >= 4) { found.push('Sequential descending characters'); break; }
  }

  // Year pattern (1900–2035)
  const yearM = pwd.match(/\b(19[0-9]{2}|20[0-3][0-9])\b/);
  if (yearM) found.push(`Year pattern: "${yearM[0]}"`);

  // Leet-speak normalisation check
  const leetNorm = lc
    .replace(/@/g,'a').replace(/3/g,'e').replace(/1/g,'i')
    .replace(/0/g,'o').replace(/\$/g,'s').replace(/5/g,'s')
    .replace(/7/g,'t').replace(/4/g,'a').replace(/!/g,'i');
  const LEET_WORDS = ['password','letmein','qwerty','monkey','dragon','master','login','admin','passw0rd'];
  for (const w of LEET_WORDS) {
    if (leetNorm.includes(w)) { found.push(`Common word (with substitutions): "${w}"`); break; }
  }

  return found;
}

/* Common password check */
function checkCommonPassword(pwd) {
  return COMMON_PASSWORDS.has(pwd.toLowerCase());
}

/* Tips */
function buildTips(pwd, comp, patterns, isCommon) {
  return [
    {
      met: pwd.length >= 12,
      label: 'At least 12 characters',
      detail: pwd.length >= 12 ? 'Good length.' : `Add ${12 - pwd.length} more character${12-pwd.length===1?'':'s'} to reach the recommended minimum.`,
    },
    {
      met: pwd.length >= 16,
      label: '16 characters or more (ideal)',
      detail: pwd.length >= 16 ? 'Excellent length.' : 'Aim for 16+ characters for the strongest protection.',
    },
    {
      met: comp.upper > 0,
      label: 'Uppercase letter (A–Z)',
      detail: comp.upper > 0 ? 'Good.' : 'Add at least one uppercase letter.',
    },
    {
      met: comp.lower > 0,
      label: 'Lowercase letter (a–z)',
      detail: comp.lower > 0 ? 'Good.' : 'Add at least one lowercase letter.',
    },
    {
      met: comp.digit > 0,
      label: 'Contains a digit (0–9)',
      detail: comp.digit > 0 ? 'Good.' : 'Add at least one number.',
    },
    {
      met: comp.symbol > 0,
      label: 'Contains a symbol (!@#$…)',
      detail: comp.symbol > 0 ? 'Good.' : 'Add a symbol like !, @, #, $ to greatly increase entropy.',
    },
    {
      met: patterns.length === 0,
      label: 'No predictable patterns',
      detail: patterns.length === 0 ? 'No patterns found.' : `Detected: ${patterns.join('; ')}.`,
    },
    {
      met: !isCommon,
      label: 'Not a well-known password',
      detail: !isCommon ? 'Not found in common password list.' : 'This is one of the most commonly used passwords — change it immediately.',
    },
  ];
}

/* NIST SP 800-63B checks */
function buildNIST(pwd, comp, patterns, isCommon) {
  const hasLongRepeat = /(.)\1{3,}/.test(pwd);
  let hasLongSeq = false;
  let run = 1;
  for (let i = 1; i < pwd.length; i++) {
    if (Math.abs(pwd.charCodeAt(i) - pwd.charCodeAt(i-1)) === 1) { run++; if (run >= 5) { hasLongSeq = true; break; } }
    else run = 1;
  }
  return [
    { pass: pwd.length >= 8,  label: 'Minimum length (8 characters)',      desc: 'NIST requires passwords to be at least 8 characters.' },
    { pass: pwd.length <= 64, label: 'Maximum length support (≤ 64 chars)', desc: 'NIST recommends accepting up to at least 64 characters.' },
    { pass: !isCommon,        label: 'Not a commonly used password',        desc: 'NIST requires checking against known weak/breached passwords.' },
    { pass: !hasLongRepeat,   label: 'No excessive repetition',             desc: 'Strings like "aaaa" or "1111" are explicitly flagged by NIST.' },
    { pass: !hasLongSeq,      label: 'No long sequential strings',          desc: '"abcdefgh" or "12345678" are trivially guessable sequences.' },
    { pass: null,             label: 'Not found in breach database',        desc: 'Requires live HaveIBeenPwned lookup — available in Premium.', premium: true },
  ];
}

/* ════════════════════════════════════════════════════════════
   UI RENDERING
   ════════════════════════════════════════════════════════════ */
function renderAll(a) {
  renderMeter(a.level);
  renderCommonWarning(a.isCommon);
  renderEntropy(a.entropy, a.level);
  renderCrackTimes(a.times);
  renderComposition(a.comp);
  renderPatterns(a.patterns);
  renderTips(a.tips);
  renderNIST(a.nist);
  if (isPremium() && D.compareInput && D.compareInput.value) onCompareInput();
}

function renderMeter(lv) {
  D.meterFill.style.width     = lv.pct + '%';
  D.meterFill.style.background = lv.color;
  D.strengthLabel.textContent = lv.label;
  D.strengthLabel.style.color = lv.color;
  D.meterPct.textContent      = lv.pct + '%';
}

function renderCommonWarning(isCommon) {
  D.commonWarn.style.display = isCommon ? 'flex' : 'none';
}

function renderEntropy(bits, lv) {
  D.entropyVal.textContent = bits.toFixed(1);
  D.entropyVal.style.color = lv.color;
  const MAP = [
    'Extremely low entropy. Trivially crackable in seconds.',
    'Low entropy. Vulnerable to simple dictionary and brute-force attacks.',
    'Moderate entropy. Resistant to online attacks but not targeted offline ones.',
    'High entropy. Strong against most real-world attacks.',
    'Very high entropy. Effectively uncrackable with current technology.',
  ];
  D.entropyDesc.textContent = MAP[lv.n];
}

function renderCrackTimes(times) {
  D.crackList.innerHTML = times.map(t => `
    <div class="psa-crack-row">
      <span class="psa-crack-scenario">
        <i class="bi ${esc(t.icon)}"></i>${esc(t.name)}
      </span>
      <span class="psa-crack-time" style="color:${crackColor(t.time)}">${esc(t.time)}</span>
    </div>`).join('');
}

function crackColor(t) {
  if (/instant|second/i.test(t))                       return '#dc3545';
  if (/minute|hour/i.test(t))                          return '#fd7e14';
  if (/day|month/i.test(t))                            return '#e8a800';
  if (/year|centur/i.test(t))                          return '#0d6efd';
  return '#198754';
}

function renderComposition(comp) {
  const total = comp.length || 1;
  const rows = [
    { label: 'Uppercase', n: comp.upper,  color: '#6f42c1' },
    { label: 'Lowercase', n: comp.lower,  color: '#0d6efd' },
    { label: 'Digits',    n: comp.digit,  color: '#fd7e14' },
    { label: 'Symbols',   n: comp.symbol, color: '#198754' },
  ];
  D.compBars.innerHTML = rows.map(r => {
    const pct = total ? Math.round((r.n / total) * 100) : 0;
    return `<div class="psa-comp-row">
      <div class="psa-comp-meta">
        <span class="psa-comp-name">${r.label}</span>
        <span>${r.n} char${r.n!==1?'s':''} &nbsp;(${pct}%)</span>
      </div>
      <div class="psa-comp-track">
        <div class="psa-comp-fill" style="width:${pct}%;background:${r.color};"></div>
      </div>
    </div>`;
  }).join('');
}

function renderPatterns(patterns) {
  if (!patterns.length) {
    D.patternsWrap.innerHTML = `<p class="psa-no-patterns mb-0">
      <i class="bi bi-check-circle-fill"></i> No common patterns detected</p>`;
  } else {
    D.patternsWrap.innerHTML = `<div class="psa-pattern-wrap">${
      patterns.map(p => `<span class="psa-pattern-chip">
        <i class="bi bi-exclamation-triangle-fill"></i>${esc(p)}</span>`).join('')
    }</div>`;
  }
}

function renderTips(tips) {
  D.tipsList.innerHTML = tips.map(t => `
    <div class="psa-tip-item ${t.met ? 'met' : 'unmet'}">
      <span class="psa-tip-icon">${
        t.met
          ? '<i class="bi bi-check-circle-fill text-success"></i>'
          : '<i class="bi bi-x-circle-fill text-danger"></i>'
      }</span>
      <div>
        <span class="psa-tip-label">${esc(t.label)}</span>
        ${!t.met ? `<span class="psa-tip-detail">${esc(t.detail)}</span>` : ''}
      </div>
    </div>`).join('');
}

function renderNIST(checks) {
  D.nistList.innerHTML = checks.map(c => {
    const isPrem = !!c.premium;
    let iconHtml;
    if (isPrem)        iconHtml = `<i class="bi bi-lock-fill psa-nist-icon" style="color:#6c757d;"></i>`;
    else if (c.pass)   iconHtml = `<i class="bi bi-check-circle-fill psa-nist-icon" style="color:#198754;"></i>`;
    else               iconHtml = `<i class="bi bi-x-circle-fill psa-nist-icon" style="color:#dc3545;"></i>`;
    return `<div class="psa-nist-row${isPrem ? ' opacity-50' : ''}">
      ${iconHtml}
      <div class="psa-nist-text">
        <span class="psa-nist-label">${esc(c.label)}</span>
        <span class="psa-nist-desc">${esc(c.desc)}</span>
      </div>
      ${isPrem ? '<span class="psa-premium-badge-sm">PREMIUM</span>' : ''}
    </div>`;
  }).join('');
}

function showResults() {
  [D.resultsSection, D.tipsSection, D.nistSection].forEach(el => {
    if (el) el.classList.remove('d-none');
  });
}

function hideResults() {
  [D.resultsSection, D.tipsSection, D.nistSection].forEach(el => {
    if (el) el.classList.add('d-none');
  });
  D.meterFill.style.width = '0%';
  D.strengthLabel.textContent = '';
  D.meterPct.textContent = '';
}

/* ════════════════════════════════════════════════════════════
   PREMIUM — GATING & UNLOCK
   ════════════════════════════════════════════════════════════ */
function isPremium() {
  return !!localStorage.getItem(PSA_CONFIG.LS_KEY);
}

function applyPremiumState() {
  if (!isPremium()) return;
  D.premiumCards.forEach(c => c.classList.add('unlocked'));
  if (D.unlockPanel)     D.unlockPanel.style.display    = 'none';
  if (D.alreadyUnlocked) D.alreadyUnlocked.style.display = 'flex';
  if (D.compareSection)  D.compareSection.style.display  = 'block';
}

/* Stripe redirect handling */
function checkStripeReturn() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('unlocked') === '1') {
    const sid = params.get('sid') || 'stripe';
    localStorage.setItem(PSA_CONFIG.LS_KEY, sid);
    history.replaceState({}, '', window.location.pathname);
    // slight delay so DOM is ready
    setTimeout(() => {
      applyPremiumState();
      showToast('Payment confirmed. Premium features unlocked!', 'success');
    }, 300);
  }
}

/* Ko-fi code validation */
async function onKofiSubmit() {
  const code = D.kofiCode.value.trim();
  if (!code) return;
  D.kofiError.textContent = '';
  D.kofiSubmit.disabled   = true;
  D.kofiSubmit.textContent = 'Checking…';

  const valid = await validateKofiCode(code);
  D.kofiSubmit.disabled    = false;
  D.kofiSubmit.textContent = 'Unlock';

  if (valid) {
    localStorage.setItem(PSA_CONFIG.LS_KEY, 'kofi');
    applyPremiumState();
    showToast('Code accepted! Premium features unlocked.', 'success');
  } else {
    D.kofiError.textContent = 'Invalid code. Check your Ko-fi receipt email.';
  }
}

async function validateKofiCode(code) {
  if (PSA_CONFIG.KOFI_CODE_HASH === 'YOUR_SHA256_HASH_HERE') return false;
  const hash = await sha256(code.toUpperCase().trim());
  return hash === PSA_CONFIG.KOFI_CODE_HASH.toLowerCase();
}

/* ════════════════════════════════════════════════════════════
   PREMIUM FEATURE 1 — HaveIBeenPwned check
   ════════════════════════════════════════════════════════════ */
async function onHIBPCheck() {
  if (!lastAnalysis || !isPremium()) return;
  D.hibpResult.className = 'psa-hibp-result loading show';
  D.hibpResult.innerHTML = `<i class="bi bi-arrow-repeat psa-spin"></i><span>Checking breach database…</span>`;
  D.hibpBtn.disabled = true;

  try {
    const { found, count } = await runHIBPCheck(lastAnalysis.pwd);
    if (found) {
      D.hibpResult.className = 'psa-hibp-result breached show';
      D.hibpResult.innerHTML = `
        <i class="bi bi-exclamation-triangle-fill" style="font-size:1.1rem;flex-shrink:0;margin-top:0.1rem;"></i>
        <div>
          <strong>Found in data breaches!</strong><br>
          <span>This password has appeared <strong>${count.toLocaleString()}</strong> times in known data breach databases. Do not use it.</span>
        </div>`;
    } else {
      D.hibpResult.className = 'psa-hibp-result safe show';
      D.hibpResult.innerHTML = `
        <i class="bi bi-shield-check-fill" style="font-size:1.1rem;flex-shrink:0;margin-top:0.1rem;"></i>
        <div>
          <strong>Not found in any known breach</strong><br>
          <span>Great news — this exact password hasn't appeared in any database checked by HaveIBeenPwned.</span>
        </div>`;
    }
    hibpRanOnce = true;
  } catch {
    D.hibpResult.className = 'psa-hibp-result show';
    D.hibpResult.style.background = '#f8f9fa';
    D.hibpResult.innerHTML = `<i class="bi bi-wifi-off"></i><span>Could not reach breach database. Check your connection and try again.</span>`;
  }
  D.hibpBtn.disabled = false;
}

async function runHIBPCheck(pwd) {
  // k-anonymity: only first 5 chars of SHA-1 hash are sent — full password never leaves browser
  const hash   = await sha1(pwd);
  const prefix = hash.slice(0, 5).toUpperCase();
  const suffix = hash.slice(5).toUpperCase();
  const resp   = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' }
  });
  if (!resp.ok) throw new Error('HIBP request failed');
  const lines  = (await resp.text()).split('\r\n');
  for (const line of lines) {
    const [s, cnt] = line.split(':');
    if (s === suffix) return { found: true, count: parseInt(cnt, 10) };
  }
  return { found: false, count: 0 };
}

/* ════════════════════════════════════════════════════════════
   PREMIUM FEATURE 2 — PDF Report
   ════════════════════════════════════════════════════════════ */
function onGeneratePDF() {
  if (!lastAnalysis || !isPremium()) return;
  if (typeof window.jspdf === 'undefined') {
    showToast('PDF library still loading — please try again in a moment.', 'warn');
    return;
  }
  generatePDF(lastAnalysis);
}

function generatePDF(a) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const W   = doc.internal.pageSize.getWidth();
  let   y   = 0;

  /* Header */
  doc.setFillColor(15, 17, 23);
  doc.rect(0, 0, W, 30, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(15);
  doc.setFont('helvetica', 'bold');
  doc.text('PASSWORD SECURITY REPORT', 14, 11);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(168, 181, 200);
  doc.text('george-condrea.com/tools', 14, 18);
  doc.text(`Generated: ${new Date().toUTCString()}`, 14, 24);
  y = 38;

  /* Privacy note */
  doc.setFillColor(240, 253, 244);
  doc.setDrawColor(187, 247, 208);
  doc.roundedRect(14, y, W - 28, 9, 1.5, 1.5, 'FD');
  doc.setFontSize(7.5);
  doc.setTextColor(22, 101, 52);
  doc.text('All analysis was performed locally in your browser. Your password was never transmitted to any server.', 18, y + 5.8);
  y += 16;

  /* Strength summary */
  doc.setTextColor(30, 30, 30);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.text('Strength Summary', 14, y);
  y += 7;

  const lvColors = {
    'Very Weak':   [220, 53, 69],
    'Weak':        [253, 126, 20],
    'Fair':        [232, 168, 0],
    'Strong':      [13, 110, 253],
    'Very Strong': [25, 135, 84],
  };
  const [r, g, b] = lvColors[a.level.label] || [100, 100, 100];
  doc.setFillColor(r, g, b);
  doc.roundedRect(14, y, 55, 14, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text(a.level.label, 41.5, y + 9, { align: 'center' });
  doc.setTextColor(50, 50, 50);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.text(`Entropy:  ${a.entropy.toFixed(1)} bits`, 76, y + 5);
  doc.text(`Length:   ${a.comp.length} characters`, 76, y + 11);
  y += 22;

  /* Composition */
  y = pdfSection(doc, 'Character Composition', y);
  const compData = [
    ['Uppercase', a.comp.upper], ['Lowercase', a.comp.lower],
    ['Digits',    a.comp.digit], ['Symbols',   a.comp.symbol],
  ];
  doc.setFontSize(9);
  for (const [label, count] of compData) {
    doc.setTextColor(80, 80, 80); doc.text(label + ':', 18, y);
    doc.setTextColor(20, 20, 20); doc.text(String(count), 58, y);
    y += 5;
  }
  y += 4;

  /* Crack times */
  y = pdfSection(doc, 'Estimated Crack Times', y);
  doc.setFontSize(9);
  for (const t of a.times) {
    doc.setTextColor(80, 80, 80); doc.text(t.name + ':', 18, y);
    doc.setTextColor(20, 20, 20); doc.text(t.time, 90, y);
    y += 5;
  }
  y += 4;

  /* Patterns */
  y = pdfSection(doc, 'Pattern Analysis', y);
  doc.setFontSize(9);
  if (a.patterns.length === 0) {
    doc.setTextColor(25, 135, 84);
    doc.text('No common patterns detected.', 18, y); y += 5;
  } else {
    for (const p of a.patterns) {
      doc.setTextColor(146, 64, 14);
      doc.text('• ' + p, 18, y); y += 5;
    }
  }
  y += 4;

  /* Recommendations */
  y = pdfSection(doc, 'Recommendations', y);
  doc.setFontSize(9);
  const failedTips = a.tips.filter(t => !t.met);
  if (failedTips.length === 0) {
    doc.setTextColor(25, 135, 84);
    doc.text('All criteria met. Excellent password!', 18, y); y += 5;
  } else {
    for (const t of failedTips) {
      doc.setTextColor(153, 27, 27);
      doc.text('• ' + t.detail, 18, y); y += 5;
    }
  }
  y += 4;

  /* NIST */
  y = pdfSection(doc, 'NIST SP 800-63B Compliance', y);
  doc.setFontSize(9);
  for (const c of a.nist) {
    if (c.premium) continue;
    const mark = c.pass ? '[PASS]' : '[FAIL]';
    doc.setTextColor(c.pass ? 25 : 220, c.pass ? 135 : 53, c.pass ? 84 : 69);
    doc.text(mark + '  ' + c.label, 18, y); y += 5;
  }

  /* Footer on every page */
  const pages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    const ph = doc.internal.pageSize.getHeight();
    doc.setFillColor(248, 249, 250);
    doc.rect(0, ph - 11, W, 11, 'F');
    doc.setFontSize(7);
    doc.setTextColor(108, 117, 125);
    doc.text('Password Security Analyzer — george-condrea.com/tools', 14, ph - 4);
    doc.text(`Page ${i} of ${pages}`, W - 14, ph - 4, { align: 'right' });
  }

  doc.save('password-security-report.pdf');
}

function pdfSection(doc, title, y) {
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 17, 23);
  doc.text(title, 14, y);
  doc.setFont('helvetica', 'normal');
  return y + 7;
}

/* ════════════════════════════════════════════════════════════
   PREMIUM FEATURE 3 — Password Comparison
   ════════════════════════════════════════════════════════════ */
function onCompareInput() {
  if (!isPremium() || !lastAnalysis) return;
  const pwd2 = D.compareInput.value;
  if (!pwd2) { D.compareOut.innerHTML = ''; return; }
  const b = analyzePassword(pwd2);
  renderComparison(lastAnalysis, b);
}

function renderComparison(a, b) {
  const metrics = [
    { label: 'Strength',  va: a.level.label,             vb: b.level.label,             win: a.level.n > b.level.n ? 'a' : b.level.n > a.level.n ? 'b' : 'tie' },
    { label: 'Entropy',   va: a.entropy.toFixed(1)+' b', vb: b.entropy.toFixed(1)+' b', win: a.entropy > b.entropy ? 'a' : b.entropy > a.entropy ? 'b' : 'tie' },
    { label: 'Length',    va: a.comp.length+' chars',    vb: b.comp.length+' chars',    win: a.comp.length > b.comp.length ? 'a' : b.comp.length > a.comp.length ? 'b' : 'tie' },
    { label: 'Patterns',  va: a.patterns.length+' found',vb: b.patterns.length+' found',win: a.patterns.length < b.patterns.length ? 'a' : b.patterns.length < a.patterns.length ? 'b' : 'tie' },
    { label: 'Common?',   va: a.isCommon?'Yes':'No',     vb: b.isCommon?'Yes':'No',     win: !a.isCommon && b.isCommon ? 'a' : !b.isCommon && a.isCommon ? 'b' : 'tie' },
    { label: 'GPU Crack', va: a.times[4].time,           vb: b.times[4].time,           win: a.entropy >= b.entropy ? 'a' : 'b' },
  ];
  D.compareOut.innerHTML = metrics.map(m => `
    <div class="psa-compare-metric">
      <span style="color:#a8b5c8">${esc(m.label)}</span>
      <div class="d-flex align-items-center gap-3">
        <span style="color:${m.win==='a'?'#3dd68c':'#6c757d'}">
          ${esc(m.va)}${m.win==='a'?'<span class="psa-winner-pill">A</span>':''}
        </span>
        <span style="color:#4a5568;font-size:0.7rem;">vs</span>
        <span style="color:${m.win==='b'?'#3dd68c':'#6c757d'}">
          ${esc(m.vb)}${m.win==='b'?'<span class="psa-winner-pill">B</span>':''}
        </span>
      </div>
    </div>`).join('');
}

/* ════════════════════════════════════════════════════════════
   CRYPTO HELPERS
   ════════════════════════════════════════════════════════════ */
async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha1(str) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ════════════════════════════════════════════════════════════
   TOAST NOTIFICATION
   ════════════════════════════════════════════════════════════ */
function showToast(msg, type) {
  const el = document.createElement('div');
  el.className = 'psa-toast';
  const icon = type === 'success' ? 'bi-check-circle-fill text-success' : 'bi-exclamation-triangle-fill text-warning';
  el.innerHTML = `<i class="bi ${icon}"></i><span>${esc(msg)}</span>`;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

/* ════════════════════════════════════════════════════════════
   UTILITY
   ════════════════════════════════════════════════════════════ */
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
