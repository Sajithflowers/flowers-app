/* iPhone / iPad install gate.
   Safari deletes a website's stored data after 7 days of not opening it. This app
   keeps work on the device until it has been uploaded, so on a phone used now and
   then that rule could quietly destroy unsent work. Adding the app to the Home
   Screen exempts it from the rule — so until that is done, the app does not open.
   Runs ONLY in mobile Safari on the web. Never inside the Windows or Android app. */
(function () {
  if (location.protocol === 'file:') return;              /* packaged app */
  if (window.Capacitor) return;                           /* Android wrapper */
  if (/electron/i.test(navigator.userAgent)) return;      /* Windows wrapper */

  const ua = navigator.userAgent;
  const iPadOS13up = navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1;
  const isIOS = /iPad|iPhone|iPod/.test(ua) || iPadOS13up;
  if (!isIOS) return;                                     /* other browsers are fine */

  const installed = window.navigator.standalone === true ||
    (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);
  if (installed) return;                                  /* already on the Home Screen */

  /* Chrome, Firefox and the rest on iOS cannot "Add to Home Screen" properly —
     they must be told to use Safari, not given instructions that will not work. */
  const inSafari = !/CriOS|FxiOS|EdgiOS|OPiOS|Chrome/i.test(ua);

  const html =
    '<div id="fl-ios-gate" style="position:fixed;inset:0;z-index:99999;overflow:auto;' +
      'background:linear-gradient(160deg,#3a0210,#550318 70%);color:#fff;' +
      'font-family:Lato,Arial,sans-serif;padding:34px 22px;">' +
      '<div style="max-width:420px;margin:0 auto;text-align:center;">' +
        '<div style="font-family:\'EB Garamond\',Georgia,serif;font-size:23px;letter-spacing:2px;">' +
          'FLOWERS.AE</div>' +
        '<div style="width:44px;height:2px;background:#E6CCA1;margin:13px auto 10px;"></div>' +
        '<div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#E6CCA1;">' +
          'The Art of Gifting</div>' +

        (inSafari
          ? '<h1 style="font-family:\'EB Garamond\',Georgia,serif;font-size:24px;font-weight:700;' +
              'margin:32px 0 10px;line-height:1.3;">Add this to your Home Screen first</h1>' +
            '<p style="font-size:14.5px;line-height:1.65;color:rgba(255,255,255,.88);margin:0 0 26px;">' +
              'It only takes a moment, and it is not optional &mdash; iPhone deletes a ' +
              'website&rsquo;s saved data after 7 days of not opening it. Installed, your work ' +
              'is safe.</p>' +
            '<div style="text-align:left;background:rgba(255,255,255,.08);border:1px solid rgba(230,204,161,.3);' +
              'border-radius:8px;padding:18px 20px;">' +
              step(1, 'Tap the Share button', 'The square with an arrow, at the bottom of Safari.') +
              step(2, 'Scroll down and tap <b>Add to Home Screen</b>', '') +
              step(3, 'Tap Add', 'Then open Flowers.ae from your Home Screen, not from Safari.', true) +
            '</div>'
          : '<h1 style="font-family:\'EB Garamond\',Georgia,serif;font-size:24px;font-weight:700;' +
              'margin:32px 0 10px;line-height:1.3;">Please open this in Safari</h1>' +
            '<p style="font-size:14.5px;line-height:1.65;color:rgba(255,255,255,.88);margin:0 0 20px;">' +
              'On iPhone, only Safari can install this properly &mdash; and installing it is what ' +
              'keeps your work from being deleted.</p>' +
            '<p style="font-size:13.5px;color:rgba(230,204,161,.85);">Copy the address, open ' +
              'Safari, paste it there, then use Share &rarr; Add to Home Screen.</p>') +

        '<p style="font-size:12px;color:rgba(230,204,161,.6);margin-top:26px;line-height:1.6;">' +
          'Your PC and tablet apps are unaffected.</p>' +
      '</div>' +
    '</div>';

  function step(n, title, sub, last) {
    return '<div style="display:flex;gap:13px;align-items:flex-start;' +
      (last ? '' : 'margin-bottom:16px;') + '">' +
      '<span style="flex:none;width:25px;height:25px;border-radius:50%;background:#E6CCA1;' +
        'color:#550318;font-weight:700;font-size:12.5px;display:flex;align-items:center;' +
        'justify-content:center;">' + n + '</span>' +
      '<span><span style="font-size:14.5px;font-weight:700;">' + title + '</span>' +
        (sub ? '<span style="display:block;font-size:12.5px;color:rgba(230,204,161,.8);' +
               'margin-top:3px;line-height:1.5;">' + sub + '</span>' : '') +
      '</span></div>';
  }

  function show() {
    if (document.getElementById('fl-ios-gate')) return;
    document.body.insertAdjacentHTML('beforeend', html);
    document.documentElement.style.overflow = 'hidden';
  }
  if (document.body) show();
  else document.addEventListener('DOMContentLoaded', show);
})();
