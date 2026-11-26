const byId = id => document.getElementById(id);
let lastQr = '', currentChallenge = null, widget = null, provider, busy = false;
let confirmed = false;
const resetSignout = () => {
  confirmed = false;
  byId('signout').textContent = 'Sign out and delete all credentials';
};
const showError = message => {
  byId('error').textContent = message;
  byId('error').hidden = !message;
};
async function request(path, body) {
  const options = body === undefined ? {} : {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Activity-Request': '1'},
    body: JSON.stringify(body),
  };
  const result = await fetch(path, options);
  const data = await result.json();
  if (!result.ok) throw new Error(data.error || 'The console rejected the request.');
  return data;
}
function drawQr(url) {
  const canvas = byId('qr');
  canvas.hidden = !url;
  if (!url || url === lastQr) return;
  lastQr = url;
  const qr = qrcodegen.QrCode.encodeText(url, qrcodegen.QrCode.Ecc.MEDIUM);
  canvas.width = canvas.height = qr.size + 8;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#14221c';
  for (let y = 0; y < qr.size; y++)
    for (let x = 0; x < qr.size; x++)
      if (qr.getModule(x, y)) ctx.fillRect(x + 4, y + 4, 1, 1);
}
async function refresh() {
  const s = await request('/status');
  if (busy) return;
  const linking = ['linking', 'verification_required', 'verifying'].includes(s.state);
  const signedIn = s.state === 'ready';
  byId('login').hidden = signedIn;
  byId('account').hidden = !signedIn;
  byId('signin').hidden = s.saved || !['disconnected', 'error'].includes(s.state);
  byId('signout').hidden = !signedIn && !s.saved;
  byId('cancel').hidden = !linking;
  byId('status').textContent = s.qr_url ? 'Scan with the Discord mobile app, then approve the login.' :
    ({linking:'Preparing your sign-in…', connecting:'Connecting to Discord…',
      verifying:'Checking verification…', verification_required:'Discord requires verification.'}[s.state] ||
      'Connect Discord to show what you’re playing.');
  byId('identity').textContent = 'Signed in as ' + s.username;
  byId('activity').textContent = s.game ? 'Playing' : 'Waiting for a game…';
  byId('game').hidden = !s.game;
  byId('title').textContent = s.game?.name || '';
  const image = s.game?.image_url;
  const cover = byId('cover');
  if (image && cover.getAttribute('src') !== image) {
    cover.src = image;
    cover.hidden = false;
  } else if (!image) {
    cover.removeAttribute('src');
    cover.hidden = true;
  }
  drawQr(s.qr_url);
  showError(s.error);
  const challenge = s.state === 'verification_required' ? s.verification : null;
  if (currentChallenge?.id !== challenge?.id) {
    if (widget !== null) window.hcaptcha?.remove(widget);
    widget = null;
    currentChallenge = challenge;
  }
  byId('challenge').hidden = !challenge;
  byId('verify').hidden = widget !== null;
}
async function action(path, body = {}) {
  if (busy) return;
  busy = true;
  try {
    showError('');
    await request(path, body);
  } catch (error) {
    showError(error.message);
  } finally {
    busy = false;
  }
}
byId('signin').onclick = () => action('/signin');
byId('cancel').onclick = () => action('/cancel');
byId('signout').onclick = () => {
  if (!confirmed) {
    confirmed = true;
    byId('signout').textContent = 'Confirm deletion of saved credentials';
    setTimeout(resetSignout, 6000);
    return;
  }
  resetSignout();
  void action('/signout');
};
byId('cover').onerror = () => { byId('cover').hidden = true; };
byId('verify').onclick = async () => {
  const challenge = currentChallenge;
  if (!challenge || widget !== null) return;
  try {
    if (!provider) provider = new Promise((resolve, reject) => {
      window.activityCaptchaReady = resolve;
      const script = document.createElement('script');
      script.src = 'https://js.hcaptcha.com/1/api.js?onload=activityCaptchaReady&render=explicit&recaptchacompat=off';
      script.onerror = reject;
      document.head.append(script);
    });
    await provider;
    if (currentChallenge?.id !== challenge.id || widget !== null) return;
    widget = window.hcaptcha.render(byId('widget'), {
      sitekey: challenge.sitekey, theme: 'dark',
      callback: solution => action('/verify', {challenge_id: challenge.id, solution}),
    });
    if (challenge.rqdata) window.hcaptcha.setData(widget, {rqdata: challenge.rqdata});
  } catch (_) {
    provider = null;
    showError('Verification could not load. Try again or cancel sign-in.');
  }
};
async function poll() {
  try { await refresh(); }
  catch (_) { showError('Cannot reach the console. Retrying…'); }
  finally { setTimeout(poll, 1000); }
}
void poll();
