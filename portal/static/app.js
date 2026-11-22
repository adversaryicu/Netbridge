'use strict';
const $ = id => document.getElementById(id);
let csrf = '', pairing = false, trustChallenge = '', refreshTimer;
const secure = location.protocol === 'https:';
const https = `https://${location.hostname}`;
function notice(text, error = false) { $('notice').hidden = false; $('notice').className = error ? 'error' : ''; $('notice').textContent = text; }
async function api(action, data) {
  const response = await fetch(`/api/${action}`, {method: data === undefined ? 'GET' : 'POST',
    credentials:'same-origin', headers: data === undefined ? {} : {'Content-Type':'application/json','X-NetBridge-CSRF':csrf},
    body: data === undefined ? undefined : JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) { const error = new Error(result.error || 'Request failed'); error.status = response.status; throw error; }
  if (result.csrf) csrf = result.csrf;
  return result;
}
function show(id) { for (const name of ['onboarding','trust','authentication','dashboard']) $(name).hidden = name !== id; }
function busy(form, action) { form.addEventListener('submit', async event => { event.preventDefault(); const button = form.querySelector('button'); button.disabled = true; try { await action(); } catch(error) { notice(error.message,true); } finally { button.disabled=false; } }); }
async function dashboard() {
  const state = await api('status'); show('dashboard');
  $('wan-state').textContent = state.wan_connected ? 'Connected' : 'Offline';
  $('client-count').textContent = state.clients.length;
  if (document.activeElement !== $('ssid')) $('ssid').value = state.ssid;
  const container = $('clients'); container.replaceChildren();
  if (!state.clients.length) { const p=document.createElement('p');p.className='empty';p.textContent=state.monitor==='ok'?'No devices connected. Join the NetBridge Wi-Fi network to begin.':'Client monitoring is unavailable. Approvals have been cleared.';container.append(p); }
  for (const client of state.clients) {
    const row=document.createElement('article'); row.className='client';
    const info=document.createElement('div'), title=document.createElement('h3'), identity=document.createElement('p'), status=document.createElement('p');
    title.textContent=client.name;identity.textContent=`${client.ip || 'Waiting for address'} · ${client.mac}`;
    status.className='client-state';status.textContent=client.approved?'Approved for this connection · inspection remains off':client.trust_confirmed?'Browser trust confirmed · awaiting operator approval':client.downloaded?'CA downloaded · browser trust not confirmed':'Connected · onboarding needed';
    info.append(title,identity,status);row.append(info);
    const button=document.createElement('button');button.textContent=client.approved?'Revoke approval':'Approve this connection';button.disabled=!client.trust_confirmed;
    button.addEventListener('click',async()=>{button.disabled=true;try{await api(client.approved?'revoke':'approve',{mac:client.mac});await dashboard();}catch(error){notice(error.message,true);button.disabled=false;}});
    row.append(button);container.append(row);
  }
  clearTimeout(refreshTimer);refreshTimer=setTimeout(()=>dashboard().catch(error=>{if(error.status===401){show('authentication');notice('Your session expired. Sign in again.');}else notice(error.message,true);}),5000);
}
async function init() {
  $('admin-link').href=`${https}/admin`;$('trust-link').href=`${https}/trust`;$('check-link').href=`${https}/trust`;
  let info;
  try { info=await api('public'); pairing=!info.paired;
    $('ca-name').textContent=info.ca.name;$('fingerprint').textContent=info.ca.fingerprint;
    $('ca-expiry').textContent=new Date(info.ca.expires).toLocaleDateString(undefined,{year:'numeric',month:'long',day:'numeric'});
  } catch(error) { notice(error.message,true);show('onboarding');return; }
  if(location.pathname==='/admin') {
    $('admin-link').classList.add('active');$('page-title').textContent='Your network, under control.';
    $('page-intro').textContent='Manage test devices, Wi-Fi access and the local certificate authority.';
    $('auth-title').textContent=pairing?'Pair your administrator account':'Sign in';
    $('auth-submit').textContent=pairing?'Create administrator account':'Sign in';
    $('pair-field').hidden=!pairing;$('pair-code').required=pairing;
    if(pairing){$('auth-copy').textContent='Use the one-time code from the operator, then choose an administrator password with at least 12 characters.';$('admin-password').autocomplete='new-password';}
    try{await dashboard();}catch(error){show('authentication');if(error.status!==401)notice(error.message,true);}
  } else if(location.pathname==='/trust') {
    $('trust-link').classList.add('active');show('trust');$('page-title').textContent='Check this browser’s trust.';
    try{const result=await api('trust-probe');trustChallenge=result.challenge;
      $('trust-title').textContent=result.confirmed?'Browser trust already confirmed':'This browser reached the HTTPS endpoint.';
      $('trust-copy').textContent='If no certificate warning appeared and you did not bypass one earlier, confirm below. Otherwise, return to setup and install the CA correctly.';
      $('trust-form').hidden=result.confirmed;
    }catch(error){$('trust-title').textContent='Trust check unavailable';$('trust-copy').textContent=error.message;}
  } else { $('onboard-link').classList.add('active');show('onboarding'); }
}
busy($('auth-form'),async()=>{const data={password:$('admin-password').value};if(pairing)data.code=$('pair-code').value.trim();await api(pairing?'pair':'login',data);$('admin-password').value='';$('pair-code').value='';pairing=false;notice('Signed in. Inspection remains off.');await dashboard();});
busy($('trust-form'),async()=>{await api('trust-confirm',{challenge:trustChallenge,no_warning:$('no-warning').checked});$('trust-form').hidden=true;$('trust-title').textContent='Browser trust confirmed.';$('trust-copy').textContent='The operator can now approve this Wi-Fi connection. Inspection is still off.';});
busy($('wifi-form'),async()=>{if(!confirm('Restart the hotspot and disconnect all connected clients?'))return;const result=await api('ap-settings',{ssid:$('ssid').value,password:$('wifi-password').value});$('wifi-password').value='';clearTimeout(refreshTimer);notice(result.message);});
busy($('password-form'),async()=>{await api('admin-password',{password:$('new-password').value});$('new-password').value='';clearTimeout(refreshTimer);show('authentication');notice('Administrator password changed. Sign in again.');});
busy($('rotate-form'),async()=>{const result=await api('rotate-ca',{confirmation:$('rotate-confirm').value});clearTimeout(refreshTimer);show('onboarding');notice(result.message);setTimeout(()=>location.href=`http://${location.hostname}/`,5000);});
$('logout').addEventListener('click',async()=>{try{await api('logout',{});clearTimeout(refreshTimer);show('authentication');notice('Signed out.');}catch(error){notice(error.message,true);}});
$('refresh').addEventListener('click',()=>dashboard().catch(error=>notice(error.message,true)));
init();
