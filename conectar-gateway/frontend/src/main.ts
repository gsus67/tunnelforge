// Gateway WISP Access frontend — TypeScript migration.
// Wails owns the desktop shell; this file is compiled as a classic script so
// existing inline UI handlers remain accessible while the codebase is typed incrementally.
interface GatewayRuntimeConfig { token: string; wsBase: string; version: string; }
interface Window {
  go: { main: { AppBridge: { GetRuntimeConfig(): Promise<GatewayRuntimeConfig> } } };
}

interface HTMLElement { value: any; checked: any; disabled: any; files: any; options: any; _t: any; }
interface Element { value: any; checked: any; disabled: any; dataset: DOMStringMap; onclick: any; type: any; }
interface EventTarget { closest: any; value: any; checked: any; disabled: any; dataset: any; }
interface GlobalEventHandlers { classList: DOMTokenList; disabled: any; textContent: any; checked: any; value: any; }
declare var Terminal: any;
declare var FitAddon: any;

var TOKEN = '';
  var WS_BASE = '';
  var RUNTIME_READY = (async function(){
    try {
      var cfg = await window.go.main.AppBridge.GetRuntimeConfig();
      TOKEN = cfg.token || '';
      WS_BASE = (cfg.wsBase || '').replace(/\/$/, '');
      return cfg;
    } catch (err) {
      console.error('No se pudo inicializar el puente Wails', err);
      throw err;
    }
  })();
  function api(ruta: any, opciones?: any){
    opciones = opciones || {};
    return RUNTIME_READY.then(function(){
      opciones.headers = Object.assign({'X-Token': TOKEN, 'Content-Type':'application/json'}, opciones.headers||{});
      return fetch(ruta, opciones).then(function(r){ return r.json(); });
    });
  }
  function aviso(texto: any, ok?: any){
    var a = document.getElementById('aviso');
    a.textContent = texto;
    a.classList.toggle('caida', !ok);
    a.style.borderLeftColor = ok ? 'var(--verde)' : 'var(--rojo)';
    a.style.display = 'block';
    clearTimeout(a._t); a._t = setTimeout(function(){ a.style.display='none'; }, 4500);
  }
  var $: any = function(id: any){ return document.getElementById(id); };

  // Todo dato que venga de servidores, archivos o backups se inserta como texto,
  // nunca como HTML. Esto evita ejecutar contenido no confiable en la vista Wails.
  function vaciar(el: any){ while (el.firstChild) el.removeChild(el.firstChild); }
  function nodo(tag: any, clase?: any, texto?: any){
    var el = document.createElement(tag);
    if (clase) el.className = clase;
    if (texto !== undefined && texto !== null) el.textContent = String(texto);
    return el;
  }
  function svgAccion(tipo){
    var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('viewBox','0 0 24 24');
    function add(tag,attrs){ var x=document.createElementNS('http://www.w3.org/2000/svg',tag); Object.keys(attrs).forEach(function(k){x.setAttribute(k,attrs[k]);}); svg.appendChild(x); }
    if(tipo==='terminal'){ add('rect',{x:'4',y:'5',width:'16',height:'14',rx:'1.5'}); add('path',{d:'M7 9l3 3-3 3'}); add('path',{d:'M12 15h5'}); }
    else if(tipo==='files'){ add('path',{d:'M4 7h6l2 2h8v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7z'}); add('path',{d:'M4 9h16'}); }
    else if(tipo==='tools'){ add('path',{d:'M14.7 6.3a4 4 0 0 0-5 5L4 17v3h3l5.7-5.7a4 4 0 0 0 5-5l-2.3 2.3-3-3 2.3-2.3z'}); }
    else if(tipo==='disconnect'){ add('path',{d:'M12 3v8'}); add('path',{d:'M7.2 5.8a8 8 0 1 0 9.6 0'}); }
    return svg;
  }
  function botonAccion(tipo: any, titulo: any, clase?: any){
    var b=nodo('button','mini-action'+(clase?' '+clase:''),''); b.title=titulo; b.setAttribute('aria-label',titulo); b.appendChild(svgAccion(tipo)); return b;
  }
  function mensajeEn(cont: any, clase?: any, texto?: any){
    vaciar(cont);
    cont.appendChild(nodo('div', clase, texto));
  }

  function fmtB(b){
    if (b === null || b === undefined) return '—';
    var u = ['B','KB','MB','GB'], i = 0;
    while (b >= 1024 && i < u.length-1){ b /= 1024; i++; }
    return (b >= 100 ? Math.round(b) : b.toFixed(1)) + ' ' + u[i];
  }
  function fmtBs(b){ if (b === null || b === undefined) return '—'; var m=(Math.max(0,b)*8)/1000000; return (m < 10 ? m.toFixed(2) : m.toFixed(1)) + ' Mbit/s'; }

  // ── Conexiones activas (multiples) ───────────────────────────
  var estadoActual = {conectado:false, conexiones:[]};
  var previoConectados = {};          // para detectar caidas no solicitadas
  var desconectandoManual = {};       // evita falso aviso de "caida" al desconectar a proposito
  var previoBytes = {};               // nombre -> {t, rx, tx} para calcular tasas

  var sshSeguridadCache = {};
  function rotularSeguridadSSH(btn, modo){
    btn.classList.remove('seguro','password');
    btn.dataset.modo = modo || 'unknown';
    if (modo === 'secure'){
      btn.textContent = 'SSH seguro';
      btn.title = 'Contraseña desactivada. Click para volver a permitir contraseña a usuarios normales.';
      btn.classList.add('seguro');
    } else if (modo === 'password'){
      btn.textContent = 'SSH password';
      btn.title = 'PasswordAuthentication está permitido. Click para asegurar SSH y dejar acceso por key.';
      btn.classList.add('password');
    } else {
      btn.textContent = 'Seguridad SSH';
      btn.title = 'Comprobar o cambiar la política de autenticación SSH.';
    }
  }
  function consultarSeguridadSSH(nombre, btn, forzar){
    var ahora = Date.now(), c = sshSeguridadCache[nombre];
    if (!forzar && c && ahora-c.t < 30000){ rotularSeguridadSSH(btn,c.modo); return; }
    api('/api/ssh-seguridad/estado?nombre='+encodeURIComponent(nombre)).then(function(r){
      var modo = r.modo || 'unknown';
      sshSeguridadCache[nombre] = {modo:modo,t:Date.now()};
      if (btn && document.body.contains(btn)) rotularSeguridadSSH(btn,modo);
    }).catch(function(){ if(btn && document.body.contains(btn)) rotularSeguridadSSH(btn,'unknown'); });
  }
  function alternarSeguridadSSH(nombre, btn){
    var modo = btn.dataset.modo || 'unknown';
    if (modo === 'secure'){
      if (!confirm('¿Volver a permitir autenticación por contraseña para usuarios normales?\n\nRoot seguirá permitido solo mediante key.')) return;
      var sudoPass = prompt('Contraseña del usuario para sudo/verificación (si estás conectado como root, puedes dejarla vacía):','');
      if (sudoPass === null) return;
      btn.disabled=true; btn.textContent='Aplicando…';
      api('/api/ssh-seguridad/permitir-password',{method:'POST',body:JSON.stringify({nombre:nombre,password:sudoPass})}).then(function(r){
        if (r.error){ aviso(r.error,false); return; }
        sshSeguridadCache[nombre]={modo:'password',t:Date.now()};
        rotularSeguridadSSH(btn,'password');
        aviso(r.passwordProbado ? 'Acceso por contraseña habilitado y verificado. Root sigue solo por key.' : 'PasswordAuthentication habilitado. Root sigue solo por key.',true);
      }).catch(function(){ aviso('Error de comunicación al cambiar la seguridad SSH.',false); }).finally(function(){ btn.disabled=false; });
      return;
    }
    var pass = prompt('Escribe la contraseña SSH actual. Gateway la usa para sudo y para comprobar que, después del cambio, una conexión nueva por contraseña sea rechazada:','');
    if (pass === null) return;
    if (!pass){ aviso('Necesito la contraseña actual para verificar de forma real que el login por password queda bloqueado.',false); return; }
    if (!confirm('Gateway comprobará primero la key, desactivará el login por contraseña y mantendrá root solo por key. ¿Continuar?')) return;
    btn.disabled=true; btn.textContent='Asegurando…';
    api('/api/asegurar-ssh',{method:'POST',body:JSON.stringify({nombre:nombre,password:pass})}).then(function(r){
      if (r.error){ aviso(r.error,false); return; }
      sshSeguridadCache[nombre]={modo:'secure',t:Date.now()};
      rotularSeguridadSSH(btn,'secure');
      aviso('SSH asegurado y verificado. Contraseña bloqueada; root queda solo por key.',true);
    }).catch(function(){ aviso('Error de comunicación al asegurar SSH.',false); }).finally(function(){ btn.disabled=false; });
  }
  function pintarConexiones(e){
    $('ver').textContent = 'v' + (e.version||'');
    var pv = $('pie-ver'); if (pv) pv.textContent = 'v' + (e.version||'');
    var cont = $('conexiones');
    var lista = e.conexiones || [];
    var infoCon=$('info-connected'); if(infoCon) infoCon.textContent=String(lista.length);
    var infoLocal=$('info-localhost'); if(infoLocal) infoLocal.textContent=e.localhostSeleccionado||'Ninguno';
    var actuales = {};
    lista.forEach(function(c){ actuales[c.servidor] = true; });

    Object.keys(previoConectados).forEach(function(nombre){
      if (!actuales[nombre] && !desconectandoManual[nombre]){
        aviso('Se perdió la conexión con ' + nombre + '.', false);
      }
      delete desconectandoManual[nombre];
    });
    previoConectados = actuales;

    if (!lista.length){
      mensajeEn(cont, 'sin-conexion', 'Sin conexiones. Elige un servidor abajo y dale a Conectar.');
      return;
    }
    var ahora = Date.now();
    vaciar(cont);
    lista.forEach(function(c){
      var prev = previoBytes[c.servidor];
      var rxS = 0, txS = 0;
      if (prev){
        var dt = (ahora - prev.t) / 1000;
        if (dt > 0.5){ rxS = Math.max(0,(c.rx-prev.rx)/dt); txS = Math.max(0,(c.tx-prev.tx)/dt); }
      }
      previoBytes[c.servidor] = {t: ahora, rx: c.rx, tx: c.tx};

      var div = nodo('div', 'cnx');
      var fila = nodo('div', 'fila1');
      fila.appendChild(nodo('span', 'led'));
      var txt = nodo('div', 'txt');
      txt.appendChild(nodo('b', '', c.servidor));
      txt.appendChild(document.createTextNode((c.host||'servidor') + ' · ' + (c.usuario||'usuario')));
      fila.appendChild(txt);

      var bTerm = botonAccion('terminal','Terminal');
      bTerm.onclick = function(){ abrirTerminal(c.servidor); };
      fila.appendChild(bTerm);
      var bArch = botonAccion('files','Archivos');
      bArch.onclick = function(){ abrirArchivos(c.servidor); };
      fila.appendChild(bArch);
      var bTools = botonAccion('tools','Herramientas');
      bTools.onclick = function(){ abrirHerramientas(c.servidor); };
      fila.appendChild(bTools);
      var bDesc = botonAccion('disconnect','Desconectar este servidor','disconnect');
      bDesc.onclick = function(){
        desconectandoManual[c.servidor] = true;
        api('/api/desconectar',{method:'POST',body:JSON.stringify({nombre:c.servidor})}).then(function(){ refrescarEstado(); });
      };
      fila.appendChild(bDesc);

      var trafico = nodo('div', 'trafico');
      trafico.appendChild(document.createTextNode(c.desde || ''));
      fila.appendChild(trafico);
      div.appendChild(fila);

      var meta = nodo('div','cnx-meta');
      var bLocal=nodo('button','localhost-pick'+(c.localhost?' active':''),c.localhost?'✓':'');
      bLocal.title=c.localhost ? 'Este servidor responde ahora en localhost:puerto' : 'Usar este servidor para los puertos localhost compartidos';
      bLocal.setAttribute('aria-label',bLocal.title);
      bLocal.onclick=function(){
        api('/api/localhost-servidor',{method:'POST',body:JSON.stringify({nombre:c.servidor})}).then(function(r){
          if(r.error){ aviso(r.error,false); return; }
          aviso('localhost:puerto ahora apunta a '+c.servidor+'.',true);
          refrescarEstado();
        });
      };
      meta.appendChild(bLocal);
      var tuneles = c.tuneles || [];
      var puertosActivos={}; (c.puertos||[]).forEach(function(p){puertosActivos[p]=true;});
      var ports = nodo('div','ports-list');
      if (tuneles.length){
        var bPorts=nodo('button','ports-toggle','Puertos '+tuneles.length);
        bPorts.title='Mostrar/ocultar túneles';
        bPorts.onclick=function(){ ports.classList.toggle('open'); };
        meta.appendChild(bPorts);
        tuneles.forEach(function(t){
          if(puertosActivos[t.puerto]){
            var a=nodo('a','', ''); a.href='#'; a.dataset.url='http://localhost:'+t.puerto+(t.ruta||'');
            a.appendChild(nodo('b','', ':'+t.puerto)); a.appendChild(document.createTextNode(' '+(t.nombre||''))); ports.appendChild(a);
          } else {
            var off=nodo('span','port-off', ':'+t.puerto+' '+(t.nombre||''));
            off.title=c.localhost ? 'Este puerto está ocupado por otro programa local.' : 'Marca esta casilla para intentar asignar los puertos compartidos a este servidor.';
            ports.appendChild(off);
          }
        });
      } else {
        meta.appendChild(nodo('span','ports-toggle','Sin puertos'));
      }
      var bSSH = nodo('button','ssh-seg','SSH');
      bSSH.onclick=function(){ alternarSeguridadSSH(c.servidor,bSSH); };
      meta.appendChild(bSSH); consultarSeguridadSSH(c.servidor,bSSH,false);
      var traficoReal=!!c.traficoDisponible;
      var down=traficoReal ? (c.traficoRxBps||0) : rxS;
      var up=traficoReal ? (c.traficoTxBps||0) : txS;
      var stats=nodo('span','stats-mini'+(traficoReal?' server-net':''),'↓ '+fmtBs(down)+' · ↑ '+fmtBs(up));
      stats.title=traficoReal ? ('Tráfico real del servidor'+(c.traficoInterfaz?' · '+c.traficoInterfaz:'')) : 'Tráfico observado en los túneles SSH';
      meta.appendChild(stats);
      div.appendChild(meta);
      div.appendChild(ports);
      cont.appendChild(div);
    });
  }
  function refrescarEstado(){
    api('/api/estado').then(function(e){ estadoActual=e; pintarConexiones(e); refrescarSelectorServidores(); }).catch(function(){});
  }
  setInterval(refrescarEstado, 3000); refrescarEstado();

  // Enlaces de las conexiones: abren en el navegador del sistema
  document.addEventListener('click', function(e){
    var a = e.target.closest ? e.target.closest('a[data-url]') : null;
    if (!a) return;
    e.preventDefault();
    abrirFuera(a.getAttribute('data-url'));
  });

  // ── Lista de servidores: buscador + favoritos + arrastrar ────
  var servidoresCache = [];
  function pintarLista(lista){
    servidoresCache = lista;
    var infoSaved=$('info-saved'); if(infoSaved) infoSaved.textContent=String((lista||[]).length);
    var cta = document.getElementById('srv-cuenta');
    if (cta) cta.textContent = '— ' + lista.length + ' servidor' + (lista.length===1?'':'es');
    var filtro = ($('buscador').value || '').toLowerCase().trim();
    var mostrar = lista.filter(function(s){
      if (!filtro) return true;
      return (s.nombre + ' ' + s.host + ' ' + s.usuario).toLowerCase().indexOf(filtro) !== -1;
    });
    mostrar.sort(function(a,b){ return (b.favorito?1:0) - (a.favorito?1:0); });

    var cont = $('lista');
    if (!lista.length){
      mensajeEn(cont, 'vacio', 'Ningún servidor todavía — agrega el primero abajo.');
      return;
    }
    if (!mostrar.length){
      mensajeEn(cont, 'vacio', 'Sin resultados para "' + filtro + '".');
      return;
    }
    vaciar(cont);
    mostrar.forEach(function(s){
      var div = nodo('div', 'srv');
      div.draggable = true; div.dataset.nombre = s.nombre;
      var metodo = s.key ? 'key' : (s.tienePassword ? 'contraseña guardada' : 'contraseña al conectar');

      var asa = nodo('span', 'asa', '⠿'); asa.title = 'Arrastra para reordenar';
      div.appendChild(asa); div.appendChild(nodo('div', 'franja'));
      var fav = nodo('button', 'fav' + (s.favorito ? ' on' : ''), s.favorito ? '★' : '☆');
      fav.title = 'Favorito';
      fav.onclick = function(ev){
        ev.stopPropagation();
        api('/api/servidores', {method:'POST', body: JSON.stringify({
          nombre: s.nombre, host: s.host, puerto: s.puerto, usuario: s.usuario,
          key: s.key, favorito: !s.favorito, tuneles: s.tuneles || []
        })}).then(refrescarLista);
      };
      div.appendChild(fav);
      var info = nodo('div', 'info');
      info.appendChild(nodo('div', 'nombre', s.nombre));
      info.appendChild(nodo('div', 'detalle', s.host + ' · ' + s.usuario));
      div.appendChild(info);
      div.appendChild(nodo('span', 'metodo', 'SSH :' + s.puerto));
      var tags = nodo('div','srv-tags');
      tags.appendChild(nodo('span','tag ' + (s.key ? 'key':'pass'), s.key ? 'Key SSH' : (s.tienePassword ? 'Contraseña guardada' : 'Password al conectar')));
      if (s.confiado) tags.appendChild(nodo('span','tag fingerprint','Huella verificada'));
      div.appendChild(tags);

      var acciones = nodo('div', 'acciones');
      var bC = nodo('button', 'principal', 'Conectar');
      bC.onclick = function(){ conectar(s.nombre, '', false); };
      var bE = nodo('button', '', 'Editar');
      bE.onclick = function(){ abrirFormulario(); cargarEnForm(s); };
      var bB = nodo('button', 'peligro', '✕');
      bB.title = 'Borrar';
      bB.onclick = function(){
        if (confirm('¿Borrar "' + s.nombre + '"?'))
          api('/api/servidores?nombre=' + encodeURIComponent(s.nombre), {method:'DELETE'}).then(refrescarLista);
      };
      acciones.appendChild(bC); acciones.appendChild(bE); acciones.appendChild(bB);
      div.appendChild(acciones);
      cont.appendChild(div);
    });
    activarArrastre(cont);
  }
  function refrescarLista(){ api('/api/servidores').then(pintarLista).catch(function(){}); }
  refrescarLista();
  $('buscador').addEventListener('input', function(){ pintarLista(servidoresCache); });
  if ($('btn-new-toolbar')) $('btn-new-toolbar').onclick = function(){ abrirFormulario(); mostrarVista('profiles'); };
  if ($('btn-import-toolbar')) $('btn-import-toolbar').onclick = function(){ mostrarVista('backup'); setTimeout(function(){ var el=$('imp-archivo'); if(el) el.click(); }, 50); };
  if ($('btn-desc-todo')) $('btn-desc-todo').onclick = function(){
    if(!window.confirm('¿Desconectar todas las sesiones activas?')) return;
    api('/api/estado').then(function(e){
      return Promise.all((e.conexiones||[]).map(function(c){ desconectandoManual[c.servidor]=true; return api('/api/desconectar',{method:'POST', body: JSON.stringify({nombre:c.servidor})}).catch(function(){}); }));
    }).then(function(){ setTimeout(refrescarEstado, 200); });
  };
  if ($('srv-view-grid')) $('srv-view-grid').onclick = function(){ $('lista').style.gridTemplateColumns='repeat(2,minmax(0,1fr))'; };
  if ($('srv-view-list')) $('srv-view-list').onclick = function(){ $('lista').style.gridTemplateColumns='1fr'; };
  if ($('dash-upd-search')) $('dash-upd-search').onclick = function(){ updBuscar(false); };
  if ($('lista')) $('lista').style.gridTemplateColumns='repeat(2,minmax(0,1fr))';


  // Arrastrar para reordenar (HTML5 drag & drop nativo)
  function activarArrastre(cont){
    var arrastrando = null;
    cont.querySelectorAll('.srv').forEach(function(el){
      el.addEventListener('dragstart', function(){ arrastrando = el; el.classList.add('arrastrando'); });
      el.addEventListener('dragend', function(){
        el.classList.remove('arrastrando');
        var nombres = Array.prototype.map.call(cont.querySelectorAll('.srv'), function(x){ return x.dataset.nombre; });
        api('/api/servidores/orden', {method:'POST', body: JSON.stringify(nombres)}).then(refrescarLista);
      });
      el.addEventListener('dragover', function(ev){
        ev.preventDefault();
        if (!arrastrando || arrastrando === el) return;
        var despues = (ev.clientY - el.getBoundingClientRect().top) > el.offsetHeight / 2;
        cont.insertBefore(arrastrando, despues ? el.nextSibling : el);
      });
    });
  }

  // ── Formulario ────────────────────────────────────────────────
  function cargarEnForm(s){
    $('f-nombre').value = s.nombre; $('f-host').value = s.host;
    $('f-puerto').value = s.puerto; $('f-usuario').value = s.usuario;
    $('f-key').value = s.key || ''; $('f-pass').value = '';
    $('f-guardar').checked = !!s.tienePassword;
    pintarTunelesForm(s.tuneles || tunelesDefecto);
  }
  $('btn-limpiar').onclick = function(){
    ['f-nombre','f-host','f-usuario','f-key','f-pass'].forEach(function(i){ $(i).value=''; });
    $('f-puerto').value = 22; $('f-guardar').checked = false; pintarTunelesForm(tunelesDefecto);
  };
  function guardarServidorDesdeForm(){
    var nombre = $('f-nombre').value.trim();
    var existente = servidoresCache.find(function(s){ return s.nombre === nombre; });
    api('/api/servidores', {method:'POST', body: JSON.stringify({
      nombre: nombre, host: $('f-host').value.trim(),
      puerto: parseInt($('f-puerto').value)||22, usuario: $('f-usuario').value.trim(),
      key: $('f-key').value.trim(), password: $('f-pass').value,
      guardarPassword: $('f-guardar').checked,
      favorito: existente ? existente.favorito : false,
      tuneles: leerTunelesForm()
    })}).then(function(r){
      if (r.error){ aviso(r.error, false); return; }
      aviso('Servidor guardado.', true);
      $('btn-limpiar').click();
      refrescarLista();
    });
  }
  $('btn-guardar').onclick = guardarServidorDesdeForm;

  // ── Asistente de clave SSH ─────────────────────────────────
  var seguridadPendiente = null;
  function cerrarModalSeguridad(){
    $('m-seguridad').classList.remove('abierto');
    seguridadPendiente = null;
  }
  function crearInstalarKey(aceptarHuella){
    var pet={nombre:$('f-nombre').value.trim(),host:$('f-host').value.trim(),puerto:parseInt($('f-puerto').value)||22,usuario:$('f-usuario').value.trim(),password:$('f-pass').value,aceptarHuella:!!aceptarHuella,tuneles:leerTunelesForm()};
    if(!pet.nombre||!pet.host||!pet.usuario||!pet.password){ aviso('Completa nombre, host, usuario y la contraseña actual del servidor.',false); return; }
    var passwordActual=pet.password;
    var b=$('btn-crear-key'); b.disabled=true; b.textContent='Instalando…';
    api('/api/crear-instalar-key',{method:'POST',body:JSON.stringify(pet)}).then(function(r){
      if(r.confirmarHuella){ if(confirm('Primera conexión a este servidor. Huella SSH:\n\n'+r.confirmarHuella+'\n\n¿Confiar e instalar la clave?')) crearInstalarKey(true); return; }
      if(r.error){ aviso(r.error,false); return; }
      $('f-key').value=r.key||''; $('f-pass').value=''; $('f-guardar').checked=false;
      $('key-res').textContent='✓ Key ED25519 creada, instalada y comprobada. Huella de la key: '+(r.huella||'');
      seguridadPendiente={nombre:pet.nombre,password:passwordActual};
      $('m-seguridad').classList.add('abierto');
      aviso('Clave SSH instalada y comprobada. Ya puedes conectar sin contraseña.',true);
      refrescarLista();
    }).catch(function(){ aviso('Error de comunicación al instalar la key.',false); }).finally(function(){ b.disabled=false; b.textContent='🔑 Crear e instalar Key'; });
  }
  $('btn-crear-key').onclick=function(){ crearInstalarKey(false); };
  $('seg-no').onclick=function(){
    cerrarModalSeguridad();
    aviso('La key quedó configurada. SSH conserva la autenticación por contraseña.',true);
  };
  $('seg-si').onclick=function(){
    if(!seguridadPendiente){ cerrarModalSeguridad(); return; }
    var datos=seguridadPendiente;
    var b=$('seg-si'); b.disabled=true; b.textContent='Asegurando…';
    api('/api/asegurar-ssh',{method:'POST',body:JSON.stringify(datos)}).then(function(r){
      if(r.error){ aviso(r.error,false); return; }
      cerrarModalSeguridad();
      aviso('SSH asegurado y verificado: una conexión nueva con contraseña fue rechazada; root queda solo por key.',true);
    }).catch(function(){ aviso('Error de comunicación al asegurar SSH.',false); }).finally(function(){ b.disabled=false; b.textContent='Sí, asegurar SSH'; });
  };

  // ── Conectar (con flujo de huella y contraseña) ──────────────
  var pendiente = null;
  var terminalTras = null;
  function conectar(nombre, password, aceptarHuella){
    aviso('Conectando a ' + nombre + '…', true);
    api('/api/conectar', {method:'POST', body: JSON.stringify({
      nombre: nombre, password: password, aceptarHuella: aceptarHuella
    })}).then(function(r){
      if (r.error){ aviso(r.error, false); return; }
      if (r.necesitaPassphrase){
        pendiente = {nombre: nombre, aceptarHuella: aceptarHuella};
        $('pass-para').textContent = 'La clave SSH de ' + nombre + ' tiene passphrase. Escríbela:';
        $('pass-input').value = '';
        $('m-pass').classList.add('abierto');
        $('pass-input').focus();
        return;
      }
      if (r.necesitaPassword){
        pendiente = {nombre: nombre, aceptarHuella: aceptarHuella};
        $('pass-para').textContent = 'Escribe la contraseña para ' + nombre + ' (no se guardará):';
        $('pass-input').value = '';
        $('m-pass').classList.add('abierto');
        $('pass-input').focus();
        return;
      }
      if (r.confirmarHuella){
        pendiente = {nombre: nombre, password: password};
        $('huella-txt').textContent = r.confirmarHuella;
        $('m-huella').classList.add('abierto');
        return;
      }
      if (r.ok){
        var msg;
        if (r.sinTuneles){
          msg = 'Conectado a ' + nombre + ' — sin túneles (puertos ocupados por otra conexión). Usa la terminal.';
        } else {
          msg = 'Conectado. Túneles: ' + r.puertos.join(', ');
          if (r.puertosOmitidos) msg += ' (omitidos por estar ocupados: ' + r.puertosOmitidos.join(', ') + ')';
        }
        aviso(msg, true);
        refrescarEstado();
        (r.abrirWeb || []).forEach(function(url){ abrirFuera(url); });
        if (terminalTras){
          var srv = terminalTras; terminalTras = null;
          setTimeout(function(){ abrirTerminal(srv); }, 300);
        }
      }
    }).catch(function(){ aviso('Error de comunicación con la app.', false); });
  }
  function pedirTerminal(nombre){
    if (estadoActual.conexiones && estadoActual.conexiones.some(function(c){ return c.servidor === nombre; })){
      abrirTerminal(nombre); return;
    }
    terminalTras = nombre;
    conectar(nombre, '', false);
  }
  $('huella-si').onclick = function(){
    $('m-huella').classList.remove('abierto');
    conectar(pendiente.nombre, pendiente.password || '', true);
  };
  $('huella-no').onclick = function(){ $('m-huella').classList.remove('abierto'); };
  $('pass-si').onclick = function(){
    $('m-pass').classList.remove('abierto');
    conectar(pendiente.nombre, $('pass-input').value, pendiente.aceptarHuella || false);
  };
  $('pass-input').addEventListener('keydown', function(e){
    if (e.key === 'Enter') $('pass-si').click();
  });
  $('pass-no').onclick = function(){ $('m-pass').classList.remove('abierto'); };

  // Guardar estado por si la API cambia de forma (usado por pedirTerminal)
  api('/api/estado').then(function(e){ estadoActual = e; });

  // ── Túneles por servidor ───────────────────────────────────
  var tunelesDefecto = [
    {puerto:8888,nombre:'Panel',ruta:''}, {puerto:10086,nombre:'WGDashboard',ruta:''},
    {puerto:19999,nombre:'Netdata',ruta:''}, {puerto:6060,nombre:'CrowdSec',ruta:'/metrics'},
    {puerto:60601,nombre:'Bouncer',ruta:'/metrics'}
  ];
  function actualizarCuentaTuneles(){ var n=document.querySelectorAll('#tun-lista .tun-fila').length; if($('tun-cuenta')) $('tun-cuenta').textContent='— '+n+' túnel'+(n===1?'':'es'); }
  function filaTunel(t){
    var d=nodo('div','tun-fila');
    var p=nodo('input','p'); p.type='number'; p.min='1'; p.max='65535'; p.value=t.puerto||''; p.placeholder='8888';
    var n=nodo('input','n'); n.type='text'; n.value=t.nombre||''; n.placeholder='Nombre del servicio';
    var r=nodo('input','r'); r.type='text'; r.value=t.ruta||''; r.placeholder='/opcional';
    var aw=nodo('div','aw'); var ch=document.createElement('input'); ch.type='checkbox'; ch.className='auto-web'; ch.checked=!!t.abrirWeb; ch.title='Abrir web al conectar'; aw.appendChild(ch);
    var b=nodo('button','peligro','✕'); b.type='button'; b.title='Quitar este túnel'; b.onclick=function(){d.remove();actualizarCuentaTuneles();};
    d.appendChild(p); d.appendChild(n); d.appendChild(r); d.appendChild(aw); d.appendChild(b); return d;
  }
  function pintarTunelesForm(lista){ var c=$('tun-lista'); vaciar(c); var l=lista||[]; l.forEach(function(t){c.appendChild(filaTunel(t));}); actualizarCuentaTuneles(); }
  function leerTunelesForm(){ var out=[]; document.querySelectorAll('#tun-lista .tun-fila').forEach(function(f){ var p=parseInt(f.querySelector('.p').value); if(!p)return; out.push({puerto:p,nombre:f.querySelector('.n').value.trim(),ruta:f.querySelector('.r').value.trim(),abrirWeb:f.querySelector('.auto-web').checked}); }); return out; }
  $('tun-agregar').onclick=function(){ $('tun-lista').appendChild(filaTunel({})); actualizarCuentaTuneles(); };
  $('tun-defecto').onclick=function(){ pintarTunelesForm(tunelesDefecto); };
  pintarTunelesForm(tunelesDefecto);

  // ── Terminal SSH integrado (+ historial) ─────────────────────
  var term = null, fit = null, wsTerm = null, servidorTerminal = null;
  var bufferLinea = '';

  function abrirTerminal(nombre: any, comandoInicial?: any, comandoSilencioso?: any){
    if (typeof Terminal !== 'function' || typeof FitAddon === 'undefined' || typeof FitAddon.FitAddon !== 'function'){
      aviso('No se pudieron cargar los componentes de la terminal. Reinicia la aplicación o reinstala esta versión.', false);
      return;
    }
    if (term) cerrarTerminalUI();
    servidorTerminal = nombre;
    document.getElementById('term-srv').textContent = nombre;
    document.getElementById('term-velo').classList.add('abierto');
    var termNodo = document.getElementById('term');
    vaciar(termNodo);
    term = new Terminal({
      cursorBlink: true, fontSize: 14,
      fontFamily: "'JetBrains Mono', Consolas, monospace",
      theme: { background: '#060D11', foreground: '#D8E4EA',
               cursor: '#E8A33D', selectionBackground: '#1F3B49' }
    });
    fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(termNodo);
    fit.fit();

    // La ventana Wails puede devolver el foco al botón que abrió la terminal.
    // Reforzamos el foco tras el layout y al hacer click dentro de xterm.
    setTimeout(function(){ if (term){ fit.fit(); term.focus(); } }, 0);
    setTimeout(function(){ if (term) term.focus(); }, 80);

    cargarHistorialTerminal(nombre);
    bufferLinea = '';

    wsTerm = new WebSocket(WS_BASE + '/ws/terminal?t=' + TOKEN + '&nombre=' + encodeURIComponent(nombre));
    wsTerm.binaryType = 'arraybuffer';
    var codificador = new TextEncoder();
    wsTerm.onopen = function(){
      if (!term) return;
      wsTerm.send(JSON.stringify({cols: term.cols, rows: term.rows}));
      term.focus();
      if (comandoInicial){
        if (comandoSilencioso){
          setTimeout(function(){
            if (!wsTerm || wsTerm.readyState !== 1 || !term) return;
            wsTerm.send(codificador.encode('stty -echo\r'));
            setTimeout(function(){
              if (!term || !wsTerm || wsTerm.readyState !== 1) return;
              term.clear();
              term.write('\x1b[2J\x1b[H');
              wsTerm.send(codificador.encode(comandoInicial + '; __gw_rc=$?; stty echo; printf "\\n"\r'));
            }, 140);
          }, 300);
        } else {
          setTimeout(function(){
            if (wsTerm && wsTerm.readyState === 1){
              wsTerm.send(codificador.encode(comandoInicial + '\r'));
              guardarComandoHistorial(nombre, comandoInicial);
            }
          }, 250);
        }
      }
    };
    wsTerm.onmessage = function(e){ if (term) term.write(new Uint8Array(e.data)); };
    wsTerm.onerror = function(){ if (term) term.write('\r\n\x1b[31m[error en la conexión de terminal]\x1b[0m\r\n'); };
    wsTerm.onclose = function(){ if (term) term.write('\r\n\x1b[33m[sesión terminada]\x1b[0m\r\n'); };
    term.onData(function(d){
      if (wsTerm && wsTerm.readyState === 1) wsTerm.send(codificador.encode(d));
      // capturar linea completa para el historial (best-effort, ignora control keys)
      if (d === '\r' || d === '\n'){
        var linea = bufferLinea.trim();
        bufferLinea = '';
        if (linea) guardarComandoHistorial(nombre, linea);
      } else if (d === '\x7f'){ // backspace
        bufferLinea = bufferLinea.slice(0, -1);
      } else if (d.length === 1 && d >= ' '){
        bufferLinea += d;
      }
    });
    term.onResize(function(t){
      if (wsTerm && wsTerm.readyState === 1) wsTerm.send(JSON.stringify({cols:t.cols, rows:t.rows}));
    });
    window.addEventListener('resize', ajustarTerm);
  }
  function ajustarTerm(){ if (fit) fit.fit(); }
  function cerrarTerminalUI(){
    document.getElementById('term-velo').classList.remove('abierto');
    window.removeEventListener('resize', ajustarTerm);
    if (wsTerm){ wsTerm.close(); wsTerm = null; }
    if (term){ term.dispose(); term = null; fit = null; }
    vaciar(document.getElementById('term'));
    servidorTerminal = null;
  }
  document.getElementById('term-cerrar').onclick = cerrarTerminalUI;
  document.getElementById('term').addEventListener('mousedown', function(){
    setTimeout(function(){ if (term) term.focus(); }, 0);
  });

  function pintarHistorialTerminal(lista){
    var cont = document.getElementById('term-hist-lista');
    if (!lista || !lista.length){
      mensajeEn(cont, 'vacio-hist', 'Sin comandos todavía.'); return;
    }
    vaciar(cont);
    lista.slice().reverse().forEach(function(cmd){
      var d = document.createElement('div');
      d.className = 'cmd'; d.textContent = cmd;
      d.title = 'Click para reenviar';
      d.onclick = function(){
        if (wsTerm && wsTerm.readyState === 1 && term){
          var enc = new TextEncoder();
          wsTerm.send(enc.encode(cmd + '\\n'));
          term.focus();
        }
      };
      cont.appendChild(d);
    });
  }
  function cargarHistorialTerminal(nombre){
    api('/api/historial?nombre=' + encodeURIComponent(nombre)).then(pintarHistorialTerminal).catch(function(){});
  }
  function guardarComandoHistorial(nombre, comando){
    api('/api/historial', {method:'POST', body: JSON.stringify({nombre: nombre, comando: comando})})
      .then(function(){ if (servidorTerminal === nombre) cargarHistorialTerminal(nombre); });
  }

  // ── Copia de seguridad ────────────────────────────────────────
  document.getElementById('copia-cabecera').onclick = function(){
    this.classList.toggle('abierta');
    document.getElementById('copia-caja').classList.toggle('abierto');
  };
  document.getElementById('btn-exportar').onclick = function(){
    var pass = document.getElementById('exp-pass').value;
    if (pass.length < 8){ aviso('La contraseña debe tener al menos 8 caracteres.', false); return; }
    var b = this; b.disabled = true; b.textContent = 'Exportando…';
    api('/api/exportar', {method:'POST', body: JSON.stringify({
      password: pass,
      incluirClaves: document.getElementById('exp-claves').checked,
      incluirKeys: document.getElementById('exp-keys').checked,
      incluirMonitoreo: document.getElementById('exp-monitoring').checked,
      incluirWireGuard: document.getElementById('exp-wireguard').checked
    })}).then(function(r){
      var res = document.getElementById('exp-res');
      if (r.error){ res.textContent = r.error; aviso(r.error, false); return; }
      if (r.cancelado){ res.textContent = 'Exportación cancelada.'; return; }
      res.textContent = 'Copia creada. ' + r.servidores + ' servidor(es), ' +
        r.tuneles + ' túnel(es), ' + r.keys + ' clave(s) SSH' + (r.monitoring ? ', monitoreo incluido' : '') + (r.wireguard ? ', WireGuard incluido' : '') + '. Guardada en: ' + r.ruta +
        ((r.omitidas && r.omitidas.length) ? ' · No pude leer: ' + r.omitidas.join(', ') : '');
      document.getElementById('exp-pass').value = '';
      aviso('Copia exportada.', true);
    }).finally(function(){ b.disabled = false; b.textContent = 'Exportar…'; });
  };
  document.getElementById('btn-importar').onclick = function(){
    var archivo = document.getElementById('imp-archivo').files[0];
    var pass = document.getElementById('imp-pass').value;
    if (!archivo){ aviso('Elige el archivo .cgw a importar.', false); return; }
    if (!pass){ aviso('Escribe la contraseña de la copia.', false); return; }
    var b = this; b.disabled = true; b.textContent = 'Importando…';
    var lector = new FileReader();
    lector.onload = function(){
      api('/api/importar', {method:'POST', body: JSON.stringify({
        password: pass, contenido: lector.result,
        modo: document.getElementById('imp-reemplazar').checked ? 'reemplazar' : 'fusionar'
      })}).then(function(r){
        var res = document.getElementById('imp-res');
        if (r.error){ res.textContent = r.error; aviso(r.error, false); return; }
        res.textContent = 'Importado. ' + r.nuevos + ' nuevo(s), ' +
          r.actualizados + ' actualizado(s), ' + r.tuneles + ' túnel(es), ' +
          r.keys + ' clave(s)' + (r.monitoring ? ', monitoreo restaurado' : '') + (r.wireguard ? ', WireGuard restaurado' : '') + '. Copia del ' + (r.creado || '?');
        document.getElementById('imp-pass').value = '';
        document.getElementById('imp-archivo').value = '';
        refrescarLista();
        aviso('Configuración importada.', true);
      }).finally(function(){ b.disabled = false; b.textContent = 'Importar'; });
    };
    lector.onerror = function(){ aviso('No pude leer el archivo.', false); b.disabled = false; b.textContent = 'Importar'; };
    lector.readAsText(archivo);
  };


  // ── Monitoreo ────────────────────────────────────────────────
  var monCache=null, monDashboard='overview', monProgressTimer=null, monPeerTimer=null, monSummaryTimer=null;
  function monNota(txt,tipo){ var e=$('mon-note'); if(!e)return; e.textContent=txt||''; e.className='monitor-note'+(tipo?' '+tipo:''); }
  function renderMonitoring(data){
    monCache=data; var cfg=data.config||{}; var servers=data.servidores||[];
    var sel=$('mon-server'); var previo=sel.value; vaciar(sel); var vac=nodo('option','','Selecciona servidor…');vac.value='';sel.appendChild(vac);
    servers.forEach(function(s){var o=nodo('option','',s.nombre+' · '+s.host);o.value=s.nombre;sel.appendChild(o);});
    sel.value=cfg.monitorServer||previo||''; $('mon-port-start').value=cfg.portStart||19100; $('mon-port-end').value=cfg.portEnd||19999;
    var list=$('mon-server-list');vaciar(list); var targets=cfg.targets||[]; var targetNames={};targets.forEach(function(t){targetNames[t.servidor]=t;});
    servers.forEach(function(s){
      var row=nodo('label','mon-server-row'); var cb=document.createElement('input');cb.type='checkbox';cb.dataset.server=s.nombre;cb.checked=!!targetNames[s.nombre];row.appendChild(cb);
      var main=nodo('span','mon-server-main');main.appendChild(nodo('b','',s.nombre));main.appendChild(nodo('small','',s.host+':'+s.puerto+' · '+s.usuario));row.appendChild(main);
      var state=nodo('span','mon-server-state'+(s.monitorizado?' on':''),s.monitorizado?('● '+(targetNames[s.nombre].localPort||9100)):(s.conectado?'Conectado':'Conectar primero'));row.appendChild(state);if(s.monitorizado){var d=nodo('button','mon-diag-btn','Diagnosticar');d.type='button';d.dataset.server=s.nombre;d.onclick=function(ev){ev.preventDefault();ev.stopPropagation();var btn=this;btn.disabled=true;monNota('Diagnosticando '+btn.dataset.server+'…','');api('/api/monitoring/diagnostico',{method:'POST',body:JSON.stringify({servidor:btn.dataset.server})}).then(function(r){if(r.error){monNota(r.error,'err');return;}var txt=(r.pasos||[]).map(function(x){return (x.ok?'✓ ':'✗ ')+x.nombre;}).join(' · ');monNota(btn.dataset.server+': '+txt,r.saludable?'ok':'err');}).finally(function(){btn.disabled=false;});};row.appendChild(d);}list.appendChild(row);
    });
    $('mon-target-count').textContent=targets.length+' target'+(targets.length===1?'':'s');
    $('mon-prom-dot').classList.toggle('ok',!!data.prometheusOnline);
    var map=$('mon-port-map');vaciar(map); if(!targets.length)map.appendChild(nodo('div','','Sin túneles de monitoreo todavía.'));targets.forEach(function(t){map.appendChild(nodo('div','',t.servidor+' · 127.0.0.1:'+t.localPort+' → SSH → :'+t.remotePort));});
    if(monDashboard==='overview') cargarResumen(); else if(monDashboard==='wg') cargarPeers();
  }
  function cargarMonitoring(){ return api('/api/monitoring/estado').then(function(r){if(r.error){monNota(r.error,'err');return;}renderMonitoring(r);}).catch(function(){monNota('No pude cargar la configuración de monitoreo.','err');}); }
  function monRenderProgress(p){
    var box=$('mon-progress'); if(!box)return;
    if(!p || (!p.activo && !p.mostrar)){ box.hidden=true; return; }
    box.hidden=false; $('mon-progress-title').textContent=p.operacion||'Monitoreo'; $('mon-progress-pct').textContent=(p.porcentaje||0)+'%'; $('mon-progress-bar').style.width=(p.porcentaje||0)+'%'; $('mon-progress-stage').textContent=p.etapa||'';
    var log=$('mon-progress-log'); log.textContent=(p.log||[]).join('\n'); log.scrollTop=log.scrollHeight;
  }
  function monPollProgress(){
    if(monProgressTimer) clearInterval(monProgressTimer);
    var tick=function(){api('/api/monitoring/progreso').then(function(r){if(!r.error)monRenderProgress(r);});}; tick(); monProgressTimer=setInterval(tick,700);
  }
  function monStopProgress(){ if(monProgressTimer){clearInterval(monProgressTimer);monProgressTimer=null;} api('/api/monitoring/progreso').then(function(r){if(!r.error)monRenderProgress(r);}); }

  function fmtPct(v){v=Number(v)||0;return v.toFixed(v<10?1:0)+'%';}
  function fmtUptime(s){s=Number(s)||0;if(s<=0)return '—';var d=Math.floor(s/86400),h=Math.floor((s%86400)/3600);return d?d+'d '+h+'h':h+'h';}
  function renderResumen(r){
    var k=$('mon-kpis');vaciar(k);
    var cards=[['Servidores online',(r.online||0)+' / '+(r.total||0),'Targets respondiendo'],['CPU promedio',fmtPct(r.cpuPromedio),'Servidores activos'],['RAM promedio',fmtPct(r.ramPromedio),'Memoria utilizada'],['Tráfico total','↓ '+fmtPeerRate(r.rxMbit),'↑ '+fmtPeerRate(r.txMbit)]];
    cards.forEach(function(c){var d=nodo('div','mon-kpi');d.appendChild(nodo('span','',c[0]));d.appendChild(nodo('b','',c[1]));d.appendChild(nodo('small','',c[2]));k.appendChild(d);});
    var list=$('mon-health-list');vaciar(list);var arr=(r.servidores||[]);
    if(!arr.length){list.appendChild(nodo('div','mon-peer-empty','Selecciona servidores y aplica el monitoreo para ver métricas.'));return;}
    arr.forEach(function(x){var card=nodo('div','mon-health-card');var name=nodo('div','mon-health-name');var title=nodo('b','');var dot=nodo('i','mon-live-dot'+(x.online?' ok':''));title.appendChild(dot);title.appendChild(document.createTextNode(x.nombre||'Servidor'));name.appendChild(title);name.appendChild(nodo('small','',x.online?('Uptime '+fmtUptime(x.uptime)):'Sin métricas'));card.appendChild(name);
      [['CPU',x.cpu],['RAM',x.ram],['Disco',x.disco]].forEach(function(m){var d=nodo('div','mon-health-metric');d.appendChild(nodo('span','',m[0]));d.appendChild(nodo('b','',fmtPct(m[1])));var bar=nodo('div','mon-mini');var i=document.createElement('i');i.style.width=Math.max(0,Math.min(100,Number(m[1])||0))+'%';bar.appendChild(i);d.appendChild(bar);card.appendChild(d);});
      var net=nodo('div','mon-health-net');var rx=nodo('span','rx','↓ '+fmtPeerRate(x.rxMbit));var tx=nodo('span','tx','↑ '+fmtPeerRate(x.txMbit));net.appendChild(rx);net.appendChild(tx);card.appendChild(net);list.appendChild(card);});
  }
  function cargarResumen(){if(monDashboard!=='overview')return;api('/api/monitoring/resumen').then(function(r){if(r.error){var l=$('mon-health-list');vaciar(l);l.appendChild(nodo('div','mon-peer-empty',r.error));return;}renderResumen(r);});}
  function fmtPeerRate(v){v=Number(v)||0;return (v<10?v.toFixed(2):v.toFixed(1))+' Mbit/s';}
  function fmtHandshake(age){age=Number(age);if(!isFinite(age)||age<0)return '—';if(age<60)return Math.round(age)+'s';if(age<3600)return Math.floor(age/60)+'m';if(age<86400)return Math.floor(age/3600)+'h';return Math.floor(age/86400)+'d';}
  function renderPeers(data){
    var list=$('mon-peer-list');vaciar(list);var peers=((data&&data.peers)||[]).slice();var q=(($('mon-peer-search')&&$('mon-peer-search').value)||'').trim().toLowerCase();if(q)peers=peers.filter(function(p){return ((p.nombre||'')+' '+(p.servidor||'')).toLowerCase().indexOf(q)>=0;});var ord=($('mon-peer-sort')&&$('mon-peer-sort').value)||'name';peers.sort(function(a,b){if(ord==='rx')return (Number(b.rxMbit)||0)-(Number(a.rxMbit)||0);if(ord==='tx')return (Number(b.txMbit)||0)-(Number(a.txMbit)||0);if(ord==='active')return (Number(a.handshakeAge)||1e15)-(Number(b.handshakeAge)||1e15);return (a.nombre||'').localeCompare(b.nombre||'');});
    if(!peers.length){list.appendChild(nodo('div','mon-peer-empty','No hay peers WireGuard con métricas todavía.'));return;}
    peers.forEach(function(p){var row=nodo('div','mon-peer-row');var name=nodo('span','mon-peer-name');name.appendChild(nodo('b','',p.nombre||'Peer WireGuard'));name.appendChild(nodo('small','',(p.interfaz||'wg')+(p.allowedIps?' · '+p.allowedIps:'')));row.appendChild(name);row.appendChild(nodo('span','mon-peer-server',p.servidor||''));row.appendChild(nodo('span','mon-peer-rx','↓ '+fmtPeerRate(p.rxMbit)));row.appendChild(nodo('span','mon-peer-tx','↑ '+fmtPeerRate(p.txMbit)));row.appendChild(nodo('span','mon-peer-handshake',fmtHandshake(p.handshakeAge)));list.appendChild(row);});
  }
  function cargarPeers(){if(monDashboard!=='wg')return;api('/api/monitoring/peers').then(function(r){if(r.error){var l=$('mon-peer-list');vaciar(l);l.appendChild(nodo('div','mon-peer-empty',r.error));return;}renderPeers(r);});}
  function monSetTab(tab){
    monDashboard=tab;var wg=tab==='wg', summary=tab==='overview';
    $('mon-tab-wg').classList.toggle('activo',wg);$('mon-tab-overview').classList.toggle('activo',summary);
    $('mon-peer-view').hidden=!wg;$('mon-summary-view').hidden=!summary;$('mon-wg-legend').hidden=!wg;
    $('mon-view-label').textContent=wg?'Peers en tiempo real':'Vista rápida nativa';
    if(monPeerTimer){clearInterval(monPeerTimer);monPeerTimer=null;} if(monSummaryTimer){clearInterval(monSummaryTimer);monSummaryTimer=null;}
    if(wg){cargarPeers();monPeerTimer=setInterval(cargarPeers,3000);}else{cargarResumen();monSummaryTimer=setInterval(cargarResumen,5000);}
  }
  $('mon-refresh').onclick=cargarMonitoring;
  $('mon-save').onclick=function(){var b=this;b.disabled=true;monNota('Guardando configuración…','');api('/api/monitoring/config',{method:'POST',body:JSON.stringify({monitorServer:$('mon-server').value,portStart:Number($('mon-port-start').value),portEnd:Number($('mon-port-end').value)})}).then(function(r){if(r.error){monNota(r.error,'err');return;}monNota('Configuración cifrada y guardada.','ok');return cargarMonitoring();}).finally(function(){b.disabled=false;});};
  $('mon-prepare').onclick=function(){var b=this;b.disabled=true;monNota('Preparando servidor de monitoreo…','');monPollProgress();api('/api/monitoring/preparar',{method:'POST',body:'{}'}).then(function(r){if(r.error){monNota(r.error,'err');return;}monNota(r.mensaje||'Servidor monitor preparado.','ok');return cargarMonitoring();}).finally(function(){b.disabled=false;monStopProgress();});};
  $('mon-apply').onclick=function(){var elegidos=[];document.querySelectorAll('#mon-server-list input[type=checkbox]:checked').forEach(function(c){elegidos.push(c.dataset.server);});var b=this;b.disabled=true;monNota('Aplicando selección…','');monPollProgress();api('/api/monitoring/targets',{method:'POST',body:JSON.stringify({servidores:elegidos})}).then(function(r){if(r.error){monNota(r.error,'err');return;}monNota('Monitoreo aplicado. Prometheus ya tiene '+(r.targets||[]).length+' target(s).','ok');return cargarMonitoring();}).finally(function(){b.disabled=false;monStopProgress();});};
  $('mon-peer-search').oninput=cargarPeers;$('mon-peer-sort').onchange=cargarPeers;
  $('mon-tab-overview').onclick=function(){monSetTab('overview');}; $('mon-tab-wg').onclick=function(){monSetTab('wg');}; $('mon-reload').onclick=function(){if(monDashboard==='wg')cargarPeers();else cargarResumen();}; $('mon-peer-refresh').onclick=cargarPeers;

  // ── WireGuard local ───────────────────────────────────
  var wgcProfiles:any[]=[], wgcSelected:string|null=null, wgcStatus:any={}, wgcPrev:any={}, wgcTimer:any=null, wgcSecretsVisible=false;
  function wgcNote(texto:any,tipo?:any){var e=$('wgc-note');if(!e)return;e.textContent=texto||'';e.className='wgclient-note'+(tipo?' '+tipo:'');}
  function wgcSplit(v:any){return String(v||'').split(/[,\n]/).map(function(x){return x.trim();}).filter(Boolean);}
  function wgcLines(v:any){return String(v||'').split(/\r?\n/).map(function(x){return x.trim();}).filter(Boolean);}
  function wgcBytes(v:any){v=Math.max(0,Number(v)||0);var u=['B','KB','MB','GB','TB'],i=0;while(v>=1024&&i<u.length-1){v/=1024;i++;}return (v>=100?Math.round(v):v.toFixed(1))+' '+u[i];}
  function wgcHandshake(ts:any){var n=Number(ts)||0;if(!n)return '—';var d=Math.max(0,Math.floor(Date.now()/1000-n));if(d<60)return d+' s';if(d<3600)return Math.floor(d/60)+' min';if(d<86400)return Math.floor(d/3600)+' h';return Math.floor(d/86400)+' d';}
  function wgcMbit(bytesPerSec:any){var x=Math.max(0,Number(bytesPerSec)||0)*8/1000000;return (x<10?x.toFixed(2):x.toFixed(1))+' Mbit/s';}
  function wgcProfileById(id:any){return wgcProfiles.find(function(p){return p.id===id;})||null;}
  function wgcEndpoint(p:any){var peers=(p&&p.peers)||[];for(var i=0;i<peers.length;i++){if(peers[i].endpoint)return peers[i].endpoint;}return 'sin endpoint';}

  function wgcPeerRow(peer?:any,index?:any){
    peer=peer||{}; var row=nodo('div','wgclient-peer'); row.dataset.index=String(index||0);
    var head=nodo('div','wgclient-peer-head'); head.appendChild(nodo('b','',peer.name||('Peer '+((index||0)+1)))); var tools=nodo('div','wgclient-peer-head-tools');var live=nodo('small','wgclient-peer-live','Sin telemetría');live.dataset.role='live';tools.appendChild(live);var rm=nodo('button','wgclient-peer-remove','×');rm.type='button';rm.title='Quitar peer';rm.onclick=function(){row.remove();wgcRenumberPeers();};tools.appendChild(rm);head.appendChild(tools);row.appendChild(head);
    var grid=nodo('div','wgclient-peer-grid');
    function field(label:any,id:any,val:any,ph:any,span?:any,type?:any){var d=nodo('div',span?'span2':'');var l=nodo('label','',label);d.appendChild(l);var inp=document.createElement('input');inp.type=type||'text';inp.dataset.field=id;inp.value=val||'';if(ph)inp.placeholder=ph;d.appendChild(inp);grid.appendChild(d);return inp;}
    var name=field('Nombre amigable','name',peer.name||'','Casa / Oficina / Gateway');name.oninput=function(){head.querySelector('b').textContent=name.value||('Peer '+(Number(row.dataset.index)+1));};
    field('Endpoint','endpoint',peer.endpoint||'','vpn.example.com:51820');
    field('PublicKey','publicKey',peer.publicKey||'','clave pública del servidor',true);
    var pskWrap=nodo('div','span2');pskWrap.appendChild(nodo('label','','PresharedKey (opcional)'));var pskRow=nodo('div','wgclient-copy-row');var psk=document.createElement('input');psk.type='password';psk.dataset.field='presharedKey';psk.placeholder=peer.hasPresharedKey?'Guardada cifrada · vacío = conservar':'opcional';psk.autocomplete='off';pskRow.appendChild(psk);var genPSK=nodo('button','','Generar PSK');genPSK.type='button';genPSK.onclick=function(){genPSK.disabled=true;api('/api/wireguard/generar-psk',{method:'POST',body:'{}'}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}psk.value=r.presharedKey||'';psk.type='text';wgcNote('PresharedKey generada localmente. Guarda el perfil para cifrarla.','warn');}).finally(function(){genPSK.disabled=false;});};pskRow.appendChild(genPSK);pskWrap.appendChild(pskRow);grid.appendChild(pskWrap);
    field('AllowedIPs','allowedIPs',(peer.allowedIPs||[]).join(', '),'0.0.0.0/0, ::/0',true);
    field('PersistentKeepalive','persistentKeepalive',peer.persistentKeepalive||'','25',false,'number');
    row.appendChild(grid); return row;
  }
  function wgcRenumberPeers(){document.querySelectorAll('#wgc-peers .wgclient-peer').forEach(function(row,i){row.dataset.index=String(i);var b=row.querySelector('.wgclient-peer-head b');var n=row.querySelector('[data-field=name]');if(b&&!n.value)b.textContent='Peer '+(i+1);});}
  function wgcRenderPeers(peers:any[]){var box=$('wgc-peers');vaciar(box);(peers||[]).forEach(function(p,i){box.appendChild(wgcPeerRow(p,i));});if(!box.children.length)box.appendChild(wgcPeerRow({},0));}
  function wgcCollectPeers(){var out:any[]=[];document.querySelectorAll('#wgc-peers .wgclient-peer').forEach(function(row){function v(n){var e=row.querySelector('[data-field='+n+']');return e?e.value.trim():'';}out.push({name:v('name'),endpoint:v('endpoint'),publicKey:v('publicKey'),presharedKey:v('presharedKey'),allowedIPs:wgcSplit(v('allowedIPs')),persistentKeepalive:Number(v('persistentKeepalive'))||0});});return out;}

  function wgcClear(){
    wgcSelected=null;wgcSecretsVisible=false;$('wgc-title').textContent='Nuevo perfil';$('wgc-subtitle').textContent='Configura un túnel o importa un archivo .conf.';
    ['wgc-name','wgc-address','wgc-private','wgc-public','wgc-dns','wgc-mtu','wgc-listen','wgc-table','wgc-notes','wgc-preup','wgc-postup','wgc-predown','wgc-postdown'].forEach(function(id){$(id).value='';});
    $('wgc-private').type='password';$('wgc-auto').checked=false;$('wgc-hooks-allow').checked=false;wgcRenderPeers([]);$('wgc-export').hidden=true;$('wgc-delete').hidden=true;wgcSetSnapshot({connected:false,interface:'—',rxBytes:0,txBytes:0});wgcNote('Las claves privadas y PresharedKey se guardan cifradas. El archivo .conf exportado sí contiene secretos.','');wgcRenderList();
  }
  function wgcLoadProfile(id:any){var p=wgcProfileById(id);if(!p)return;wgcSelected=id;wgcSecretsVisible=false;$('wgc-title').textContent=p.name;$('wgc-subtitle').textContent=(p.addresses||[]).join(', ')+' · '+wgcEndpoint(p);$('wgc-name').value=p.name||'';$('wgc-address').value=(p.addresses||[]).join(', ');$('wgc-private').value='';$('wgc-private').type='password';$('wgc-public').value=p.publicKey||'';$('wgc-dns').value=(p.dns||[]).join(', ');$('wgc-mtu').value=p.mtu||'';$('wgc-listen').value=p.listenPort||'';$('wgc-table').value=p.table||'';$('wgc-notes').value=p.notes||'';$('wgc-preup').value=(p.preUp||[]).join('\n');$('wgc-postup').value=(p.postUp||[]).join('\n');$('wgc-predown').value=(p.preDown||[]).join('\n');$('wgc-postdown').value=(p.postDown||[]).join('\n');$('wgc-auto').checked=!!p.autoConnect;$('wgc-hooks-allow').checked=!!p.allowHooks;wgcRenderPeers(p.peers||[]);$('wgc-export').hidden=false;$('wgc-delete').hidden=false;wgcRenderList();var st=wgcStatus[id]&&wgcStatus[id].snapshot;wgcSetSnapshot(st||{connected:false,interface:p.interface});}

  function wgcRenderList(){var box=$('wgc-profile-list');vaciar(box);var q=String($('wgc-search').value||'').toLowerCase();var arr=wgcProfiles.filter(function(p){return !q||String(p.name).toLowerCase().includes(q)||wgcEndpoint(p).toLowerCase().includes(q);});if(!arr.length){box.appendChild(nodo('div','wgclient-empty',wgcProfiles.length?'No coincide ningún perfil.':'No hay perfiles WireGuard.'));return;}arr.forEach(function(p){var st=wgcStatus[p.id]&&wgcStatus[p.id].snapshot||{};var row=nodo('div','wgclient-profile'+(p.id===wgcSelected?' active':''));row.onclick=function(){wgcLoadProfile(p.id);};var dot=nodo('span','wgclient-profile-dot'+(st.connected?' up':''));row.appendChild(dot);var m=nodo('div','wgclient-profile-main');m.appendChild(nodo('b','',p.name));m.appendChild(nodo('small','',wgcEndpoint(p)+(p.autoConnect?' · auto':'')));row.appendChild(m);var rate=wgcStatus[p.id]&&wgcStatus[p.id]._rate||{};row.appendChild(nodo('div','wgclient-profile-rate',st.connected?('↓ '+wgcMbit(rate.rx||0)+'\n↑ '+wgcMbit(rate.tx||0)):'OFF'));box.appendChild(row);});}

  function wgcUpdatePeerLive(s:any){var rates=wgcSelected&&wgcStatus[wgcSelected]&&wgcStatus[wgcSelected]._peerRates||{};var peers=(s&&s.peers)||[];var byKey:any={};peers.forEach(function(p){byKey[p.publicKey]=p;});document.querySelectorAll('#wgc-peers .wgclient-peer').forEach(function(row){var pk=row.querySelector('[data-field=publicKey]');var live=row.querySelector('[data-role=live]');if(!live||!pk)return;var info=byKey[pk.value.trim()];if(!info){live.textContent=s&&s.connected?'Sin datos del peer':'Sin telemetría';live.className='wgclient-peer-live';return;}var rate=rates[info.publicKey]||{};live.textContent='↓ '+wgcMbit(rate.rx||0)+' · ↑ '+wgcMbit(rate.tx||0)+' · '+wgcHandshake(info.latestHandshake);live.className='wgclient-peer-live'+(info.latestHandshake?' up':'');});}
  function wgcSetSnapshot(s:any){s=s||{};var connected=!!s.connected;$('wgc-state').textContent=connected?'Conectado':'Desconectado';$('wgc-state').className='wgclient-state'+(connected?' up':'');$('wgc-connect').hidden=connected;$('wgc-disconnect').hidden=!connected;$('wgc-connect').disabled=!wgcSelected;$('wgc-interface').textContent=s.interface||'—';$('wgc-rx-total').textContent=wgcBytes(s.rxBytes||0)+' total';$('wgc-tx-total').textContent=wgcBytes(s.txBytes||0)+' total';$('wgc-handshake').textContent=wgcHandshake(s.latestHandshake);var p=wgcSelected?wgcProfileById(wgcSelected):null;$('wgc-endpoint-summary').textContent=wgcEndpoint(p);var rate=wgcSelected&&wgcStatus[wgcSelected]&&wgcStatus[wgcSelected]._rate||{};$('wgc-rx').textContent=wgcMbit(rate.rx||0);$('wgc-tx').textContent=wgcMbit(rate.tx||0);wgcUpdatePeerLive(s);}

  function wgcApplyStatus(data:any){if(!data)return;var eng=data.engine||{};$('wgc-engine-name').textContent=eng.name||'WireGuard';$('wgc-engine-msg').textContent=eng.installed?((eng.version||'Motor oficial detectado')+(eng.path?' · '+eng.path:'')):(eng.message||'Motor no instalado');$('wgc-engine-dot').className='wgclient-engine-dot'+(eng.installed?' ok':'');$('wgc-engine-install').hidden=!!eng.installed||!eng.canInstall;var now=Date.now();(data.profiles||[]).forEach(function(x){var snap=x.snapshot||{},prev=wgcPrev[x.id],rx=0,tx=0,peerRates:any={};if(prev&&snap.connected){var dt=(now-prev.t)/1000;if(dt>.3){rx=Math.max(0,(Number(snap.rxBytes||0)-prev.rx)/dt);tx=Math.max(0,(Number(snap.txBytes||0)-prev.tx)/dt);(snap.peers||[]).forEach(function(pp){var old=prev.peers&&prev.peers[pp.publicKey];if(old){peerRates[pp.publicKey]={rx:Math.max(0,(Number(pp.rxBytes||0)-old.rx)/dt),tx:Math.max(0,(Number(pp.txBytes||0)-old.tx)/dt)};}});}}var peerPrev:any={};(snap.peers||[]).forEach(function(pp){peerPrev[pp.publicKey]={rx:Number(pp.rxBytes||0),tx:Number(pp.txBytes||0)};});wgcPrev[x.id]={t:now,rx:Number(snap.rxBytes||0),tx:Number(snap.txBytes||0),peers:peerPrev};x._rate={rx:rx,tx:tx};x._peerRates=peerRates;wgcStatus[x.id]=x;});wgcRenderList();if(wgcSelected){var st=wgcStatus[wgcSelected];wgcSetSnapshot(st?st.snapshot:{connected:false,interface:(wgcProfileById(wgcSelected)||{}).interface});}}
  function wgcPoll(){api('/api/wireguard/estado').then(wgcApplyStatus).catch(function(){});}
  function cargarWireGuard(){api('/api/wireguard/perfiles').then(function(p){wgcProfiles=p||[];if(wgcSelected&&!wgcProfileById(wgcSelected))wgcSelected=null;if(!wgcSelected&&wgcProfiles.length)wgcSelected=wgcProfiles[0].id;if(wgcSelected)wgcLoadProfile(wgcSelected);else wgcClear();wgcPoll();if(wgcTimer)clearInterval(wgcTimer);wgcTimer=setInterval(function(){if(vistaActual==='wireguard')wgcPoll();},2000);}).catch(function(){wgcNote('No pude cargar los perfiles WireGuard.','err');});}

  function wgcSave(connectAfter?:any){var req:any={id:wgcSelected||'',name:$('wgc-name').value.trim(),privateKey:$('wgc-private').value.trim(),addresses:wgcSplit($('wgc-address').value),dns:wgcSplit($('wgc-dns').value),mtu:Number($('wgc-mtu').value)||0,listenPort:Number($('wgc-listen').value)||0,table:$('wgc-table').value.trim(),notes:$('wgc-notes').value,autoConnect:!!$('wgc-auto').checked,allowHooks:!!$('wgc-hooks-allow').checked,preUp:wgcLines($('wgc-preup').value),postUp:wgcLines($('wgc-postup').value),preDown:wgcLines($('wgc-predown').value),postDown:wgcLines($('wgc-postdown').value),peers:wgcCollectPeers()};var b=$('wgc-save');b.disabled=true;wgcNote('Guardando perfil cifrado…','');return api('/api/wireguard/perfiles',{method:'POST',body:JSON.stringify(req)}).then(function(r){if(r.error){wgcNote(r.error,'err');throw new Error(r.error);}wgcSelected=r.profile.id;$('wgc-private').value='';wgcNote('Perfil guardado. PrivateKey y PresharedKey quedaron cifradas.','ok');return api('/api/wireguard/perfiles');}).then(function(list){wgcProfiles=list||[];wgcLoadProfile(wgcSelected);if(connectAfter)return wgcConnectNow();return;}).finally(function(){b.disabled=false;});}
  function wgcConnectNow(){if(!wgcSelected)return Promise.resolve();var b=$('wgc-connect');b.disabled=true;b.textContent='Conectando…';wgcNote('Activando túnel con el motor oficial WireGuard…','');return api('/api/wireguard/conectar',{method:'POST',body:JSON.stringify({id:wgcSelected})}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}wgcNote('Túnel conectado.','ok');wgcPoll();}).finally(function(){b.disabled=false;b.textContent='Conectar';});}

  $('wgc-new').onclick=function(){wgcClear();$('wgc-name').focus();};$('wgc-search').oninput=wgcRenderList;$('wgc-add-peer').onclick=function(){var box=$('wgc-peers');box.appendChild(wgcPeerRow({},box.children.length));};
  $('wgc-generate').onclick=function(){api('/api/wireguard/generar-key',{method:'POST',body:'{}'}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}$('wgc-private').value=r.privateKey;$('wgc-private').type='text';$('wgc-public').value=r.publicKey;wgcSecretsVisible=true;wgcNote('Nuevo par de keys generado localmente. Guarda el perfil para cifrar la privada.','warn');});};
  $('wgc-reveal').onclick=function(){if(!wgcSelected){$('wgc-private').type=$('wgc-private').type==='password'?'text':'password';return;}if(wgcSecretsVisible){wgcSecretsVisible=false;$('wgc-private').type='password';$('wgc-private').value='';document.querySelectorAll('#wgc-peers [data-field=presharedKey]').forEach(function(x){x.type='password';x.value='';});this.textContent='Mostrar secretos';return;}if(!confirm('La clave privada se mostrará en pantalla. ¿Continuar?'))return;api('/api/wireguard/revelar',{method:'POST',body:JSON.stringify({id:wgcSelected})}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}wgcSecretsVisible=true;$('wgc-private').type='text';$('wgc-private').value=r.privateKey||'';document.querySelectorAll('#wgc-peers [data-field=presharedKey]').forEach(function(x,i){x.type='text';x.value=(r.presharedKeys||[])[i]||'';});$('wgc-reveal').textContent='Ocultar secretos';});};
  $('wgc-copy-public').onclick=function(){var v=$('wgc-public').value;if(!v)return;if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(v);wgcNote('Clave pública copiada.','ok');}else{var e=$('wgc-public');e.select();document.execCommand('copy');wgcNote('Clave pública copiada.','ok');}};
  $('wgc-save').onclick=function(){wgcSave(false).catch(function(){});};$('wgc-connect').onclick=function(){if(!wgcSelected){wgcSave(true).catch(function(){});}else wgcConnectNow();};$('wgc-disconnect').onclick=function(){if(!wgcSelected)return;var b=this;b.disabled=true;b.textContent='Desconectando…';api('/api/wireguard/desconectar',{method:'POST',body:JSON.stringify({id:wgcSelected})}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}wgcNote('Túnel desconectado.','ok');wgcPoll();}).finally(function(){b.disabled=false;b.textContent='Desconectar';});};
  $('wgc-full-tunnel').onclick=function(){var rows=document.querySelectorAll('#wgc-peers .wgclient-peer');if(!rows.length){$('wgc-add-peer').click();rows=document.querySelectorAll('#wgc-peers .wgclient-peer');}var ip=rows[0].querySelector('[data-field=allowedIPs]');ip.value='0.0.0.0/0, ::/0';wgcNote('El primer peer quedó como túnel completo IPv4 + IPv6.','warn');};
  $('wgc-import').onclick=function(){$('wgc-import-file').click();};$('wgc-import-file').onchange=function(){var f=this.files&&this.files[0];if(!f)return;var rd=new FileReader();rd.onload=function(){var nm=f.name.replace(/\.conf$/i,'');api('/api/wireguard/importar',{method:'POST',body:JSON.stringify({name:nm,content:String(rd.result||'')})}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}wgcSelected=r.profile.id;var warns=r.warnings||[];wgcNote('Perfil importado'+(warns.length?' · '+warns.join(' · '):'.'),'warn');cargarWireGuard();});};rd.readAsText(f);this.value='';};
  $('wgc-export').onclick=function(){if(!wgcSelected)return;if(!confirm('El archivo .conf exportado contiene la PrivateKey en texto legible. ¿Exportar?'))return;api('/api/wireguard/exportar',{method:'POST',body:JSON.stringify({id:wgcSelected})}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}if(r.cancelado){wgcNote('Exportación cancelada.','');return;}wgcNote('Perfil exportado en '+r.path,'ok');});};
  $('wgc-delete').onclick=function(){if(!wgcSelected)return;var p=wgcProfileById(wgcSelected);if(!confirm('¿Eliminar el perfil WireGuard "'+(p?p.name:'')+'"?'))return;api('/api/wireguard/eliminar',{method:'POST',body:JSON.stringify({id:wgcSelected})}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}wgcSelected=null;cargarWireGuard();wgcNote('Perfil eliminado.','ok');});};
  $('wgc-engine-install').onclick=function(){var b=this;b.disabled=true;b.textContent='Preparando…';api('/api/wireguard/motor/instalar',{method:'POST',body:'{}'}).then(function(r){if(r.error){wgcNote(r.error,'err');return;}wgcNote(r.message||'Motor preparado. Vuelve a comprobar después de instalar.','warn');setTimeout(wgcPoll,1500);}).finally(function(){b.disabled=false;b.textContent='Instalar motor oficial';});};

  // ── Actualizaciones privadas y firmadas ───────────────────────
  var updUltima = null;
  function updSemaforo(estado, resumen){
    var p=$('upd-punto');
    p.className='upd-punto '+estado;
    $('upd-resumen').textContent=resumen;
    p.title=resumen;
    var p2=$('upd-punto-dash'); if (p2){ p2.className='upd-punto '+estado; p2.title=resumen; }
    var s2=$('upd-dash-status'); if (s2) s2.textContent = resumen || 'sin comprobar';
    var is=$('info-update-status'); if(is) is.textContent = resumen || 'Actualizaciones firmadas';
    var next=$('dash-next-check'); if(next){ next.textContent = estado==='rojo' ? 'Hay una nueva versión disponible.' : (estado==='verde' ? 'Tu instalación está verificada y al día.' : 'Pendiente de comprobar o falta token.'); }
  }
  function updEstado(texto, tipo){
    var e=$('upd-estado'); e.textContent=texto; e.className='estado'+(tipo?' '+tipo:'');
  }
  function updBuscar(silencioso){
    if(!silencioso) updEstado('Buscando la última Release privada…',''); updSemaforo('amarillo','comprobando…');
    return api('/api/actualizaciones',{method:'POST',body:JSON.stringify({accion:'buscar'})}).then(function(r){
      if(r.error){ if(!silencioso) updEstado(r.error,'err'); updSemaforo('amarillo','no se pudo comprobar'); return; }
      updUltima=r;
      $('upd-instalar').style.display=r.disponible?'inline-block':'none';
      $('upd-notas').textContent=r.notas||''; $('upd-notas').style.display=r.notas?'block':'none';
      if(r.disponible){ updEstado('Nueva versión v'+r.nueva+' disponible. Firma verificada.','err'); updSemaforo('rojo','v'+r.nueva+' disponible'); }
      else { updEstado('Estás al día: v'+r.actual+'. Firma de la Release verificada.','ok'); updSemaforo('verde','estás al día'); }
    }).catch(function(){ if(!silencioso) updEstado('No pude consultar GitHub.','err'); updSemaforo('amarillo','sin comprobar'); });
  }
  api('/api/version').then(function(v){
    $('app-ver').textContent='v'+v.version;
    var dv=$('dash-app-ver'); if (dv) dv.textContent='v'+v.version;
    var iv=$('info-version'); if(iv) iv.textContent='v'+v.version;
    $('btn-releases').onclick=function(){ abrirFuera(v.releasesURL); };
  }).catch(function(){});
  api('/api/actualizaciones').then(function(c){
    $('upd-inicio').checked=!!c.buscarAlInicio;
    updEstado(c.tokenConfigurado?'Token configurado de forma segura.':'Configura el token una sola vez para habilitar las actualizaciones privadas.',c.tokenConfigurado?'ok':'');
    updSemaforo('amarillo', c.tokenConfigurado?'pendiente de comprobar':'token no configurado');
    if(c.tokenConfigurado && c.buscarAlInicio) updBuscar(true);
  }).catch(function(){});
  $('upd-guardar').onclick=function(){
    var token=$('upd-token').value.trim(); if(!token){updEstado('Pega primero el token de GitHub.','err');return;}
    var b=this;b.disabled=true;updEstado('Guardando y comprobando acceso al repo privado…','');
    api('/api/actualizaciones',{method:'POST',body:JSON.stringify({accion:'guardar-token',token:token})}).then(function(r){
      $('upd-token').value=''; if(r.error){updEstado(r.error,'err');updSemaforo('amarillo','token sin verificar');return;} updEstado('Token guardado y acceso verificado.','ok'); updSemaforo('amarillo','pendiente de comprobar'); updBuscar(false);
    }).finally(function(){b.disabled=false;});
  };
  $('upd-token-web').onclick=function(){ abrirFuera('https://github.com/settings/personal-access-tokens/new'); };
  $('upd-borrar').onclick=function(){ api('/api/actualizaciones',{method:'POST',body:JSON.stringify({accion:'borrar-token'})}).then(function(r){ if(r.error){updEstado(r.error,'err');return;} $('upd-instalar').style.display='none';$('upd-notas').style.display='none';updEstado('Token borrado.','ok');updSemaforo('amarillo','token no configurado'); }); };
  $('upd-buscar').onclick=function(){updBuscar(false);};
  $('upd-inicio').onchange=function(){api('/api/actualizaciones',{method:'POST',body:JSON.stringify({accion:'preferencias',buscarAlInicio:this.checked})});};
  $('upd-instalar').onclick=function(){
    if(!updUltima||!updUltima.disponible)return;
    if(!window.confirm('Instalar Gateway WISP Access v'+updUltima.nueva+' ahora? La app se cerrará y volverá a abrir sola.'))return;
    var b=this;b.disabled=true;updEstado('Descargando, verificando firma y SHA-256…','');
    api('/api/actualizaciones',{method:'POST',body:JSON.stringify({accion:'instalar'})}).then(function(r){
      if(r.error){updEstado(r.error,'err');b.disabled=false;return;} updEstado('Actualización verificada. Reiniciando en v'+r.version+'…','ok');
    }).catch(function(){updEstado('La app se está reiniciando para completar la actualización…','ok');});
  };

  // ── Abrir enlaces en el navegador del sistema ─────────────────
  function abrirFuera(url){
    api('/api/abrir', {method:'POST', body: JSON.stringify({url: url})})
      .then(function(r){ if (r && r.error) window.open(url, '_blank'); })
      .catch(function(){ window.open(url, '_blank'); });
  }


  // En Wails los enlaces externos no deben navegar la WebView principal.
  // Se delegan al navegador del sistema mediante el backend ya protegido.
  document.addEventListener('click', function(e){
    var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (!a) return;
    var href = a.getAttribute('href') || '';
    if (!/^https?:\/\//i.test(href)) return;
    e.preventDefault();
    abrirFuera(href);
  });

  // ── Atajos de teclado ──────────────────────────────────────────
  document.addEventListener('keydown', function(e){
    if (e.key === 'Escape'){
      if (document.getElementById('gw-velo').classList.contains('abierto')){ cerrarGatewayWISP(); return; }
      if (document.getElementById('sshadmin-velo').classList.contains('abierto')){ cerrarSSHAdmin(); return; }
      if (document.getElementById('m-firewall').classList.contains('abierto')){ cerrarFirewall(); return; }
      if (document.getElementById('fx-velo').classList.contains('abierto')){ cerrarArchivos(); return; }
      if (document.getElementById('tools-velo').classList.contains('abierto')){ cerrarHerramientas(); return; }
      if (document.getElementById('term-velo').classList.contains('abierto')){ cerrarTerminalUI(); return; }
      if (document.getElementById('m-huella').classList.contains('abierto')){ document.getElementById('huella-no').click(); return; }
      if (document.getElementById('m-pass').classList.contains('abierto')){ document.getElementById('pass-no').click(); return; }
      if (document.getElementById('m-seguridad').classList.contains('abierto')){ document.getElementById('seg-no').click(); return; }
    }
    if (e.ctrlKey && e.key === 'Enter'){
      if (document.getElementById('m-pass').classList.contains('abierto')){ document.getElementById('pass-si').click(); return; }
      var activo = document.activeElement;
      if (activo && activo.closest && activo.closest('#form')){ guardarServidorDesdeForm(); }
    }
  });

  // ── Plegables de servidores y formulario ─────────────────────
  function plegar(cabId, cajaId){
    document.getElementById(cabId).onclick = function(){
      this.classList.toggle('abierta');
      document.getElementById(cajaId).classList.toggle('abierto');
    };
  }
  plegar('tun-cabecera-form','tun-caja-form');

  function abrirFormulario(){
    mostrarVista('profiles');
    document.getElementById('form-cabecera').classList.add('abierta');
    document.getElementById('form').classList.add('abierto');
  }

  function abrirPlegable(cabId, cajaId){
    var cab=document.getElementById(cabId), caja=document.getElementById(cajaId);
    if(cab) cab.classList.add('abierta');
    if(caja) caja.classList.add('abierto');
  }
  function irA(el){
    if(!el) return;
    el.scrollIntoView({behavior:'smooth',block:'start'});
  }
  var vistaActual='dashboard';
  var titulosVista={
    dashboard:['Dashboard','Servidores guardados y conexiones activas en una sola vista.'],
    profiles:['Perfil SSH','Agrega un servidor nuevo o edita un perfil existente.'],
    backup:['Copia de seguridad','Exporta o restaura servidores, túneles, contraseñas guardadas, claves SSH y monitoreo.'],
    monitoring:['Monitoreo','Prometheus, métricas nativas y peers WireGuard en tiempo real por túneles SSH persistentes.'],
    wireguard:['WireGuard','Perfiles VPN locales con el motor oficial de WireGuard para Windows y Linux.'],
    updates:['Actualizaciones','Comprueba e instala versiones firmadas desde el repositorio privado.'],
    info:['Gateway WISP Access','Información de seguridad, componentes y versión instalada.']
  };
  function mostrarVista(nombre){
    if(!titulosVista[nombre]) nombre='dashboard';
    vistaActual=nombre;
    document.querySelectorAll('.app-view').forEach(function(v){v.classList.toggle('activa',v.dataset.view===nombre);});
    document.querySelectorAll('.nav-item[data-nav]').forEach(function(a){a.classList.toggle('activo',a.dataset.nav===nombre);});
    $('view-title').textContent=titulosVista[nombre][0];
    $('view-subtitle').textContent=titulosVista[nombre][1];
    var cs=document.querySelector('.content-shell'); if(cs) cs.scrollTop=0;
    if(nombre==='profiles') abrirPlegable('form-cabecera','form');
    if(nombre==='backup') abrirPlegable('copia-cabecera','copia-caja');
    if(nombre==='updates') abrirPlegable('upd-cabecera','upd-caja');
    if(nombre==='monitoring') cargarMonitoring();
    if(nombre==='wireguard') cargarWireGuard();
    var df=$('dashboard-footer'); if(df) df.classList.toggle('hidden', nombre!=='dashboard');
  }
  document.querySelectorAll('.nav-item[data-nav]').forEach(function(a){
    a.addEventListener('click',function(ev){ev.preventDefault();mostrarVista(a.dataset.nav);});
  });


  // ── Herramientas por servidor ────────────────────────────────
  var toolsServidor = null;
  function abrirHerramientas(nombre){
    toolsServidor = nombre;
    $('tools-srv').textContent = nombre;
    $('tools-velo').classList.add('abierto');
  }
  function cerrarHerramientas(){ $('tools-velo').classList.remove('abierto'); }
  $('tools-cerrar').onclick = cerrarHerramientas;
  $('tool-script').onclick = function(){
    if (!toolsServidor){ aviso('No hay servidor seleccionado.',false); return; }
    selectorDestino = 'script';
    selectorScriptServidor = toolsServidor;
    cerrarHerramientas();
    abrirArchivos(toolsServidor);
    cargarLocal('');
    aviso('Elige el script en "Tu equipo" y pulsa Ejecutar.',true);
  };
  $('tool-speedtest').onclick = function(){
    if (!toolsServidor){ aviso('No hay servidor seleccionado.',false); return; }
    var srv = toolsServidor;
    var b = this;
    b.disabled = true; b.textContent = 'Preparando…';
    api('/api/herramientas/test-velocidad',{method:'POST',body:JSON.stringify({servidor:srv})}).then(function(r){
      if (r.error){ aviso(r.error,false); return; }
      cerrarHerramientas();
      aviso('Abriendo terminal para medir la conexión de '+srv+'…',true);
      abrirTerminal(srv,r.comando,!!r.silencioso);
    }).catch(function(){ aviso('No pude preparar el test de velocidad.',false); }).finally(function(){ b.disabled=false; b.textContent='Probar velocidad'; });
  };

  var firewallServidor = null;
  var firewallEditable = false;
  function pintarFirewall(f){
    if(!f) return;
    firewallEditable=!!f.editable;
    $('fw-backend').textContent=f.nombre||f.backend||'Firewall';
    $('fw-backend').className='fw-badge '+(f.backend&&f.backend!=='none'?'ok':'warn');
    $('fw-estado').textContent=f.estado||'—';
    $('fw-estado').className='fw-badge '+(f.estado==='activo'?'ok':'warn');
    $('fw-ssh').textContent='SSH '+(f.puertoSSH||22)+'/tcp protegido';
    $('fw-reglas').textContent=f.reglas||'Sin reglas para mostrar.';
    $('fw-nota').textContent=f.nota||'Gateway crea una copia del firewall antes de modificarlo.';
    $('fw-nota').className='fw-note';
    $('fw-abrir').disabled=!firewallEditable;
    $('fw-cerrar-puerto').disabled=!firewallEditable;
  }
  function cargarFirewall(){
    if(!firewallServidor) return;
    $('fw-reglas').textContent='Consultando firewall…';
    $('fw-abrir').disabled=true; $('fw-cerrar-puerto').disabled=true;
    api('/api/herramientas/firewall?servidor='+encodeURIComponent(firewallServidor)).then(function(r){
      if(r.error){ $('fw-reglas').textContent=r.error; $('fw-nota').textContent=r.error; $('fw-nota').className='fw-note err'; return; }
      pintarFirewall(r);
    }).catch(function(){ $('fw-reglas').textContent='No pude consultar el firewall.'; $('fw-nota').textContent='No pude consultar el firewall.'; $('fw-nota').className='fw-note err'; });
  }
  // ── Administración SSH (key + puerto seguro) ───────────────
  var sshAdminServidor=null, sshPortToken=null;
  function perfilCache(nombre){ return servidoresCache.find(function(x){ return x.nombre===nombre; }) || null; }
  function sshStatus(id,texto,tipo){ var e=$(id); e.textContent=texto; e.className='ssh-status'+(tipo?' '+tipo:''); }
  function sshPortLog(text: any, tipo?: any, reset?: any){var n=$('ssh-port-console');if(!n)return;if(reset)vaciar(n);var l=document.createElement('div');if(tipo)l.className=tipo;l.textContent=text;n.appendChild(l);n.scrollTop=n.scrollHeight;}
  function sshSteps(a,b,c){
    $('ssh-step-config').className='ssh-step'+(a?' '+a:'');
    $('ssh-step-test').className='ssh-step'+(b?' '+b:'');
    $('ssh-step-apply').className='ssh-step'+(c?' '+c:'');
  }
  function abrirSSHAdmin(nombre){
    sshAdminServidor=nombre; sshPortToken=null;
    var p=perfilCache(nombre)||{};
    $('sshadmin-srv').textContent=nombre;
    $('ssh-key-path').value=p.key||''; $('ssh-key-pass').value=''; $('ssh-key-recordar').checked=false;
    $('ssh-port-actual').textContent=p.puerto||22;
    $('ssh-port-nuevo').value=(p.puerto||22)===2222?22022:2222;
    $('ssh-port-sudo').value=''; $('ssh-port-aplicar').disabled=true; $('ssh-port-cancelar').disabled=true; $('ssh-port-probar').disabled=false;
    sshSteps('','','');
    sshStatus('ssh-key-status',p.key?'Key actual: '+p.key:'Este perfil no tiene una key asignada todavía.','');
    sshStatus('ssh-port-status','Todavía no se ha cambiado nada.',''); sshPortLog('Esperando una prueba. La conexión actual no se cerrará.','',true);
    cerrarHerramientas(); $('sshadmin-velo').classList.add('abierto');
  }
  function cancelarPruebaPuerto(cerrarDespues){
    if(!sshPortToken){ if(cerrarDespues) $('sshadmin-velo').classList.remove('abierto'); return Promise.resolve(); }
    var tok=sshPortToken, srv=sshAdminServidor;
    return api('/api/herramientas/ssh-puerto/cancelar',{method:'POST',body:JSON.stringify({servidor:srv,token:tok,sudoPassword:$('ssh-port-sudo').value})}).then(function(r){
      if(r.error){ sshStatus('ssh-port-status',r.error,'err'); throw new Error(r.error); }
      sshPortToken=null; $('ssh-port-aplicar').disabled=true; $('ssh-port-cancelar').disabled=true; $('ssh-port-probar').disabled=false; sshSteps('','','');
      sshStatus('ssh-port-status','Prueba cancelada. Se restauró el puerto anterior.','');sshPortLog('↩ Prueba cancelada: configuración anterior restaurada.','warn');
      if(cerrarDespues) $('sshadmin-velo').classList.remove('abierto');
    });
  }
  function cerrarSSHAdmin(){
    if(sshPortToken){
      if(!confirm('Hay una prueba de puerto pendiente. ¿Cancelar la prueba y restaurar el puerto anterior antes de cerrar?')) return;
      cancelarPruebaPuerto(true).catch(function(e){ aviso(e.message||'No pude cancelar la prueba.',false); });
      return;
    }
    $('sshadmin-velo').classList.remove('abierto');
  }
  $('sshadmin-cerrar').onclick=cerrarSSHAdmin;
  $('tool-key').onclick=function(){ if(!toolsServidor){aviso('No hay servidor seleccionado.',false);return;} abrirSSHAdmin(toolsServidor); };
  $('tool-ssh-port-btn').onclick=function(){ if(!toolsServidor){aviso('No hay servidor seleccionado.',false);return;} abrirSSHAdmin(toolsServidor); setTimeout(function(){$('ssh-port-nuevo').focus();},60); };
  $('ssh-key-buscar').onclick=function(){
    if(!sshAdminServidor) return;
    selectorDestino='ssh-tool-key';
    $('sshadmin-velo').classList.remove('abierto');
    abrirArchivos(''); cargarLocal('');
    aviso('Elige tu key privada en "Tu equipo" y pulsa Usar.',true);
  };
  $('ssh-key-usar').onclick=function(){
    if(!sshAdminServidor) return;
    var key=$('ssh-key-path').value.trim(); if(!key){sshStatus('ssh-key-status','Selecciona primero una key privada.','warn');return;}
    var b=this;b.disabled=true;b.textContent='Probando…';sshStatus('ssh-key-status','Abriendo una segunda conexión SSH con esta key…','');
    api('/api/herramientas/usar-key',{method:'POST',body:JSON.stringify({servidor:sshAdminServidor,key:key,passphrase:$('ssh-key-pass').value,recordar:$('ssh-key-recordar').checked})}).then(function(r){
      if(r.necesitaPassphrase){sshStatus('ssh-key-status','La key necesita passphrase. Escríbela arriba y vuelve a probar.','warn');return;}
      if(r.error){sshStatus('ssh-key-status',r.error,'err');return;}
      $('ssh-key-path').value=r.key||key; sshStatus('ssh-key-status','✓ Key instalada/comprobada y asignada al perfil · '+(r.tipo||'')+' · '+(r.huellaKey||'')+(r.publicaInstalada?' · pública añadida al servidor':' · pública ya estaba instalada'),'ok');
      refrescarLista(); aviso('Key SSH comprobada y asignada al perfil.',true);
    }).catch(function(){sshStatus('ssh-key-status','Error de comunicación al probar la key.','err');}).finally(function(){b.disabled=false;b.textContent='Instalar, probar y usar esta key';});
  };
  $('ssh-key-crear').onclick=function(){
    if(!sshAdminServidor) return;
    if(!confirm('Se generará una ED25519 nueva en este equipo y se instalará únicamente su clave pública en '+sshAdminServidor+'. ¿Continuar?')) return;
    var b=this;b.disabled=true;b.textContent='Creando…';sshStatus('ssh-key-status','Generando, instalando la pública y abriendo una segunda conexión de prueba…','');
    api('/api/herramientas/crear-key',{method:'POST',body:JSON.stringify({servidor:sshAdminServidor})}).then(function(r){
      if(r.error){sshStatus('ssh-key-status',r.error,'err');return;}
      $('ssh-key-path').value=r.key||''; $('ssh-key-pass').value=''; sshStatus('ssh-key-status','✓ ED25519 creada, instalada y comprobada. Key local: '+(r.key||''),'ok');
      refrescarLista(); aviso('Nueva key SSH instalada y comprobada.',true);
    }).catch(function(){sshStatus('ssh-key-status','Error de comunicación al crear la key.','err');}).finally(function(){b.disabled=false;b.textContent='Crear e instalar nueva ED25519';});
  };
  $('ssh-port-probar').onclick=function(){
    if(!sshAdminServidor) return;
    var puerto=parseInt($('ssh-port-nuevo').value,10); if(!puerto||puerto<1||puerto>65535){sshStatus('ssh-port-status','Puerto inválido.','err');return;}
    var b=this;b.disabled=true;sshSteps('active','','');sshStatus('ssh-port-status','Preparando ambos puertos y ejecutando sshd -t…','');sshPortLog('1/3  Manteniendo abierto el puerto actual y preparando '+puerto+'…','',true);sshPortLog('     Validando firewall y sshd_config…','');
    api('/api/herramientas/ssh-puerto/probar',{method:'POST',body:JSON.stringify({servidor:sshAdminServidor,puerto:puerto,sudoPassword:$('ssh-port-sudo').value})}).then(function(r){
      if(r.error){sshSteps('','','');sshStatus('ssh-port-status',r.error,'err');sshPortLog('ERROR  '+r.error,'err');return;}
      sshPortToken=r.token; sshSteps('ok','ok',''); $('ssh-port-aplicar').disabled=false; $('ssh-port-cancelar').disabled=false; $('ssh-port-probar').disabled=true;sshPortLog('2/3  ✓ Segunda conexión SSH interna verificada por '+puerto+'.','ok');if(r.rollbackGuard)sshPortLog('     Protección activa: rollback automático en 5 min si el flujo queda abandonado.','warn');sshPortLog('     El perfil TODAVÍA usa el puerto anterior. Pulsa Aplicar para confirmar.','');
      sshStatus('ssh-port-status','✓ '+(r.mensaje||('Conexión real verificada por '+puerto+'. Pulsa Aplicar para guardar el cambio.')),'ok');
    }).catch(function(){sshSteps('','','');sshStatus('ssh-port-status','Error de comunicación durante la prueba.','err');sshPortLog('ERROR  No se pudo completar la prueba.','err');}).finally(function(){if(!sshPortToken)b.disabled=false;});
  };
  $('ssh-port-aplicar').onclick=function(){
    if(!sshPortToken||!sshAdminServidor) return;
    var b=this;b.disabled=true;sshSteps('ok','ok','active');sshStatus('ssh-port-status','Aplicando el puerto probado y haciendo una comprobación final…','');sshPortLog('3/3  Aplicando '+$('ssh-port-nuevo').value+' y ejecutando la comprobación final…','');
    api('/api/herramientas/ssh-puerto/aplicar',{method:'POST',body:JSON.stringify({servidor:sshAdminServidor,token:sshPortToken,cerrarAnterior:$('ssh-port-close-old').checked,sudoPassword:$('ssh-port-sudo').value})}).then(function(r){
      if(r.error){sshStatus('ssh-port-status',r.error,'err');sshPortLog('ERROR  '+r.error,'err');b.disabled=false;return;}
      sshPortToken=null; sshSteps('ok','ok','ok'); $('ssh-port-aplicar').disabled=true; $('ssh-port-cancelar').disabled=true; $('ssh-port-probar').disabled=false; $('ssh-port-actual').textContent=r.puerto;
      sshStatus('ssh-port-status','✓ '+(r.mensaje||('Puerto '+r.puerto+' aplicado y perfil actualizado.')),'ok');sshPortLog('✓ CAMBIO CONFIRMADO. Perfil actualizado a '+r.puerto+'.','ok');
      refrescarLista(); aviso('Puerto SSH cambiado y verificado.',true);
    }).catch(function(){sshStatus('ssh-port-status','Error de comunicación al aplicar. La sesión actual sigue abierta.','err');b.disabled=false;});
  };
  $('ssh-port-cancelar').onclick=function(){ cancelarPruebaPuerto(false).catch(function(e){aviso(e.message||'No pude cancelar la prueba.',false);}); };

  // ── Gateway WISP modular con terminal integrada ──────────────
  var gwServidor=null,gwTerm=null,gwFit=null,gwWs=null,gwPendingCmd=null,gwPackageReady=false,gwPreparing=false;
  function abrirGWTerminal(nombre){
    if(typeof Terminal!=='function'||typeof FitAddon==='undefined'||typeof FitAddon.FitAddon!=='function'){aviso('No se pudo cargar xterm.js.',false);return;}
    cerrarGWTerminal();
    var n=$('gw-term'); vaciar(n); gwTerm=new Terminal({cursorBlink:true,fontSize:12,fontFamily:"'JetBrains Mono', Consolas, monospace",theme:{background:'#050c12',foreground:'#d8e4ea',cursor:'#4de19a',selectionBackground:'#1f3b49'}}); gwFit=new FitAddon.FitAddon();gwTerm.loadAddon(gwFit);gwTerm.open(n);gwFit.fit();
    gwWs=new WebSocket(WS_BASE+'/ws/terminal?t='+TOKEN+'&nombre='+encodeURIComponent(nombre));gwWs.binaryType='arraybuffer';var enc=new TextEncoder();
    gwWs.onopen=function(){if(gwTerm){gwWs.send(JSON.stringify({cols:gwTerm.cols,rows:gwTerm.rows}));gwTerm.focus();if(gwPendingCmd){var cmd=gwPendingCmd;gwPendingCmd=null;setTimeout(function(){enviarGW(cmd);},80);}}};
    gwWs.onmessage=function(e){if(gwTerm)gwTerm.write(new Uint8Array(e.data));};gwWs.onerror=function(){if(gwTerm)gwTerm.write('\r\n\x1b[31m[error en terminal Gateway WISP]\x1b[0m\r\n');};gwWs.onclose=function(){if(gwTerm)gwTerm.write('\r\n\x1b[33m[sesión terminada]\x1b[0m\r\n');};
    gwTerm.onData(function(d){if(gwWs&&gwWs.readyState===1)gwWs.send(enc.encode(d));});gwTerm.onResize(function(t){if(gwWs&&gwWs.readyState===1)gwWs.send(JSON.stringify({cols:t.cols,rows:t.rows}));});
    setTimeout(function(){if(gwFit){gwFit.fit();gwTerm.focus();}},80);
  }
  function cerrarGWTerminal(){if(gwWs){gwWs.close();gwWs=null;}if(gwTerm){gwTerm.dispose();gwTerm=null;gwFit=null;}if($('gw-term'))vaciar($('gw-term'));}
  function enviarGW(cmd){if(!gwWs||gwWs.readyState!==1){gwPendingCmd=cmd;if(gwTerm)gwTerm.write('\r\n\x1b[33m[esperando a que la terminal esté lista…]\x1b[0m\r\n');return;}gwTerm.clear();gwTerm.write('\x1b[2J\x1b[H');gwWs.send(new TextEncoder().encode(cmd+'\r'));gwTerm.focus();}
  function gwBotones(disabled){$('gw-install-all').disabled=disabled;$('gw-uninstall-all').disabled=disabled;document.querySelectorAll('#gw-components button[data-a]').forEach(function(b){b.disabled=disabled;});}
  function prepararGWPaquete(){if(!gwServidor||gwPreparing)return Promise.resolve(false);gwPreparing=true;gwPackageReady=false;gwBotones(true);$('gw-package-state').textContent='Preparando paquete…';$('gw-package-state').className='gw-chip';return api('/api/herramientas/gateway-wisp/preparar',{method:'POST',body:JSON.stringify({servidor:gwServidor})}).then(function(r){if(r.error){$('gw-package-state').textContent='Error de paquete';$('gw-package-state').className='gw-chip';if(gwTerm)gwTerm.write('\r\n\x1b[31m[No pude preparar el paquete: '+r.error+']\x1b[0m\r\n');return false;}gwPackageReady=true;$('gw-bundle-ver').textContent='v'+(r.versionPaquete||'?');$('gw-package-state').textContent='✓ Paquete listo';$('gw-package-state').className='gw-chip ok';gwBotones(false);if(gwTerm)gwTerm.write('\r\n\x1b[32m[Gateway WISP '+(r.versionPaquete||'')+' listo. Elige una acción a la izquierda.]\x1b[0m\r\n');return true;}).catch(function(){$('gw-package-state').textContent='Error de paquete';return false;}).finally(function(){gwPreparing=false;});}
  function cargarGWEstado(){
    if(!gwServidor)return;$('gw-state-main').textContent='Consultando…';
    api('/api/herramientas/gateway-wisp/estado?servidor='+encodeURIComponent(gwServidor)).then(function(r){
      if(r.error){$('gw-state-main').textContent='No disponible';return;}
      $('gw-bundle-ver').textContent='v'+(r.versionPaquete||'?');$('gw-installed-ver').textContent=(r.version&&r.version!=='absent')?r.version:'—';$('gw-state-main').textContent=r.instalado?'● Gateway detectado':'○ No instalado';$('gw-state-main').className='gw-chip '+(r.instalado?'ok':'');
      document.querySelectorAll('#gw-components .gw-component').forEach(function(row){var c=row.dataset.comp;var st=(r.componentes||{})[c];var dot=row.querySelector('.gw-dot');if(dot)dot.className='gw-dot '+(st==='installed'?'ok':'');});
    }).catch(function(){$('gw-state-main').textContent='Error consultando';});
  }
  function abrirGatewayWISP(nombre){gwServidor=nombre;gwPackageReady=false;gwPendingCmd=null;$('gw-srv').textContent=nombre;cerrarHerramientas();$('gw-velo').classList.add('abierto');abrirGWTerminal(nombre);cargarGWEstado();prepararGWPaquete();setTimeout(function(){if(gwFit)gwFit.fit();},100);}
  function cerrarGatewayWISP(){$('gw-velo').classList.remove('abierto');cerrarGWTerminal();gwServidor=null;gwPackageReady=false;gwPendingCmd=null;}
  $('gw-cerrar').onclick=cerrarGatewayWISP;$('gw-refresh').onclick=cargarGWEstado;
  $('tool-gw-install').onclick=function(){if(!toolsServidor){aviso('No hay servidor seleccionado.',false);return;}abrirGatewayWISP(toolsServidor);};
  function gwAccion(accion,comp){
    if(!gwServidor)return;
    if((accion==='desinstalar-todo'||accion==='desinstalar-componente')&&!confirm(accion==='desinstalar-todo'?'Se creará un backup y se retirará la integración Gateway WISP sin purgar paquetes de terceros. ¿Continuar?':'¿Quitar de forma conservadora la integración de este componente?'))return;
    var ejecutar=function(){gwBotones(true);return api('/api/herramientas/gateway-wisp/comando',{method:'POST',body:JSON.stringify({servidor:gwServidor,accion:accion,componente:comp||''})}).then(function(r){if(r.error){aviso(r.error,false);return;}enviarGW(r.comando);}).catch(function(){aviso('No pude preparar el paquete Gateway WISP.',false);}).finally(function(){gwBotones(false);});};if(!gwPackageReady){prepararGWPaquete().then(function(ok){if(ok)ejecutar();});}else ejecutar();
  }
  $('gw-install-all').onclick=function(){gwAccion('instalar-todo','');};$('gw-uninstall-all').onclick=function(){gwAccion('desinstalar-todo','');};
  document.querySelectorAll('#gw-components .gw-component button[data-a]').forEach(function(b){b.onclick=function(){var row=b.closest('.gw-component'),comp=row.dataset.comp,act=b.dataset.a==='install'?'instalar-componente':'desinstalar-componente';gwAccion(act,comp);};});

  $('tool-firewall').onclick=function(){
    if(!toolsServidor){ aviso('No hay servidor seleccionado.',false); return; }
    firewallServidor=toolsServidor;
    $('fw-srv').textContent=firewallServidor;
    $('m-firewall').classList.add('abierto');
    cargarFirewall();
  };
  function cerrarFirewall(){ $('m-firewall').classList.remove('abierto'); }
  $('fw-salir').onclick=cerrarFirewall;
  $('fw-refrescar').onclick=cargarFirewall;
  function cambiarPuertoFirewall(accion,boton){
    if(!firewallServidor||!firewallEditable) return;
    var puerto=parseInt($('fw-puerto').value,10);
    if(!puerto||puerto<1||puerto>65535){ aviso('Escribe un puerto entre 1 y 65535.',false); return; }
    var proto=$('fw-proto').value;
    var original=boton.textContent; boton.disabled=true; boton.textContent=accion==='abrir'?'Abriendo…':'Cerrando…';
    $('fw-nota').textContent='Creando backup y aplicando el cambio…'; $('fw-nota').className='fw-note';
    api('/api/herramientas/firewall',{method:'POST',body:JSON.stringify({servidor:firewallServidor,accion:accion,puerto:puerto,protocolo:proto})}).then(function(r){
      if(r.error){ $('fw-nota').textContent=r.error; $('fw-nota').className='fw-note err'; aviso(r.error,false); return; }
      pintarFirewall(r.estado);
      $('fw-nota').textContent=(accion==='abrir'?'Puerto abierto. ':'Puerto cerrado. ')+(r.backup?'Backup: '+r.backup:'');
      $('fw-nota').className='fw-note ok';
      aviso((accion==='abrir'?'Puerto abierto: ':'Puerto cerrado: ')+puerto+'/'+proto,true);
    }).catch(function(){ $('fw-nota').textContent='No pude aplicar el cambio de firewall.'; $('fw-nota').className='fw-note err'; }).finally(function(){ boton.textContent=original; boton.disabled=!firewallEditable; });
  }
  $('fw-abrir').onclick=function(){ cambiarPuertoFirewall('abrir',this); };
  $('fw-cerrar-puerto').onclick=function(){ cambiarPuertoFirewall('cerrar',this); };

  // ── Selector de clave SSH y diagnóstico ──────────────────────
  var selectorDestino = null;  // 'key' | 'script' | null
  var selectorScriptServidor = null;
  document.getElementById('btn-buscar-key').onclick = function(){
    selectorDestino = 'key';
    abrirArchivos('');
    cargarLocal('');
    aviso('Elige tu clave en el panel "Tu equipo" (botón Usar).', true);
  };
  document.getElementById('btn-probar-key').onclick = function(){
    var key = document.getElementById('f-key').value.trim();
    var res = document.getElementById('key-res');
    if (!key){ res.textContent = 'Escribe o busca la ruta de la clave.'; return; }
    res.textContent = 'Probando…';
    api('/api/probar-key', {method:'POST', body: JSON.stringify({
      key: key, passphrase: document.getElementById('f-pass').value
    })}).then(function(r){
      if (r.error){ res.textContent = r.error; res.style.color = 'var(--rojo)'; return; }
      if (r.necesitaPassphrase){
        res.textContent = 'La clave tiene passphrase: escríbela en el campo Contraseña de abajo y marca Recordar si quieres guardarla.';
        res.style.color = 'var(--ambar)'; return;
      }
      res.textContent = 'Clave válida (' + r.tipo + ') · ' + r.huella; res.style.color = 'var(--verde)';
      document.getElementById('f-key').value = r.rutaFinal;
    });
  };
  // etiqueta dinámica: con key, lo que se guarda es la passphrase
  document.getElementById('f-key').addEventListener('input', function(){
    document.getElementById('lbl-pass').textContent =
      this.value.trim() ? 'Passphrase de la clave (si tiene)' : 'Contraseña';
  });

  // ── Gestor de archivos ───────────────────────────────────────
  var fxServidor = null, fxRutaRem = '', fxRutaLoc = '';

  function abrirArchivos(nombre){
    refrescarSelectorServidores();
    var sel = document.getElementById('fx-servidor');
    if (nombre && Array.prototype.some.call(sel.options, function(o){ return o.value === nombre; })) sel.value = nombre;
    fxServidor = nombre || sel.value || null;
    document.getElementById('fx-srv').textContent = fxServidor || 'solo equipo local';
    document.getElementById('fx-velo').classList.add('abierto');
    if (!fxRutaLoc) cargarLocal('');
    if (fxServidor) cargarRemoto('');
    else mensajeEn(document.getElementById('fx-lista-rem'), 'vacio-fx', 'Conecta un servidor para explorar sus archivos.');
  }

  function cerrarArchivos(){
    var destinoAnterior=selectorDestino;
    document.getElementById('fx-velo').classList.remove('abierto');
    selectorDestino = null;
    if(destinoAnterior==='ssh-tool-key' && sshAdminServidor) document.getElementById('sshadmin-velo').classList.add('abierto');
  }
  document.getElementById('fx-cerrar').onclick = cerrarArchivos;

  function refrescarSelectorServidores(){
    var sel = document.getElementById('fx-servidor');
    var activos = (estadoActual.conexiones || []).map(function(c){ return c.servidor; });
    var previo = sel.value;
    vaciar(sel);
    if (activos.length){
      activos.forEach(function(n){ var o=nodo('option','',n); o.value=n; sel.appendChild(o); });
    } else {
      var o=nodo('option','','— sin conexiones activas —'); o.value=''; sel.appendChild(o);
    }
    if (activos.indexOf(previo) !== -1) sel.value = previo;
  }

  function iconoDe(a){ return a.carpeta ? '📁' : '📄'; }
  function fmtTam(a){ return a.carpeta ? '' : fmtB(a.tamano); }

  function cargarRemoto(ruta){
    if (!fxServidor){ aviso('Elige un servidor conectado.', false); return; }
    api('/api/archivos', {method:'POST', body: JSON.stringify({servidor: fxServidor, ruta: ruta})})
      .then(function(d){
        var cont = document.getElementById('fx-lista-rem');
        if (d.error){ mensajeEn(cont, 'vacio-fx', d.error); return; }
        fxRutaRem = d.ruta;
        document.getElementById('fx-ruta-rem').value = d.ruta;
        if (!d.archivos || !d.archivos.length){ mensajeEn(cont, 'vacio-fx', 'Carpeta vacía.'); return; }
        vaciar(cont);
        d.archivos.forEach(function(a){
          var it = nodo('div', 'it');
          it.appendChild(nodo('span', 'ic', iconoDe(a)));
          it.appendChild(nodo('span', 'nm', a.nombre));
          it.appendChild(nodo('span', 'meta', fmtTam(a)));
          if (a.carpeta){
            it.onclick = function(ev){ if (ev.target.tagName !== 'BUTTON') cargarRemoto(a.ruta); };
          } else {
            var bD = document.createElement('button'); bD.textContent = '⬇ Bajar';
            bD.onclick = function(ev){
              ev.stopPropagation();
              bD.disabled = true; bD.textContent = '…';
              api('/api/archivos/descargar', {method:'POST', body: JSON.stringify({
                servidor: fxServidor, ruta: a.ruta, destinoLocal: fxRutaLoc
              })}).then(function(r){
                if (r.error) aviso(r.error, false);
                else { aviso('Descargado: ' + r.destino, true); cargarLocal(fxRutaLoc); }
              }).finally(function(){ bD.disabled = false; bD.textContent = '⬇ Bajar'; });
            };
            it.appendChild(bD);
          }
          var bR = document.createElement('button'); bR.textContent = '✎';
          bR.title = 'Renombrar';
          bR.onclick = function(ev){
            ev.stopPropagation();
            var nuevo = prompt('Nuevo nombre para ' + a.nombre + ':', a.nombre);
            if (!nuevo || nuevo === a.nombre) return;
            var destino = fxRutaRem.replace(/\/$/,'') + '/' + nuevo;
            api('/api/archivos', {method:'POST', body: JSON.stringify({
              servidor: fxServidor, accion: 'renombrar', ruta: a.ruta, destino: destino
            })}).then(function(r){ r.error ? aviso(r.error,false) : cargarRemoto(fxRutaRem); });
          };
          var bB = document.createElement('button'); bB.className='peligro'; bB.textContent = '✕';
          bB.title = 'Borrar';
          bB.onclick = function(ev){
            ev.stopPropagation();
            if (!confirm('¿Borrar ' + a.nombre + ' en el servidor?')) return;
            api('/api/archivos', {method:'POST', body: JSON.stringify({
              servidor: fxServidor, accion: 'borrar', ruta: a.ruta
            })}).then(function(r){ r.error ? aviso(r.error,false) : cargarRemoto(fxRutaRem); });
          };
          it.appendChild(bR); it.appendChild(bB);
          cont.appendChild(it);
        });
      }).catch(function(){});
  }

  function cargarLocal(ruta){
    api('/api/local?ruta=' + encodeURIComponent(ruta || '')).then(function(d){
      var cont = document.getElementById('fx-lista-loc');
      if (d.error){ mensajeEn(cont, 'vacio-fx', d.error); return; }
      fxRutaLoc = d.ruta;
      document.getElementById('fx-ruta-loc').value = d.ruta;
      if (!d.archivos || !d.archivos.length){ mensajeEn(cont, 'vacio-fx', 'Carpeta vacía.'); return; }
      vaciar(cont);
      d.archivos.forEach(function(a){
        var it = nodo('div', 'it');
        it.appendChild(nodo('span', 'ic', iconoDe(a)));
        it.appendChild(nodo('span', 'nm', a.nombre));
        it.appendChild(nodo('span', 'meta', fmtTam(a)));
        if (a.carpeta){
          it.onclick = function(ev){ if (ev.target.tagName !== 'BUTTON') cargarLocal(a.ruta); };
        } else {
          if (selectorDestino === 'key'){
            var bU = document.createElement('button'); bU.className='principal'; bU.textContent = 'Usar';
            bU.onclick = function(ev){
              ev.stopPropagation();
              document.getElementById('f-key').value = a.ruta;
              document.getElementById('f-key').dispatchEvent(new Event('input'));
              cerrarArchivos();
              abrirFormulario();
              document.getElementById('btn-probar-key').click();
              document.getElementById('form').scrollIntoView({behavior:'smooth'});
            };
            it.appendChild(bU);
          }
          if (selectorDestino === 'ssh-tool-key'){
            var bKU=document.createElement('button'); bKU.className='principal'; bKU.textContent='Usar';
            bKU.onclick=function(ev){ev.stopPropagation(); document.getElementById('ssh-key-path').value=a.ruta; cerrarArchivos(); sshStatus('ssh-key-status','Key seleccionada. Pulsa Probar y usar esta key.','');};
            it.appendChild(bKU);
          }
          if (selectorDestino === 'script'){
            var bE = document.createElement('button'); bE.className='principal'; bE.textContent = 'Ejecutar';
            bE.onclick = function(ev){
              ev.stopPropagation();
              var srv = selectorScriptServidor;
              if (!srv){ aviso('No hay servidor seleccionado.',false); return; }
              bE.disabled=true; bE.textContent='Subiendo…';
              api('/api/herramientas/ejecutar-script',{method:'POST',body:JSON.stringify({servidor:srv,rutaLocal:a.ruta})}).then(function(r){
                if (r.error){ aviso(r.error,false); return; }
                cerrarArchivos(); selectorDestino=null; selectorScriptServidor=null;
                aviso('Script cargado en '+r.remoto+'. Abriendo terminal…',true);
                abrirTerminal(srv,r.comando,!!r.silencioso);
              }).catch(function(){ aviso('Error cargando el script.',false); }).finally(function(){ bE.disabled=false; bE.textContent='Ejecutar'; });
            };
            it.appendChild(bE);
          } else {
          var bS = document.createElement('button'); bS.textContent = '⬆ Subir';
          bS.onclick = function(ev){
            ev.stopPropagation();
            if (!fxServidor || !fxRutaRem){ aviso('Abre primero una carpeta del servidor.', false); return; }
            bS.disabled = true; bS.textContent = '…';
            api('/api/archivos/subir', {method:'POST', body: JSON.stringify({
              servidor: fxServidor, rutaLocal: a.ruta, carpetaRemota: fxRutaRem
            })}).then(function(r){
              if (r.error) aviso(r.error, false);
              else { aviso('Subido: ' + r.destino, true); cargarRemoto(fxRutaRem); }
            }).finally(function(){ bS.disabled = false; bS.textContent = '⬆ Subir'; });
          };
          it.appendChild(bS);
          }
        }
        cont.appendChild(it);
      });
    }).catch(function(){});
  }

  document.getElementById('fx-abrir').onclick = function(){
    fxServidor = document.getElementById('fx-servidor').value;
    document.getElementById('fx-srv').textContent = fxServidor || 'solo equipo local';
    if (!fxServidor){ aviso('No hay conexiones activas.', false); return; }
    cargarRemoto('');
    if (!fxRutaLoc) cargarLocal('');
  };
  document.getElementById('fx-ir-rem').onclick = function(){ cargarRemoto(document.getElementById('fx-ruta-rem').value); };
  document.getElementById('fx-ir-loc').onclick = function(){ cargarLocal(document.getElementById('fx-ruta-loc').value); };
  document.getElementById('fx-arriba-rem').onclick = function(){
    var p = fxRutaRem.replace(/\/+$/,'').split('/').slice(0,-1).join('/') || '/';
    cargarRemoto(p);
  };
  document.getElementById('fx-arriba-loc').onclick = function(){
    var sep = fxRutaLoc.indexOf('\\') !== -1 ? '\\' : '/';
    var p = fxRutaLoc.replace(/[\\/]+$/,'').split(sep).slice(0,-1).join(sep) || sep;
    cargarLocal(p);
  };
  document.getElementById('fx-nueva-carpeta').onclick = function(){
    if (!fxServidor || !fxRutaRem){ aviso('Abre primero una carpeta del servidor.', false); return; }
    var nombre = prompt('Nombre de la nueva carpeta:');
    if (!nombre) return;
    api('/api/archivos', {method:'POST', body: JSON.stringify({
      servidor: fxServidor, accion: 'carpeta', ruta: fxRutaRem.replace(/\/$/,'') + '/' + nombre
    })}).then(function(r){ r.error ? aviso(r.error,false) : cargarRemoto(fxRutaRem); });
  };
  cargarLocal('');
