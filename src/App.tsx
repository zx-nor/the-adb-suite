import { useState, useEffect, useRef, useCallback } from 'react';

// ============================================================================
// ADB PROTOCOL CONSTANTS
// ============================================================================
const A_CNXN = 0x4e584e43, A_AUTH = 0x48545541, A_OPEN = 0x4e45504f,
  A_OKAY = 0x59414b4f, A_CLSE = 0x45534c43, A_WRTE = 0x45545257;

const CMD_NAMES: Record<number, string> = {
  [A_CNXN]: 'CNXN', [A_AUTH]: 'AUTH', [A_OPEN]: 'OPEN',
  [A_OKAY]: 'OKAY', [A_CLSE]: 'CLSE', [A_WRTE]: 'WRTE'
};

const AUTH_TOKEN = 1, AUTH_SIGNATURE = 2, AUTH_RSAPUBLICKEY = 3;
const ADB_VERSION = 0x01000000;
const MAX_PAYLOAD = 4096;

// ============================================================================
// ADB CRYPTO
// ============================================================================
class AdbCrypto {
  keyPair: CryptoKeyPair | null = null;

  async loadOrCreate() {
    const stored = await this._load();
    if (stored) { this.keyPair = stored; return; }
    this.keyPair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
      true, ['sign', 'verify']
    ) as CryptoKeyPair;
    await this._save();
  }

  async _save() {
    const priv = await crypto.subtle.exportKey('jwk', this.keyPair!.privateKey);
    const pub = await crypto.subtle.exportKey('jwk', this.keyPair!.publicKey);
    localStorage.setItem('adb-keys', JSON.stringify({ priv, pub }));
  }

  async _load(): Promise<CryptoKeyPair | null> {
    const s = localStorage.getItem('adb-keys');
    if (!s) return null;
    try {
      const { priv, pub } = JSON.parse(s);
      const privK = await crypto.subtle.importKey('jwk', priv, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' }, true, ['sign']);
      const pubK = await crypto.subtle.importKey('jwk', pub, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' }, true, ['verify']);
      return { privateKey: privK, publicKey: pubK };
    } catch { return null; }
  }

  async signToken(token: Uint8Array) {
    return new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', this.keyPair!.privateKey, token as unknown as BufferSource));
  }

  async getPublicKeyADB() {
    const jwk = await crypto.subtle.exportKey('jwk', this.keyPair!.publicKey);
    const n = this._b64ToBigEndian(jwk.n!);
    const e = this._b64ToBigEndian(jwk.e!);
    if (n.length !== 256) throw new Error('Bad modulus length');

    const nLE = new Uint8Array(n).reverse();
    const R = BigInt(1) << 2048n;
    const nBig = this._bytesToBigInt(nLE);
    const R2 = (R * R) % nBig;
    const R2Bytes = this._bigIntToBytesLE(R2, 256);

    const n0 = nLE[0];
    const n0inv = this._modInverse((-n0 + 0x100000000) % 0x100000000, 0x100000000);

    const out = new Uint8Array(4 + 4 + 256 + 256 + 4);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, 64, true);
    dv.setInt32(4, n0inv, true);
    out.set(nLE, 8);
    out.set(R2Bytes, 264);
    dv.setUint32(520, e[e.length - 1] || 0x03, true);

    let b64 = btoa(String.fromCharCode(...out));
    const suffix = ' ADBDirect@web\x00';
    return b64 + suffix;
  }

  _b64ToBigEndian(b64: string) {
    const raw = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    let start = 0;
    while (start < bytes.length && bytes[start] === 0) start++;
    const stripped = bytes.slice(start);
    if (stripped.length === 256) return stripped;
    const padded = new Uint8Array(256);
    padded.set(stripped, 256 - stripped.length);
    return padded;
  }

  _bytesToBigInt(bytes: Uint8Array) {
    let r = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(bytes[i]);
    return r;
  }

  _bigIntToBytesLE(n: bigint, len: number) {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) { out[i] = Number(n & 0xFFn); n >>= 8n; }
    return out;
  }

  _modInverse(a: number, m: number) {
    a = ((a % m) + m) % m;
    let [old_r, r] = [a, m];
    let [old_s, s] = [1, 0];
    while (r !== 0) {
      const q = Math.floor(old_r / r);
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % m) + m) % m;
  }
}

// ============================================================================
// ADB DEVICE
// ============================================================================
interface StreamData {
  buffer: number[];
  callback: ((data: Uint8Array) => void) | null;
  remoteId?: number;
  onOpen?: () => void;
  onClose?: () => void;
}

interface PacketInfo {
  dir: 'in' | 'out';
  cmd: number;
  arg0: number;
  arg1: number;
  data: Uint8Array;
  size: number;
}

class AdbDevice {
  device: USBDevice | null = null;
  inEndpoint: number | null = null;
  outEndpoint: number | null = null;
  connected = false;
  authenticated = false;
  crypto = new AdbCrypto();
  localIdCounter = 1;
  streams = new Map<number, StreamData>();
  pendingAuth: Uint8Array | null = null;
  onPacket: ((pkt: PacketInfo) => void) | null = null;
  remoteBanner = '';
  private _cnxnResolve: ((banner: string) => void) | null = null;
  private _authResolve: (() => void) | null = null;

  async connect() {
    if (!('usb' in navigator)) throw new Error('WebUSB not supported — use Chrome/Edge over HTTPS');
    
    this.device = await navigator.usb.requestDevice({
      filters: [{ classCode: 0xff, subclassCode: 0x42, protocolCode: 0x01 }]
    });
    
    await this.device.open();

    // FIX: Find ADB interface across all configurations FIRST
    let adbInterface: USBInterface | null = null;
    let adbAlt: USBAlternateInterface | null = null;
    let targetConfigValue: number | null = null;

    for (const cfg of this.device.configurations) {
      for (const iface of cfg.interfaces) {
        for (const alt of iface.alternates) {
          if (alt.interfaceClass === 0xff && alt.interfaceSubclass === 0x42 && alt.interfaceProtocol === 0x01) {
            adbInterface = iface;
            adbAlt = alt;
            targetConfigValue = cfg.configurationValue;
            break;
          }
        }
        if (adbInterface) break;
      }
      if (adbInterface) break;
    }

    if (!adbInterface || !adbAlt) throw new Error('No ADB interface found');

    // FIX: Only select configuration if needed, and use the CORRECT config value
    if (targetConfigValue !== null) {
      if (!this.device.configuration || this.device.configuration.configurationValue !== targetConfigValue) {
        try {
          await this.device.selectConfiguration(targetConfigValue);
        } catch (e) {
          // If selection fails, try without selecting (device may already be configured)
          console.warn('selectConfiguration failed, proceeding with current config:', e);
        }
      }
    }

    await this.device.claimInterface(adbInterface.interfaceNumber);

    for (const ep of adbAlt.endpoints) {
      if (ep.direction === 'in') this.inEndpoint = ep.endpointNumber;
      else this.outEndpoint = ep.endpointNumber;
    }

    if (!this.inEndpoint || !this.outEndpoint) throw new Error('Could not find ADB endpoints');

    this.connected = true;
    this._startReadLoop();
    await this._handshake();
  }

  _startReadLoop() {
    const readLoop = async () => {
      while (this.connected) {
        try {
          const result = await this.device!.transferIn(this.inEndpoint!, 16384);
          if (result.status === 'ok' && result.data && result.data.byteLength >= 24) {
            await this._handleMessage(new Uint8Array(result.data.buffer, result.data.byteOffset, result.data.byteLength));
          }
        } catch (e) {
          if (this.connected) console.warn('Read error', e);
          break;
        }
      }
    };
    readLoop();
  }

  async _sendMessage(cmd: number, arg0: number, arg1: number, data = new Uint8Array()) {
    const header = new ArrayBuffer(24);
    const dv = new DataView(header);
    dv.setUint32(0, cmd, true);
    dv.setUint32(4, arg0, true);
    dv.setUint32(8, arg1, true);
    dv.setUint32(12, data.byteLength, true);
    let checksum = 0;
    for (let i = 0; i < data.byteLength; i++) checksum = (checksum + data[i]) >>> 0;
    dv.setUint32(16, checksum, true);
    dv.setUint32(20, cmd ^ 0xffffffff, true);

    const packet = new Uint8Array(24 + data.byteLength);
    packet.set(new Uint8Array(header), 0);
    packet.set(data, 24);

    if (this.onPacket) this.onPacket({ dir: 'out', cmd, arg0, arg1, data, size: packet.length });
    await this.device!.transferOut(this.outEndpoint!, packet);
  }

  async _handleMessage(buf: Uint8Array) {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const cmd = dv.getUint32(0, true);
    const arg0 = dv.getUint32(4, true);
    const arg1 = dv.getUint32(8, true);
    const len = dv.getUint32(12, true);
    const data = len > 0 && buf.byteLength >= 24 + len
      ? new Uint8Array(buf.buffer, buf.byteOffset + 24, len)
      : new Uint8Array();

    if (this.onPacket) this.onPacket({ dir: 'in', cmd, arg0, arg1, data, size: buf.byteLength });

    if (cmd === A_CNXN) {
      this.authenticated = true;
      const banner = new TextDecoder().decode(data);
      this.remoteBanner = banner;
      if (this._cnxnResolve) this._cnxnResolve(banner);
    } else if (cmd === A_AUTH && arg0 === AUTH_TOKEN) {
      this.pendingAuth = data;
      if (this._authResolve) this._authResolve();
    } else if (cmd === A_OKAY) {
      const stream = this.streams.get(arg1);
      if (stream) { stream.remoteId = arg0; if (stream.onOpen) stream.onOpen(); }
    } else if (cmd === A_WRTE) {
      const stream = this.streams.get(arg1);
      if (stream) {
        if (stream.callback) stream.callback(data);
        else stream.buffer.push(...data);
        await this._sendMessage(A_OKAY, arg1, arg0);
      }
    } else if (cmd === A_CLSE) {
      const stream = this.streams.get(arg1);
      if (stream) {
        if (stream.onClose) stream.onClose();
        this.streams.delete(arg1);
      }
      await this._sendMessage(A_OKAY, arg1, arg0);
    }
  }

  async _handshake() {
    await this.crypto.loadOrCreate();
    await this._sendMessage(A_CNXN, ADB_VERSION, MAX_PAYLOAD, new TextEncoder().encode('host::features=shell_v2,cmd,stat_v2\x00'));

    const result = await Promise.race([
      new Promise<string>(r => { this._cnxnResolve = r; }).then(b => ({ type: 'cnxn', banner: b })),
      new Promise<void>(r => { this._authResolve = r; }).then(() => ({ type: 'auth' }))
    ]);

    if (result.type === 'auth') {
      const sig = await this.crypto.signToken(this.pendingAuth!);
      await this._sendMessage(A_AUTH, AUTH_SIGNATURE, 0, sig);

      const r2 = await Promise.race([
        new Promise<string>(r => { this._cnxnResolve = r; }).then(b => ({ type: 'cnxn', banner: b })),
        new Promise<void>(r => { this._authResolve = r; }).then(() => ({ type: 'auth2' })),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('Auth timeout — tap Allow on device')), 30000))
      ]);

      if (r2.type === 'auth2') {
        const pubkey = await this.crypto.getPublicKeyADB();
        await this._sendMessage(A_AUTH, AUTH_RSAPUBLICKEY, 0, new TextEncoder().encode(pubkey));
        const banner = await new Promise<string>((r, j) => {
          this._cnxnResolve = r;
          setTimeout(() => j(new Error('User did not authorize on device')), 60000);
        });
        this.remoteBanner = banner;
      }
    }

    return this.remoteBanner;
  }

  async openShell(command: string, onOutput: ((data: Uint8Array) => void) | null): Promise<Uint8Array> {
    const localId = this.localIdCounter++;
    const stream: StreamData = { buffer: [], callback: onOutput };
    this.streams.set(localId, stream);

    const dest = `shell:${command}\x00`;
    await this._sendMessage(A_OPEN, localId, 0, new TextEncoder().encode(dest));

    await new Promise<void>((r, j) => {
      stream.onOpen = r;
      setTimeout(() => j(new Error('Shell open timeout')), 5000);
    });

    return new Promise<Uint8Array>((r) => {
      stream.onClose = () => r(new Uint8Array(stream.buffer));
    });
  }

  async shell(command: string) {
    const out = await this.openShell(command, null);
    return new TextDecoder().decode(out);
  }

  async disconnect() {
    this.connected = false;
    this.authenticated = false;
    try {
      for (const [, s] of this.streams) {
        if (s.onClose) s.onClose();
      }
      this.streams.clear();
      if (this.device) await this.device.close();
    } catch (e) { console.warn(e); }
  }
}

// ============================================================================
// REACT APP
// ============================================================================

const SHELL_PRESETS = [
  ['whoami', 'whoami'], ['id', 'id'], ['ps', 'ps -A | head -30'],
  ['top (1s)', 'top -n 1 -b | head -20'], ['df', 'df -h'], ['mount', 'mount | head -20'],
  ['ip addr', 'ip addr'], ['netstat', 'netstat -tulnp | head'], ['logcat brief', 'logcat -d -t 20'],
  ['dumpsys battery', 'dumpsys battery'], ['settings', 'settings list global | head -20'],
  ['pm list packages', 'pm list packages | head -30'], ['getprop sdk', 'getprop ro.build.version.sdk']
];

function kvRow(k: string, v: string, cls = '') {
  return `<div class="kv-row"><div class="k">${k}</div><div class="v ${cls}">${v}</div></div>`;
}

export default function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [connStatus, setConnStatus] = useState({ text: 'DISCONNECTED', cls: '' });
  const [isConnected, setIsConnected] = useState(false);
  const [toastMsg, setToastMsg] = useState({ text: '', cls: '', show: false });
  const [modal, setModal] = useState({ show: false, title: '', body: '' });
  const [shellInput, setShellInput] = useState('');
  const [filePath, setFilePath] = useState('/sdcard');
  const [logFilter, setLogFilter] = useState('');
  const [lockInput, setLockInput] = useState('');
  const [pkgSearch, setPkgSearch] = useState('');

  const adbRef = useRef(new AdbDevice());
  const shellTermRef = useRef<HTMLDivElement>(null);
  const cmdHistoryRef = useRef<string[]>([]);
  const cmdIdxRef = useRef(-1);
  const logcatRunningRef = useRef(false);
  const sensorRunningRef = useRef(false);
  const thermalRunningRef = useRef(false);
  const sensorHistoryRef = useRef({ x: [] as number[], y: [] as number[], z: [] as number[] });
  const thermalHistoryRef = useRef([] as { time: number; batt: number; thermal: number; freq: number }[]);
  const packetsRef = useRef<PacketInfo[]>([]);
  const pktListRef = useRef<HTMLDivElement>(null);
  const logOutputRef = useRef<HTMLDivElement>(null);
  const sensorCanvasRef = useRef<HTMLCanvasElement>(null);
  const thermalCanvasRef = useRef<HTMLCanvasElement>(null);

  const toast = useCallback((msg: string, type = '') => {
    setToastMsg({ text: msg, cls: type, show: true });
    setTimeout(() => setToastMsg(prev => ({ ...prev, show: false })), 3000);
  }, []);

  const showModal = useCallback((title: string, body: string) => {
    setModal({ show: true, title, body });
  }, []);

  const appendTerm = useCallback((text: string, cls = '') => {
    if (!shellTermRef.current) return;
    const line = document.createElement('div');
    if (cls) line.className = cls;
    line.textContent = text;
    shellTermRef.current.appendChild(line);
    shellTermRef.current.scrollTop = shellTermRef.current.scrollHeight;
  }, []);

  const requireConn = useCallback(() => {
    if (!isConnected) { toast('Connect a device first', 'err'); return false; }
    return true;
  }, [isConnected, toast]);

  const logPacket = useCallback((pkt: PacketInfo) => {
    packetsRef.current.push(pkt);
    if (!pktListRef.current) return;
    const cmd = CMD_NAMES[pkt.cmd] || ('0x' + pkt.cmd.toString(16));
    const dataStr = pkt.data && pkt.data.length > 0
      ? new TextDecoder('utf-8', { fatal: false }).decode(pkt.data).replace(/[^\x20-\x7e]/g, '.').slice(0, 60)
      : '';
    const el = document.createElement('div');
    el.className = 'pkt ' + pkt.dir;
    el.innerHTML = `<span class="dir">${pkt.dir === 'out' ? '→ OUT' : '← IN'}</span><span class="cmd">${cmd}</span><span style="color:var(--dim)">${pkt.arg0.toString(16)}</span><span style="color:var(--dim)">${pkt.arg1.toString(16)}</span><span style="color:var(--text)">${pkt.size}B ${dataStr ? '· ' + dataStr : ''}</span>`;
    pktListRef.current.appendChild(el);
    if (pktListRef.current.childElementCount > 500 && pktListRef.current.firstChild) pktListRef.current.removeChild(pktListRef.current.firstChild);
    pktListRef.current.scrollTop = pktListRef.current.scrollHeight;
  }, []);

  // ---- CONNECTION ----
  const handleConnect = async () => {
    try {
      setConnStatus({ text: 'REQUESTING...', cls: 'warn' });
      const adb = adbRef.current;
      await adb.connect();
      adb.onPacket = logPacket;
      setIsConnected(true);
      setConnStatus({ text: 'CONNECTED', cls: 'ok' });
      toast('Connected: ' + adb.remoteBanner.split(':')[0]);
      await loadDashboard();
    } catch (e: unknown) {
      setConnStatus({ text: 'FAILED', cls: 'err' });
      toast((e as Error).message, 'err');
    }
  };

  const handleDisconnect = async () => {
    await adbRef.current.disconnect();
    setIsConnected(false);
    setConnStatus({ text: 'DISCONNECTED', cls: '' });
  };

  // ---- DASHBOARD ----
  const loadDashboard = async () => {
    const adb = adbRef.current;
    try {
      const [props, mem, uptime] = await Promise.all([
        adb.shell('getprop'), adb.shell('cat /proc/meminfo'), adb.shell('uptime')
      ]);
      const p: Record<string, string> = {};
      props.split('\n').forEach(line => {
        const m = line.match(/\[([^\]]+)\]:\s*\[([^\]]*)\]/);
        if (m) p[m[1]] = m[2];
      });

      const memInfo: Record<string, number> = {};
      mem.split('\n').forEach(line => {
        const m = line.match(/^(\w+):\s+(\d+)/);
        if (m) memInfo[m[1]] = parseInt(m[2]);
      });

      // Update dashboard stats
      const statsEl = document.getElementById('dashStats');
      if (statsEl) {
        statsEl.innerHTML = `
          <div class="card"><div class="stat-label">SDK Level</div><div class="stat-big">${p['ro.build.version.sdk'] || '?'}</div><div class="stat-sub">${p['ro.build.version.release'] || ''}</div></div>
          <div class="card"><div class="stat-label">Total RAM</div><div class="stat-big">${((memInfo.MemTotal || 0) / 1024 / 1024).toFixed(1)}G</div><div class="stat-sub">Free: ${((memInfo.MemFree || 0) / 1024 / 1024).toFixed(2)}G</div></div>
          <div class="card"><div class="stat-label">CPU ABI</div><div class="stat-big" style="font-size:16px">${p['ro.product.cpu.abi'] || '?'}</div><div class="stat-sub">${p['ro.product.cpu.abilist'] || ''}</div></div>
          <div class="card"><div class="stat-label">Uptime</div><div class="stat-big" style="font-size:16px">${uptime.trim().split(',')[0]}</div><div class="stat-sub">load avg visible in uptime</div></div>
        `;
      }

      const idEl = document.getElementById('kvIdentity');
      if (idEl) idEl.innerHTML = kvRow('Model', `<strong>${p['ro.product.model'] || '?'}</strong>`) +
        kvRow('Manufacturer', p['ro.product.manufacturer'] || '?') +
        kvRow('Brand', p['ro.product.brand'] || '?') +
        kvRow('Device', p['ro.product.device'] || '?') +
        kvRow('Serial', p['ro.serialno'] || '?') +
        kvRow('Fingerprint', p['ro.build.fingerprint'] || '?');

      const hwEl = document.getElementById('kvHardware');
      if (hwEl) hwEl.innerHTML = kvRow('Chip', p['ro.hardware.chipname'] || p['ro.board.platform'] || '?') +
        kvRow('CPU ABI', p['ro.product.cpu.abi'] || '?') +
        kvRow('ABIs', p['ro.product.cpu.abilist'] || '?') +
        kvRow('Bootloader', p['ro.bootloader'] || '?') +
        kvRow('Hardware', p['ro.hardware'] || '?');

      const buildEl = document.getElementById('kvBuild');
      if (buildEl) buildEl.innerHTML = kvRow('Android', `<strong>${p['ro.build.version.release'] || '?'}</strong>`) +
        kvRow('SDK', p['ro.build.version.sdk'] || '?') +
        kvRow('Security Patch', p['ro.build.version.security_patch'] || '?') +
        kvRow('Build ID', p['ro.build.id'] || '?') +
        kvRow('Build Type', p['ro.build.type'] || '?') +
        kvRow('Build Date', p['ro.build.date'] || '?');

      const wm = await adb.shell('wm size && wm density');
      const dispEl = document.getElementById('kvDisplay');
      if (dispEl) dispEl.innerHTML = kvRow('Raw Output', wm.trim().replace(/\n/g, ' · '));

      const bannerEl = document.getElementById('dashBanner');
      if (bannerEl) bannerEl.innerHTML = `<div class="banner info"><strong>ADB Banner</strong><code>${adb.remoteBanner}</code></div>`;
    } catch (e: unknown) {
      toast('Dashboard load failed: ' + (e as Error).message, 'err');
    }
  };

  // ---- SHELL ----
  const runShellCmd = async () => {
    if (!requireConn()) return;
    const cmd = shellInput.trim();
    if (!cmd) return;

    cmdHistoryRef.current.push(cmd);
    cmdIdxRef.current = cmdHistoryRef.current.length;

    appendTerm('$ ' + cmd, 'prompt');
    setShellInput('');

    try {
      const out = await adbRef.current.shell(cmd);
      if (out.trim()) appendTerm(out);
      else appendTerm('(no output)', 'dim');
    } catch (e: unknown) {
      appendTerm('ERROR: ' + (e as Error).message, 'err');
    }
  };

  const runPreset = async (cmd: string) => {
    setShellInput(cmd);
    cmdHistoryRef.current.push(cmd);
    cmdIdxRef.current = cmdHistoryRef.current.length;
    appendTerm('$ ' + cmd, 'prompt');
    try {
      const out = await adbRef.current.shell(cmd);
      if (out.trim()) appendTerm(out);
      else appendTerm('(no output)', 'dim');
    } catch (e: unknown) {
      appendTerm('ERROR: ' + (e as Error).message, 'err');
    }
  };

  const handleShellKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') runShellCmd();
    else if (e.key === 'ArrowUp') {
      if (cmdIdxRef.current > 0) {
        cmdIdxRef.current--;
        setShellInput(cmdHistoryRef.current[cmdIdxRef.current]);
      }
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      if (cmdIdxRef.current < cmdHistoryRef.current.length - 1) {
        cmdIdxRef.current++;
        setShellInput(cmdHistoryRef.current[cmdIdxRef.current]);
      } else {
        cmdIdxRef.current = cmdHistoryRef.current.length;
        setShellInput('');
      }
      e.preventDefault();
    }
  };

  // ---- FILES ----
  const loadDir = async (path: string) => {
    if (!requireConn()) return;
    setFilePath(path);
    const tree = document.getElementById('fileTree');
    if (!tree) return;
    tree.innerHTML = '<div class="empty">Loading...</div>';
    try {
      const out = await adbRef.current.shell(`ls -la "${path}"`);
      if (out.includes('No such file')) { tree.innerHTML = `<div class="empty">${out}</div>`; return; }
      const lines = out.split('\n').filter(l => l && !l.startsWith('total'));
      if (!lines.length) { tree.innerHTML = '<div class="empty">Empty directory</div>'; return; }
      tree.innerHTML = lines.map(line => {
        const parts = line.split(/\s+/);
        if (parts.length < 7) return '';
        const perms = parts[0];
        const size = parts[4];
        const name = parts.slice(6).join(' ');
        if (name === '.' || name === '..') return '';
        const isDir = perms.startsWith('d');
        const isLink = perms.startsWith('l');
        const cls = isDir ? 'dir' : isLink ? 'link' : '';
        const fullName = path.endsWith('/') ? path + name : path + '/' + name;
        const click = isDir
          ? `onclick="window.__loadDir('${fullName.replace(/'/g, "\\'")}')"`
          : `onclick="window.__viewFile('${fullName.replace(/'/g, "\\'")}')"`;
        return `<div class="file-row ${cls}" ${click}>
          <div class="perms">${perms}</div>
          <div>${parts[1]}</div>
          <div>${parts[2]}</div>
          <div class="size">${size}</div>
          <div>${name}</div>
        </div>`;
      }).join('');
    } catch (e: unknown) { tree.innerHTML = `<div class="empty">Error: ${(e as Error).message}</div>`; }
  };

  const viewFile = async (path: string) => {
    if (!requireConn()) return;
    try {
      const out = await adbRef.current.shell(`head -c 4096 "${path}"`);
      showModal('File: ' + path, `<pre>${out.replace(/</g, '&lt;')}</pre>`);
    } catch (e: unknown) { toast((e as Error).message, 'err'); }
  };

  // Expose for inline onclick
  useEffect(() => {
    (window as unknown as Record<string, unknown>).__loadDir = loadDir;
    (window as unknown as Record<string, unknown>).__viewFile = viewFile;
  });

  // ---- PACKAGES ----
  const loadPackages = async () => {
    if (!requireConn()) return;
    const list = document.getElementById('pkgList');
    if (!list) return;
    list.innerHTML = '<div class="empty">Loading...</div>';
    try {
      const out = await adbRef.current.shell('pm list packages -f -i -U');
      const lines = out.split('\n').filter(l => l.startsWith('package:'));
      const pkgs = lines.map(line => {
        const m = line.match(/package:(.+?)=([^=]+?)\s+(.*)$/);
        if (!m) return null;
        const path = m[1], name = m[2], extra = m[3];
        const installer = (extra.match(/installer=(\S+)/) || [])[1] || '?';
        const uid = (extra.match(/uid:(\d+)/) || [])[1] || '?';
        return { path, name, installer, uid };
      }).filter(Boolean) as { path: string; name: string; installer: string; uid: string }[];

      list.innerHTML = pkgs.map(p => {
        const isSystem = p.path.startsWith('/system') || p.path.startsWith('/product');
        return `<div class="pkg-item" data-name="${p.name}" onclick="window.__showPkg('${p.name}')">
          <div>
            <div class="pkg-name">${p.name}</div>
            <div class="pkg-ver">${p.path} · uid=${p.uid}</div>
          </div>
          <div class="pkg-flags">
            ${isSystem ? '<span class="chip warn">system</span>' : '<span class="chip info">user</span>'}
            <span class="chip">${p.installer}</span>
          </div>
        </div>`;
      }).join('');
      toast(`Loaded ${pkgs.length} packages`);
    } catch (e: unknown) { list.innerHTML = `<div class="empty">Error: ${(e as Error).message}</div>`; }
  };

  const showPkg = async (name: string) => {
    if (!requireConn()) return;
    try {
      const out = await adbRef.current.shell(`dumpsys package ${name} | head -120`);
      showModal(name, `<pre style="max-height:400px;overflow:auto">${out.replace(/</g, '&lt;')}</pre>`);
    } catch (e: unknown) { toast((e as Error).message, 'err'); }
  };

  useEffect(() => {
    (window as unknown as Record<string, unknown>).__showPkg = showPkg;
  });

  // ---- LOGCAT ----
  const startLogcat = async () => {
    if (!requireConn() || logcatRunningRef.current) return;
    logcatRunningRef.current = true;
    try {
      await adbRef.current.openShell('logcat -v brief', (data) => {
        if (!logcatRunningRef.current) return;
        const text = new TextDecoder().decode(data);
        const filter = logFilter.toLowerCase();
        text.split('\n').forEach(line => {
          if (!line.trim()) return;
          if (filter && !line.toLowerCase().includes(filter)) return;
          const m = line.match(/^([VDIWEFS])\/(.+?)\s*\(\s*\d+\):\s(.*)$/);
          if (m && logOutputRef.current) {
            const [_, level, tag, msg] = m;
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.innerHTML = `<span class="log-t">${new Date().toLocaleTimeString()}</span><span class="log-tag log-${level}">${level}</span><span style="color:var(--cyan);flex-shrink:0;max-width:150px;overflow:hidden;text-overflow:ellipsis">${tag}</span><span>${msg.replace(/</g, '&lt;')}</span>`;
            logOutputRef.current.appendChild(entry);
            if (logOutputRef.current.childElementCount > 2000 && logOutputRef.current.firstChild) logOutputRef.current.removeChild(logOutputRef.current.firstChild);
            logOutputRef.current.scrollTop = logOutputRef.current.scrollHeight;
          }
        });
      });
    } catch (e: unknown) { toast((e as Error).message, 'err'); }
    logcatRunningRef.current = false;
  };

  const stopLogcat = () => { logcatRunningRef.current = false; };

  // ---- SENSORS ----
  const drawSensorChart = () => {
    const c = sensorCanvasRef.current;
    if (!c) return;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    const w = c.width = c.offsetWidth;
    const h = c.height = 240;
    ctx.fillStyle = '#05070a'; ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = '#1e2638'; ctx.lineWidth = 1;
    for (let y = 0; y < h; y += 30) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
    ctx.strokeStyle = '#2a354d'; ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke();

    const draw = (arr: number[], color: string) => {
      if (arr.length < 2) return;
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
      const scale = 10;
      arr.forEach((v, i) => {
        const x = (i / 100) * w;
        const y = h / 2 - (v / scale) * (h / 2);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    };

    draw(sensorHistoryRef.current.x, '#ff3366');
    draw(sensorHistoryRef.current.y, '#00d8ff');
    draw(sensorHistoryRef.current.z, '#00ff9d');
  };

  const startSensors = async () => {
    if (!requireConn() || sensorRunningRef.current) return;
    sensorRunningRef.current = true;
    sensorHistoryRef.current = { x: [], y: [], z: [] };

    const vals = document.getElementById('sensorVals');
    if (vals) {
      vals.innerHTML = `
        <div class="sensor-val"><div class="n">Accel X</div><div class="v" id="sX">0.00</div></div>
        <div class="sensor-val"><div class="n">Accel Y</div><div class="v" id="sY">0.00</div></div>
        <div class="sensor-val"><div class="n">Accel Z</div><div class="v" id="sZ">0.00</div></div>
        <div class="sensor-val"><div class="n">Gyro X</div><div class="v" id="gX">0.00</div></div>
        <div class="sensor-val"><div class="n">Gyro Y</div><div class="v" id="gY">0.00</div></div>
        <div class="sensor-val"><div class="n">Gyro Z</div><div class="v" id="gZ">0.00</div></div>
      `;
    }

    let lastTick = Date.now();
    let sampleCount = 0;

    try {
      await adbRef.current.openShell('getevent -q', (data) => {
        if (!sensorRunningRef.current) return;
        const text = new TextDecoder().decode(data);
        text.split('\n').forEach(line => {
          const m = line.match(/(\d{4})\s+(\d{3})\s+([a-f0-9]+)/);
          if (!m) return;
          const type = parseInt(m[1], 16);
          const code = parseInt(m[2], 16);
          const value = parseInt(m[3], 16);

          if (type === 3) {
            const scaled = (value - 32768) / 3276.8;
            let id: string | null = null;
            if (code === 0) id = 'sX';
            else if (code === 1) id = 'sY';
            else if (code === 2) id = 'sZ';
            else if (code === 3) id = 'gX';
            else if (code === 4) id = 'gY';
            else if (code === 5) id = 'gZ';
            if (id) {
              const el = document.getElementById(id);
              if (el) el.textContent = scaled.toFixed(2);
              if (code < 3) {
                const key = (['x', 'y', 'z'] as const)[code];
                sensorHistoryRef.current[key].push(scaled);
                if (sensorHistoryRef.current.x.length > 100) {
                  sensorHistoryRef.current.x.shift();
                  sensorHistoryRef.current.y.shift();
                  sensorHistoryRef.current.z.shift();
                }
              }
            }
            sampleCount++;
            const now = Date.now();
            if (now - lastTick > 1000) {
              const hzEl = document.getElementById('sensorHz');
              if (hzEl) hzEl.textContent = sampleCount + ' samples/s';
              sampleCount = 0;
              lastTick = now;
              drawSensorChart();
            }
          }
        });
      });
    } catch (e: unknown) { toast((e as Error).message, 'err'); }
    sensorRunningRef.current = false;
  };

  // ---- THERMAL ----
  const drawThermalChart = () => {
    const c = thermalCanvasRef.current;
    if (!c) return;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    const w = c.width = c.offsetWidth;
    const h = c.height = 260;
    ctx.fillStyle = '#05070a'; ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = '#1e2638';
    for (let y = 0; y < h; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }

    const hist = thermalHistoryRef.current;
    if (hist.length < 2) return;

    const drawLine = (key: 'batt' | 'thermal' | 'freq', color: string, min: number, max: number) => {
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
      hist.forEach((pt, i) => {
        const x = (i / 60) * w;
        const y = h - ((pt[key] - min) / (max - min)) * h;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    };

    drawLine('batt', '#ffb020', 20, 60);
    drawLine('thermal', '#ff3366', 20, 60);
    drawLine('freq', '#00ff9d', 0, 3);

    ctx.fillStyle = '#ffb020'; ctx.font = '10px monospace'; ctx.fillText('● Battery', 10, 20);
    ctx.fillStyle = '#ff3366'; ctx.fillText('● Thermal', 80, 20);
    ctx.fillStyle = '#00ff9d'; ctx.fillText('● CPU GHz', 160, 20);
  };

  const startThermal = async () => {
    if (!requireConn() || thermalRunningRef.current) return;
    thermalRunningRef.current = true;
    thermalHistoryRef.current = [];

    while (thermalRunningRef.current) {
      try {
        const out = await adbRef.current.shell('dumpsys battery && cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null && cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq 2>/dev/null');
        const batt: Record<string, string> = {};
        out.split('\n').forEach(l => { const m = l.match(/(\w+):\s*(.+)/); if (m) batt[m[1]] = m[2]; });

        const temps: number[] = [];
        const tempsMatches = out.matchAll(/(\d{5,7})\n/g);
        for (const m of tempsMatches) {
          const t = parseInt(m[1]);
          if (t > 1000 && t < 100000) temps.push(t / 1000);
        }

        const freqs: number[] = [];
        const freqMatches = out.matchAll(/(\d{6,8})/g);
        for (const m of freqMatches) {
          const f = parseInt(m[1]);
          if (f > 100000) freqs.push(f);
        }

        const battTemp = parseFloat(batt.temperature || '0') / 10;
        const maxThermal = temps.length ? Math.max(...temps) : battTemp;
        const maxFreq = freqs.length ? Math.max(...freqs) : 0;

        thermalHistoryRef.current.push({ time: Date.now(), batt: battTemp, thermal: maxThermal, freq: maxFreq / 1000 });
        if (thermalHistoryRef.current.length > 60) thermalHistoryRef.current.shift();

        const statsEl = document.getElementById('thermalStats');
        if (statsEl) {
          statsEl.innerHTML = `
            <div class="card"><div class="stat-label">Battery Temp</div><div class="stat-big" style="color:${battTemp > 40 ? 'var(--red)' : battTemp > 35 ? 'var(--yellow)' : 'var(--green)'}">${battTemp.toFixed(1)}°C</div></div>
            <div class="card"><div class="stat-label">Max Thermal Zone</div><div class="stat-big" style="color:${maxThermal > 50 ? 'var(--red)' : maxThermal > 40 ? 'var(--yellow)' : 'var(--green)'}">${maxThermal.toFixed(1)}°C</div></div>
            <div class="card"><div class="stat-label">Max CPU Freq</div><div class="stat-big">${(maxFreq / 1000).toFixed(2)}GHz</div></div>
          `;
        }

        drawThermalChart();
      } catch (e: unknown) { toast((e as Error).message, 'err'); break; }
      await new Promise(r => setTimeout(r, 1000));
    }
  };

  // ---- BATTERY ----
  const loadBattery = async () => {
    if (!requireConn()) return;
    try {
      const out = await adbRef.current.shell('dumpsys batterystats --checkin | tail -5 && echo === && dumpsys battery && echo === && cat /sys/class/power_supply/battery/charge_full 2>/dev/null && cat /sys/class/power_supply/battery/charge_full_design 2>/dev/null');
      const dumpEl = document.getElementById('battDump');
      if (dumpEl) dumpEl.textContent = out;

      const batt: Record<string, string> = {};
      out.split('\n').forEach(l => { const m = l.match(/^(\w+):\s*(.+)/); if (m) batt[m[1]] = m[2]; });

      const full = parseInt(batt.charge_full) || 0;
      const design = parseInt(batt.charge_full_design) || 0;
      const health = design > 0 ? ((full / design) * 100).toFixed(1) : '?';

      const statsEl = document.getElementById('battStats');
      if (statsEl) {
        statsEl.innerHTML = `
          <div class="card"><div class="stat-label">Level</div><div class="stat-big">${batt.level || '?'}%</div><div class="stat-sub">${batt.status || ''}</div></div>
          <div class="card"><div class="stat-label">Voltage</div><div class="stat-big">${batt.voltage ? (parseInt(batt.voltage) / 1000).toFixed(2) + 'V' : '?'}</div></div>
          <div class="card"><div class="stat-label">Temperature</div><div class="stat-big">${batt.temperature ? (parseInt(batt.temperature) / 10).toFixed(1) + '°C' : '?'}</div></div>
          <div class="card"><div class="stat-label">Health (wear)</div><div class="stat-big" style="color:${parseFloat(health) < 80 ? 'var(--red)' : parseFloat(health) < 90 ? 'var(--yellow)' : 'var(--green)'}">${health}%</div><div class="stat-sub">${full / 1000 | 0}mAh / ${design / 1000 | 0}mAh design</div></div>
        `;
      }
    } catch (e: unknown) { toast((e as Error).message, 'err'); }
  };

  // ---- WAKE LOCKS ----
  const loadWakelocks = async () => {
    if (!requireConn()) return;
    try {
      const out = await adbRef.current.shell('dumpsys power | grep -i wakelock');
      const list = document.getElementById('wakeList');
      if (!list) return;
      const lines = out.split('\n').filter(l => l.trim());
      if (!lines.length) { list.innerHTML = '<div class="empty">No active wake locks</div>'; return; }
      list.innerHTML = lines.map(l => `<div class="log-entry"><span style="color:var(--green)">${l.trim().replace(/</g, '&lt;')}</span></div>`).join('');
    } catch (e: unknown) { toast((e as Error).message, 'err'); }
  };

  // ---- SECURITY ----
  const loadSecurity = async () => {
    if (!requireConn()) return;
    try {
      const [settings, , props] = await Promise.all([
        adbRef.current.shell('settings get global adb_enabled && settings get secure install_non_market_apps && settings get global wifi_on && settings get secure lockscreen.password_type'),
        adbRef.current.shell('pm list packages | wc -l && pm list permission-groups'),
        adbRef.current.shell('getprop ro.build.tags && getprop ro.debuggable && getprop ro.secure')
      ]);

      const propsLines = props.split('\n');
      const testBuild = propsLines[0]?.trim();
      const debuggable = propsLines[1]?.trim();
      const secure = propsLines[2]?.trim();

      const accessEl = document.getElementById('secAccess');
      if (accessEl) {
        accessEl.innerHTML =
          kvRow('ADB Enabled', settings.includes('1') ? '<span class="ok">✓ YES</span>' : '<span class="err">NO</span>') +
          kvRow('USB Debugging', isConnected ? '<span class="ok">✓ ACTIVE NOW</span>' : 'inactive') +
          kvRow('Auth State', adbRef.current.authenticated ? '<span class="ok">✓ RSA VERIFIED</span>' : '<span class="err">PENDING</span>') +
          kvRow('Known Computer', localStorage.getItem('adb-keys') ? '<span class="ok">✓ KEYS STORED</span>' : 'new device') +
          kvRow('Banner', adbRef.current.remoteBanner?.split(':')[0] || '?');
      }

      const integrityEl = document.getElementById('secIntegrity');
      if (integrityEl) {
        integrityEl.innerHTML =
          kvRow('Build Tags', `<span class="${testBuild?.includes('test-keys') ? 'err' : 'ok'}">${testBuild || '?'}</span>`) +
          kvRow('Root indicator', testBuild?.includes('test-keys') ? '<span class="err">⚠ TEST KEYS (likely rooted)</span>' : '<span class="ok">✓ Release keys</span>') +
          kvRow('Debuggable', debuggable === '1' ? '<span class="err">⚠ YES</span>' : '<span class="ok">✓ NO</span>') +
          kvRow('Secure Mode', secure === '1' ? '<span class="ok">✓ YES</span>' : '<span class="warn">NO</span>') +
          kvRow('Unknown Sources', settings.split('\n')[1] === '1' ? '<span class="warn">⚠ ENABLED</span>' : '<span class="ok">✓ Disabled</span>');
      }
    } catch (e: unknown) { toast((e as Error).message, 'err'); }
  };

  const sendLockInput = async () => {
    if (!requireConn()) return;
    if (!lockInput) { toast('Enter test input', 'warn'); return; }
    showModal('Lockscreen Test — Single Shot Only', `
      <p>This sends ONE input event to the device. It is NOT a brute-forcer — Android rate-limits lockscreen attempts and will lock/wipe the device.</p>
      <p>Sending: <code>${lockInput}</code></p>
      <pre>input text "${lockInput}"
input keyevent 66  # ENTER</pre>
      <p>This only works if the screen is ON and showing the lockscreen.</p>
    `);
    try {
      await adbRef.current.shell(`input text "${lockInput.replace(/"/g, '\\"')}"`);
      await adbRef.current.shell('input keyevent 66');
      toast('Input sent — check device screen');
    } catch (e: unknown) { toast((e as Error).message, 'err'); }
  };

  // ---- USB INSPECTOR ----
  const renderUSB = () => {
    const d = adbRef.current.device;
    if (!d) return;
    const cfg = d.configuration;
    if (!cfg) return;
    const rows = kvRow('Vendor ID', `0x${d.vendorId.toString(16).padStart(4, '0')}`) +
      kvRow('Product ID', `0x${d.productId.toString(16).padStart(4, '0')}`) +
      kvRow('Manufacturer', d.manufacturerName || '?') +
      kvRow('Product', d.productName || '?') +
      kvRow('Serial', d.serialNumber || '?') +
      kvRow('USB Version', `${d.usbVersionMajor}.${d.usbVersionMinor}`) +
      kvRow('Device Class', `0x${d.deviceClass.toString(16)}`);

    let ifaces = '';
    cfg.interfaces.forEach((iface, i) => {
      iface.alternates.forEach((alt, a) => {
        ifaces += `<div style="margin:8px 0;padding:8px;background:var(--bg-0);border-radius:4px"><strong style="color:var(--cyan)">Interface ${i} alt ${a}</strong> · class 0x${alt.interfaceClass.toString(16)} · ${alt.endpoints.length} endpoints`;
        alt.endpoints.forEach(ep => {
          ifaces += `<div style="padding:4px 0 4px 16px;font-size:11px">EP 0x${ep.endpointNumber.toString(16)} ${ep.direction} ${ep.type} · ${ep.packetSize}B</div>`;
        });
        ifaces += '</div>';
      });
    });

    const el = document.getElementById('usbDesc');
    if (el) el.innerHTML = rows + `<div style="grid-column:1/-1;margin-top:8px">${ifaces}</div>`;
  };

  // Initial toast
  useEffect(() => {
    toast('ADBDirect ready. Connect an Android device.', 'warn');
    appendTerm('ADBDirect shell ready. Type a command or click a preset.', 'info');
    appendTerm('Note: Connect a device via USB with USB Debugging enabled, then tap Connect.', 'dim');
  }, []);

  // Handle nav click for security/battery auto-load
  const handleNavClick = (view: string) => {
    setActiveView(view);
    if (view === 'security' && isConnected) loadSecurity();
    if (view === 'battery' && isConnected) loadBattery();
    if (view === 'usb' && isConnected) renderUSB();
  };

  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <div className="logo-box">A</div>
          ADBDirect <span style={{ color: 'var(--dim)', fontSize: '11px', fontWeight: 400 }}>· WebUSB Android Console</span>
        </div>
        <div className="header-actions">
          <div className={`conn-status ${connStatus.cls}`}>● {connStatus.text}</div>
          <button className="btn primary" onClick={handleConnect} disabled={isConnected}>⚡ Connect Device</button>
          <button className="btn" onClick={handleDisconnect} disabled={!isConnected}>Disconnect</button>
        </div>
      </header>

      <div className="workspace">
        <aside className="sidebar">
          <div className="sidebar-header">Navigation</div>
          <nav className="nav">
            <div className="nav-cat">Overview</div>
            {[
              ['dashboard', '📊', 'Dashboard'],
              ['shell', '▶', 'Shell Console'],
              ['files', '📁', 'File Explorer'],
              ['packages', '📦', 'Packages'],
              ['logcat', '📜', 'Logcat'],
            ].map(([view, icon, label]) => (
              <div key={view} className={`nav-item ${activeView === view ? 'active' : ''}`} onClick={() => handleNavClick(view)}>
                <span className="ic">{icon}</span> {label}
              </div>
            ))}
            <div className="nav-sep"></div>
            <div className="nav-cat">Experimental</div>
            {[
              ['sensors', '📡', 'Live Sensors'],
              ['thermal', '🌡', 'Thermal Monitor'],
              ['battery', '🔋', 'Battery Deep'],
              ['wakelock', '🔒', 'Wake Locks'],
            ].map(([view, icon, label]) => (
              <div key={view} className={`nav-item ${activeView === view ? 'active' : ''}`} onClick={() => handleNavClick(view)}>
                <span className="ic">{icon}</span> {label}
              </div>
            ))}
            <div className="nav-sep"></div>
            <div className="nav-cat">Security</div>
            {[
              ['security', '🛡', 'Security Audit'],
              ['protocol', '🔬', 'Protocol Debug'],
              ['usb', '🔌', 'USB Inspector'],
            ].map(([view, icon, label]) => (
              <div key={view} className={`nav-item ${activeView === view ? 'active' : ''}`} onClick={() => handleNavClick(view)}>
                <span className="ic">{icon}</span> {label}
              </div>
            ))}
          </nav>
        </aside>

        <main className="content">
          {/* DASHBOARD */}
          <section className={`view ${activeView === 'dashboard' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">📊 Device Dashboard</div>
              <div className="view-sub">{'// Real-time device telemetry'}</div>
            </div>
            <div id="dashBanner"></div>
            <div className="grid grid-4" id="dashStats"></div>
            <div className="grid grid-2" style={{ marginTop: 14 }}>
              <div className="card">
                <div className="card-head"><div className="card-title"><span className="dot"></span>System Identity</div></div>
                <div className="kv" id="kvIdentity"></div>
              </div>
              <div className="card">
                <div className="card-head"><div className="card-title"><span className="dot"></span>Hardware</div></div>
                <div className="kv" id="kvHardware"></div>
              </div>
              <div className="card">
                <div className="card-head"><div className="card-title"><span className="dot"></span>Build Info</div></div>
                <div className="kv" id="kvBuild"></div>
              </div>
              <div className="card">
                <div className="card-head"><div className="card-title"><span className="dot"></span>Display</div></div>
                <div className="kv" id="kvDisplay"></div>
              </div>
            </div>
          </section>

          {/* SHELL */}
          <section className={`view ${activeView === 'shell' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">▶ Interactive Shell</div>
              <div className="view-sub">{'// adb shell · full command history · arrow keys'}</div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>Command Presets</div>
              <div className="presets">
                {SHELL_PRESETS.map(([label, cmd]) => (
                  <button key={cmd} className="btn" onClick={() => runPreset(cmd)}>{label}</button>
                ))}
              </div>
              <div className="terminal" ref={shellTermRef}></div>
              <div className="cmd-bar">
                <input type="text" value={shellInput} onChange={e => setShellInput(e.target.value)} onKeyDown={handleShellKey} placeholder="Enter shell command..." autoComplete="off" spellCheck={false} />
                <button className="btn primary" onClick={runShellCmd}>Run</button>
                <button className="btn" onClick={() => { if (shellTermRef.current) shellTermRef.current.innerHTML = ''; }}>Clear</button>
              </div>
            </div>
          </section>

          {/* FILES */}
          <section className={`view ${activeView === 'files' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">📁 File Explorer</div>
              <div className="view-sub">{'// Browse device filesystem'}</div>
            </div>
            <div className="card">
              <div className="cmd-bar" style={{ marginBottom: 10, marginTop: 0 }}>
                <input type="text" value={filePath} onChange={e => setFilePath(e.target.value)} placeholder="/path/to/dir" />
                <button className="btn primary" onClick={() => loadDir(filePath)}>Go</button>
                <button className="btn" onClick={() => {
                  const parent = filePath.substring(0, filePath.lastIndexOf('/')) || '/';
                  setFilePath(parent);
                  loadDir(parent);
                }}>⬆ Up</button>
              </div>
              <div className="file-tree" id="fileTree"><div className="empty">Enter a path and click Go</div></div>
            </div>
          </section>

          {/* PACKAGES */}
          <section className={`view ${activeView === 'packages' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">📦 Installed Packages</div>
              <div className="view-sub">{'// All apps, versions, and install locations'}</div>
            </div>
            <div className="card">
              <input type="text" className="search-box" value={pkgSearch} onChange={e => {
                setPkgSearch(e.target.value);
                const q = e.target.value.toLowerCase();
                document.querySelectorAll('.pkg-item').forEach(item => {
                  (item as HTMLElement).style.display = (item as HTMLElement).dataset.name?.toLowerCase().includes(q) ? '' : 'none';
                });
              }} placeholder="Filter packages..." />
              <div className="pkg-list" id="pkgList"><div className="empty">Click to load</div></div>
              <div style={{ marginTop: 10 }}><button className="btn primary" onClick={loadPackages}>🔄 Refresh List</button></div>
            </div>
          </section>

          {/* LOGCAT */}
          <section className={`view ${activeView === 'logcat' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">📜 Live Logcat</div>
              <div className="view-sub">{'// Real-time system logs'}</div>
            </div>
            <div className="card">
              <div className="cmd-bar" style={{ marginBottom: 10, marginTop: 0 }}>
                <input type="text" value={logFilter} onChange={e => setLogFilter(e.target.value)} placeholder="Filter by tag or text..." />
                <button className="btn primary" onClick={startLogcat}>▶ Start</button>
                <button className="btn danger" onClick={stopLogcat}>■ Stop</button>
                <button className="btn" onClick={() => { if (logOutputRef.current) logOutputRef.current.innerHTML = ''; }}>Clear</button>
              </div>
              <div ref={logOutputRef} style={{ background: '#000', border: '1px solid var(--border)', borderRadius: 6, padding: 10, height: 420, overflowY: 'auto', fontFamily: 'var(--mono)', fontSize: 11 }}></div>
            </div>
          </section>

          {/* SENSORS */}
          <section className={`view ${activeView === 'sensors' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">📡 Live Sensor Stream</div>
              <div className="view-sub">{'// Accelerometer · Gyroscope · Magnetometer · 10Hz sampling'}</div>
            </div>
            <div className="grid grid-2">
              <div className="card">
                <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>Live Values</div>
                <div className="sensor-grid" id="sensorVals"></div>
              </div>
              <div className="card">
                <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>Acceleration (m/s²)</div>
                <canvas ref={sensorCanvasRef} height={240}></canvas>
              </div>
              <div className="card" style={{ gridColumn: '1/-1' }}>
                <div className="cmd-bar" style={{ marginTop: 0 }}>
                  <button className="btn primary" onClick={startSensors}>▶ Start Stream</button>
                  <button className="btn danger" onClick={() => { sensorRunningRef.current = false; }}>■ Stop</button>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--dim)', marginLeft: 'auto' }} id="sensorHz">0 samples/s</span>
                </div>
              </div>
            </div>
          </section>

          {/* THERMAL */}
          <section className={`view ${activeView === 'thermal' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">🌡 Thermal & Throttle Monitor</div>
              <div className="view-sub">{'// CPU temp, GPU temp, battery temp, CPU frequency over time'}</div>
            </div>
            <div className="grid grid-3" id="thermalStats"></div>
            <div className="card" style={{ marginTop: 14 }}>
              <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>Temperature History (60s)</div>
              <canvas ref={thermalCanvasRef} height={260}></canvas>
            </div>
            <div className="card" style={{ marginTop: 14 }}>
              <div className="cmd-bar" style={{ marginTop: 0 }}>
                <button className="btn primary" onClick={startThermal}>▶ Start Monitor</button>
                <button className="btn danger" onClick={() => { thermalRunningRef.current = false; }}>■ Stop</button>
              </div>
            </div>
          </section>

          {/* BATTERY */}
          <section className={`view ${activeView === 'battery' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">🔋 Battery Deep Dive</div>
              <div className="view-sub">{'// Health, wear, voltage curve, temperature'}</div>
            </div>
            <div className="grid grid-3" id="battStats"></div>
            <div className="card" style={{ marginTop: 14 }}>
              <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>Full Dump</div>
              <pre id="battDump" style={{ background: 'var(--bg-0)', padding: 12, borderRadius: 4, fontFamily: 'var(--mono)', fontSize: 11, overflow: 'auto', maxHeight: 400, color: 'var(--green)' }}>Run dumpsys battery to see details</pre>
              <div style={{ marginTop: 10 }}><button className="btn primary" onClick={loadBattery}>🔄 Refresh</button></div>
            </div>
          </section>

          {/* WAKE LOCKS */}
          <section className={`view ${activeView === 'wakelock' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">🔒 Wake Lock Analyzer</div>
              <div className="view-sub">{'// What\'s keeping your device awake'}</div>
            </div>
            <div className="card">
              <div id="wakeList"><div className="empty">Click to scan</div></div>
              <div style={{ marginTop: 10 }}><button className="btn primary" onClick={loadWakelocks}>🔄 Scan Wake Locks</button></div>
            </div>
          </section>

          {/* SECURITY */}
          <section className={`view ${activeView === 'security' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">🛡 Security Audit</div>
              <div className="view-sub">{'// Posture assessment · not a bypass tool'}</div>
            </div>
            <div className="banner warn">
              <strong>⚠ Why this is an audit, not a bypass tool</strong>
              ADB requires the device owner to authorize the connection via the on-screen prompt. There is no "PIN brute force" attack surface — the ADB protocol itself is the lock, not the PIN. Android's lockscreen also has exponential rate limiting (30s, 5m, 30m, wipe) that makes brute-force mathematically impractical. This tab shows what's <em>actually</em> exposed.
            </div>
            <div className="grid grid-2">
              <div className="card">
                <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>Access Controls</div>
                <div className="kv" id="secAccess"></div>
              </div>
              <div className="card">
                <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>System Integrity</div>
                <div className="kv" id="secIntegrity"></div>
              </div>
              <div className="card">
                <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>Dangerous Permissions</div>
                <div id="secPerms" style={{ maxHeight: 260, overflowY: 'auto' }}></div>
              </div>
              <div className="card">
                <div className="card-title" style={{ marginBottom: 10 }}><span className="dot"></span>Lockscreen Test (single input)</div>
                <p style={{ fontSize: 11, color: 'var(--dim)', marginBottom: 8 }}>Send ONE test input to the lockscreen (no looping — Android will lock you out). Only works if screen is on and showing lockscreen.</p>
                <div className="cmd-bar" style={{ marginTop: 0 }}>
                  <input type="text" value={lockInput} onChange={e => setLockInput(e.target.value)} placeholder="Test PIN/text" maxLength={32} />
                  <button className="btn warn" onClick={sendLockInput}>Send Once</button>
                </div>
              </div>
            </div>
          </section>

          {/* PROTOCOL */}
          <section className={`view ${activeView === 'protocol' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">🔬 ADB Protocol Debugger</div>
              <div className="view-sub">{'// Raw message frames · CNXN · AUTH · OPEN · WRTE · OKAY · CLSE'}</div>
            </div>
            <div className="card">
              <div className="cmd-bar" style={{ marginTop: 0, marginBottom: 10 }}>
                <button className="btn" onClick={() => { if (pktListRef.current) pktListRef.current.innerHTML = ''; }}>Clear</button>
              </div>
              <div ref={pktListRef} style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', borderRadius: 6, padding: 8, maxHeight: 500, overflowY: 'auto', fontFamily: 'var(--mono)' }}></div>
            </div>
          </section>

          {/* USB */}
          <section className={`view ${activeView === 'usb' ? 'active' : ''}`}>
            <div className="view-head">
              <div className="view-title">🔌 USB Endpoint Inspector</div>
              <div className="view-sub">{'// Raw device descriptors and endpoints'}</div>
            </div>
            <div className="card">
              <div className="kv" id="usbDesc"><div className="empty">Connect a device to see USB info</div></div>
            </div>
          </section>
        </main>
      </div>

      {/* TOAST */}
      <div className={`toast ${toastMsg.show ? 'show' : ''} ${toastMsg.cls}`}>{toastMsg.text}</div>

      {/* MODAL */}
      <div className={`modal-bg ${modal.show ? 'show' : ''}`} onClick={() => setModal({ show: false, title: '', body: '' })}>
        <div className="modal" onClick={e => e.stopPropagation()}>
          <h3>{modal.title}</h3>
          <div dangerouslySetInnerHTML={{ __html: modal.body }}></div>
          <div className="modal-actions">
            <button className="btn" onClick={() => setModal({ show: false, title: '', body: '' })}>Close</button>
          </div>
        </div>
      </div>
    </div>
  );
}
