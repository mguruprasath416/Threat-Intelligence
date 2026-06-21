// ============================================================
// pages/Login.jsx — DYNAMIC LANDING PAGE & ACCESS PLATFORM
// ============================================================
// Features:
//   - Live threat-feed ticker
//   - Dynamic activity IOC stream
//   - Interactive SVG global threat origin map
//   - Passwordless email OTP authentication flow (SSO removed)
// ============================================================

import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import api from '../api/axios';
import './Login.css';

// ─── Live ticker data ─────────────────────────────────────────────────────────
const TICKER_EVENTS = [
  { sev: "critical", msg: "New C2 server detected · 185.220.101.47" },
  { sev: "high",     msg: "Phishing domain registered · secure-login-portal[.]net" },
  { sev: "medium",   msg: "Hash match on VirusTotal · d41d8cd98f00b204e9800998ecf8427e" },
  { sev: "high",     msg: "APT29 IOC cluster updated · 14 new indicators" },
  { sev: "low",      msg: "Feed sync complete · abuse.ch · 2,341 entries" },
  { sev: "critical", msg: "Ransomware dropper URL · hxxp://malware-drop[.]ru/payload.exe" },
  { sev: "medium",   msg: "Suspicious ASN block · AS197695 flagged" },
  { sev: "high",     msg: "Domain reputation drop · analytics-cdn[.]io → malicious" },
  { sev: "low",      msg: "ThreatFox feed refreshed · 891 new IOCs ingested" },
  { sev: "critical", msg: "Zero-day exploit IOC · CVE-2024-3400 payload hash matched" },
];

// ─── Dynamic activity data ────────────────────────────────────────────────────
const ACTIVITY_POOL = [
  { type:"IP",     value:"185.220.101.47",           sev:"critical", source:"abuse.ch",    action:"Blocked",  country:"RU" },
  { type:"Domain", value:"secure-login-portal[.]net", sev:"high",    source:"OpenPhish",   action:"Flagged",  country:"CN" },
  { type:"Hash",   value:"d41d8cd9…ecf8427e",         sev:"medium",  source:"VirusTotal",  action:"Matched",  country:"--" },
  { type:"URL",    value:"hxxp://malware-drop[.]ru/…",sev:"critical",source:"URLhaus",     action:"Blocked",  country:"RU" },
  { type:"IP",     value:"91.108.4.200",              sev:"high",    source:"OTX",         action:"Flagged",  country:"IR" },
  { type:"Domain", value:"cdn-analytics-js[.]com",   sev:"high",    source:"ThreatFox",   action:"Enriched", country:"US" },
  { type:"Hash",   value:"5f4dcc3b…d8a329c0",        sev:"critical",source:"VirusTotal",  action:"Matched",  country:"--" },
  { type:"IP",     value:"45.142.212.100",            sev:"medium",  source:"abuse.ch",    action:"Enriched", country:"NL" },
  { type:"URL",    value:"hxxps://phish-kit[.]xyz/…",sev:"critical",source:"OpenPhish",   action:"Blocked",  country:"UA" },
  { type:"Domain", value:"update-microsoft[.]ru",    sev:"high",    source:"URLhaus",     action:"Flagged",  country:"RU" },
];

const THREAT_ACTORS = [
  { name:"APT29", aka:"Cozy Bear",  region:"RU", active: true,  iocs:341, campaigns:12 },
  { name:"APT41", aka:"Double Dragon",region:"CN",active:true,  iocs:218, campaigns:8  },
  { name:"Lazarus",aka:"Hidden Cobra",region:"KP",active:true, iocs:503, campaigns:21 },
  { name:"FIN7",  aka:"Carbanak",   region:"UA", active:false,  iocs:127, campaigns:5  },
];

const GEO_DOTS = [
  { x:73,  y:38,  label:"Moscow · 847 IOCs",   sev:"critical" },
  { x:82,  y:42,  label:"Beijing · 612 IOCs",  sev:"high"     },
  { x:30,  y:36,  label:"New York · 234 IOCs", sev:"medium"   },
  { x:51,  y:34,  label:"Frankfurt · 189 IOCs",sev:"medium"   },
  { x:85,  y:55,  label:"Seoul · 95 IOCs",     sev:"high"     },
  { x:68,  y:42,  label:"Tehran · 421 IOCs",   sev:"critical" },
  { x:55,  y:28,  label:"London · 143 IOCs",   sev:"low"      },
  { x:78,  y:48,  label:"Mumbai · 76 IOCs",    sev:"low"      },
];

const FEATURES = [
  { icon: "🛡️", name: "IOC Management",       desc: "Ingest, tag, enrich, and query indicators across IP, domain, hash, and URL types with full lifecycle tracking." },
  { icon: "🔗", name: "MITRE ATT&CK mapping", desc: "Every IOC and threat auto-tagged to ATT&CK techniques. Visualise kill-chain coverage and detect gaps instantly." },
  { icon: "📡", name: "Live threat feeds",    desc: "Continuous ingestion from abuse.ch, VirusTotal, OTX, OpenPhish, URLhaus and more — refreshed every 5 minutes." },
  { icon: "🎯", name: "Threat actor profiles",desc: "Track APT groups, link campaigns to IOCs, and build attribution timelines with confidence scoring." },
  { icon: "⚡", name: "Real-time alerting",   desc: "WebSocket-powered watchlists push instant alerts when new IOCs match your defined patterns." },
  { icon: "📊", name: "Threat reports",       desc: "Generate branded PDF reports with executive summaries, severity breakdowns, and full IOC tables." },
];

// ─── OTP Auth flow ────────────────────────────────────────────────────────────
function AuthCard() {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [step, setStep]           = useState("email"); // email | otp | success
  const [email, setEmail]         = useState("");
  const [otp, setOtp]             = useState(["","","","","",""]);
  const [loading, setLoading]     = useState(false);
  const [countdown, setCountdown] = useState(0);
  const [error, setError]         = useState("");
  const otpRefs = useRef([]);

  // countdown timer
  useEffect(() => {
    if (countdown <= 0) return;
    const t = setTimeout(() => setCountdown(c => c - 1), 1000);
    return () => clearTimeout(t);
  }, [countdown]);

  const handleSendOTP = async (e) => {
    e?.preventDefault();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError("Enter a valid email address."); return;
    }
    setError(""); setLoading(true);
    try {
      await api.post('/auth/send-otp', { email: email.trim() });
      setStep("otp");
      setCountdown(60);
      // Focus first OTP digit
      setTimeout(() => otpRefs.current[0]?.focus(), 100);
    } catch (err) {
      setError(err.userMessage || 'Failed to send code. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpChange = (idx, val) => {
    if (!/^\d?$/.test(val)) return;
    const next = [...otp];
    next[idx] = val;
    setOtp(next);
    setError("");

    // Auto-advance
    if (val && idx < 5) {
      otpRefs.current[idx + 1]?.focus();
    }
    // Auto-submit when all 6 digits are filled
    if (val && idx === 5) {
      const full = [...next.slice(0, 5), val].join('');
      if (full.length === 6) {
        handleVerify(null, full);
      }
    }
  };

  const handleOtpKey = (idx, e) => {
    if (e.key === "Backspace" && !otp[idx] && idx > 0) {
      const next = [...otp];
      next[idx - 1] = '';
      setOtp(next);
      otpRefs.current[idx - 1]?.focus();
    }
    if (e.key === "ArrowLeft"  && idx > 0) otpRefs.current[idx - 1]?.focus();
    if (e.key === "ArrowRight" && idx < 5) otpRefs.current[idx + 1]?.focus();
  };

  const handleOtpPaste = (e) => {
    e.preventDefault();
    const text = e.clipboardData.getData("text").replace(/\D/g,"").slice(0,6);
    if (text.length === 6) {
      setOtp(text.split(""));
      otpRefs.current[5]?.focus();
      handleVerify(null, text);
    }
  };

  const handleVerify = async (e, codeOverride) => {
    e?.preventDefault();
    const code = codeOverride ?? otp.join("");
    if (code.length < 6) { setError("Enter all 6 digits."); return; }

    setError(""); setLoading(true);
    try {
      const response = await api.post('/auth/verify-otp', { email: email.trim(), otp: code });
      const { token, user } = response.data;

      setStep("success");
      setTimeout(() => {
        login(user, token);
        navigate('/dashboard', { replace: true });
      }, 1500);
    } catch (err) {
      setError(err.userMessage || 'Invalid or expired code. Please try again.');
      setOtp(["","","","","",""]);
      otpRefs.current[0]?.focus();
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setOtp(["","","","","",""]);
    setError("");
    setLoading(true);
    try {
      await api.post('/auth/send-otp', { email: email.trim() });
      setCountdown(60);
      otpRefs.current[0]?.focus();
    } catch (err) {
      setError(err.userMessage || 'Failed to send code. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (step === "success") return (
    <div className="auth-card">
      <div className="success-state">
        <div className="success-icon">✓</div>
        <h3 style={{fontSize:"1.1rem",fontWeight:600,marginBottom:".5rem"}}>Access granted</h3>
        <p style={{fontSize:".82rem",color:"var(--ash)",lineHeight:1.6,marginBottom:"1.5rem"}}>
          Identity verified. Redirecting you to your threat dashboard…
        </p>
        <div style={{
          fontFamily:"'JetBrains Mono',monospace",
          fontSize:".7rem",color:"var(--teal)",
          background:"rgba(0,212,180,.06)",
          border:"1px solid rgba(0,212,180,.15)",
          borderRadius:6,padding:".6rem 1rem",textAlign:"left"
        }}>
          <span style={{color:"var(--dim)"}}>$ </span>Loading threat intelligence context…<br/>
          <span style={{color:"var(--dim)"}}>$ </span>Syncing IOC feeds…<br/>
          <span style={{color:"var(--dim)"}}>$ </span><span style={{animation:"pulse 1s infinite"}}>▋</span>
        </div>
      </div>
    </div>
  );

  return (
    <div className="auth-card">
      <h2 className="auth-title">
        {step === "email" ? "Analyst access" : "Verify your identity"}
      </h2>
      <p className="auth-sub">
        {step === "email"
          ? "Enter your work email. We'll send a one-time code — no passwords stored."
          : `6-digit code sent to ${email}. Check your inbox.`}
      </p>

      {error && (
        <div style={{
          background:"rgba(255,59,92,.08)",border:"1px solid rgba(255,59,92,.25)",
          borderRadius:6,padding:".5rem .75rem",marginBottom:"1rem",
          fontSize:".78rem",color:"var(--red)",
          fontFamily:"'JetBrains Mono',monospace"
        }}>⚠ {error}</div>
      )}

      {step === "email" ? (
        <form onSubmit={handleSendOTP}>
          <div className="input-group">
            <label className="input-label">WORK EMAIL</label>
            <input
              className="input-field"
              type="email"
              placeholder="analyst@company.com"
              value={email}
              onChange={e => { setEmail(e.target.value); setError(""); }}
              autoFocus
              disabled={loading}
            />
          </div>
          <button className="btn-primary" type="submit" disabled={loading || !email.trim()}>
            {loading ? "Sending code…" : "Send access code →"}
          </button>
          <div className="trust-badges">
            <div className="trust-badge"><span>✓</span> No password</div>
            <div className="trust-badge"><span>✓</span> OTP expires in 10 min</div>
            <div className="trust-badge"><span>✓</span> TLS encrypted</div>
          </div>
        </form>
      ) : (
        <form onSubmit={handleVerify}>
          <div className="otp-grid" onPaste={handleOtpPaste}>
            {otp.map((d, i) => (
              <input
                key={i}
                ref={el => otpRefs.current[i] = el}
                className="otp-box"
                type="text" inputMode="numeric"
                maxLength={1} value={d}
                onChange={e => handleOtpChange(i, e.target.value)}
                onKeyDown={e => handleOtpKey(i, e)}
                autoFocus={i === 0}
                disabled={loading}
              />
            ))}
          </div>

          <div className="resend-row">
            <span className="resend-text">Didn't get it?</span>
            {countdown > 0
              ? <span className="countdown">Resend in {countdown}s</span>
              : <button className="resend-btn" type="button" onClick={handleResend} disabled={loading}>Resend code</button>
            }
          </div>

          <button className="btn-primary" type="submit"
            disabled={loading || otp.join("").length < 6}>
            {loading ? "Verifying…" : "Verify & enter →"}
          </button>
          <button className="btn-ghost" type="button" disabled={loading} onClick={() => { setStep("email"); setOtp(["","","","","",""]); setError(""); }}>
            ← Use different email
          </button>
        </form>
      )}
    </div>
  );
}

// ─── Live ticker ──────────────────────────────────────────────────────────────
function TerminalTicker() {
  const [lines, setLines] = useState([]);
  const [idx, setIdx]     = useState(0);

  useEffect(() => {
    const t = setInterval(() => {
      const now = new Date();
      const time = now.toTimeString().slice(0,8);
      setLines(prev => [...prev.slice(-4), { ...TICKER_EVENTS[idx % TICKER_EVENTS.length], time }]);
      setIdx(i => i + 1);
    }, 1800);
    return () => clearInterval(t);
  }, [idx]);

  return (
    <div className="ticker-wrap">
      <div className="ticker-header">
        <div className="ticker-dot" style={{background:"#FF5F57"}}/>
        <div className="ticker-dot" style={{background:"#FFBD2E"}}/>
        <div className="ticker-dot" style={{background:"#28C840"}}/>
        <span style={{marginLeft:4}}>threat-feed · live</span>
      </div>
      <div className="ticker-body">
        {lines.length === 0 && (
          <div className="ticker-line">
            <span className="tl-time">--:--:--</span>
            <span className="tl-sev-low">[ INFO ]</span>
            <span className="tl-msg">Connecting to threat intelligence streams…</span>
          </div>
        )}
        {lines.map((l, i) => (
          <div className="ticker-line" key={i}>
            <span className="tl-time">{l.time}</span>
            <span className={`tl-sev-${l.sev}`}>[{l.sev.toUpperCase().padEnd(8)}]</span>
            <span className="tl-msg">{l.msg}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Live IOC Stream ─────────────────────────────────────────────────────────
function LiveStream() {
  const [rows, setRows] = useState(() =>
    ACTIVITY_POOL.slice(0, 5).map((r, i) => {
      const d = new Date(); d.setMinutes(d.getMinutes() - i * 2);
      return { ...r, id: i, time: d.toTimeString().slice(0,8) };
    })
  );
  const [nextId, setNextId] = useState(10);

  useEffect(() => {
    const t = setInterval(() => {
      const now = new Date().toTimeString().slice(0,8);
      const pick = ACTIVITY_POOL[Math.floor(Math.random() * ACTIVITY_POOL.length)];
      setRows(prev => [{ ...pick, id: nextId, time: now }, ...prev.slice(0, 6)]);
      setNextId(n => n + 1);
    }, 2200);
    return () => clearInterval(t);
  }, [nextId]);

  return (
    <div className="stream-panel">
      <div className="panel-header">
        <span className="panel-title">
          <span className="live-dot"/>
          IOC stream
        </span>
        <span className="live-badge">● LIVE</span>
      </div>
      <div className="stream-body">
        {rows.map(r => (
          <div className="stream-row" key={r.id}>
            <span className="s-time">{r.time}</span>
            <span className="s-type">{r.type}</span>
            <span className="s-value">{r.value}</span>
            <span className={`sev-pill sev-${r.sev}`}>{r.sev}</span>
            <span className="s-src">{r.source}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Animated counters ────────────────────────────────────────────────────────
function useCounter(target, duration = 1800) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = null;
    const step = ts => {
      if (!start) start = ts;
      const p = Math.min((ts - start) / duration, 1);
      setVal(Math.floor(p * target));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [target]);
  return val;
}

function StatCounters() {
  const [tick, setTick] = useState(0);
  useEffect(() => { const t = setInterval(() => setTick(n => n+1), 4000); return ()=>clearInterval(t); }, []);
  const iocs    = useCounter(24817 + tick * 3);
  const blocked = useCounter(1293  + tick * 1);
  const feeds   = useCounter(12);
  const actors  = useCounter(47);

  return (
    <div className="counters-panel">
      <div className="panel-header">
        <span className="panel-title">Platform activity</span>
        <span style={{fontSize:".65rem",color:"var(--dim)",fontFamily:"'JetBrains Mono',monospace"}}>
          auto-refreshing
        </span>
      </div>
      <div className="counter-grid">
        <div className="counter-cell">
          <div className="counter-num" style={{color:"var(--white)"}}>
            {iocs.toLocaleString()}
          </div>
          <div className="counter-label">Total IOCs</div>
          <div className="counter-delta delta-up">↑ +{tick*3} this session</div>
        </div>
        <div className="counter-cell">
          <div className="counter-num" style={{color:"var(--red)"}}>
            {blocked.toLocaleString()}
          </div>
          <div className="counter-label">Threats blocked</div>
          <div className="counter-delta delta-up">↑ +{tick} this session</div>
        </div>
        <div className="counter-cell">
          <div className="counter-num" style={{color:"var(--teal)"}}>
            {feeds}
          </div>
          <div className="counter-label">Live feeds</div>
          <div className="counter-delta delta-down">● All synced</div>
        </div>
        <div className="counter-cell">
          <div className="counter-num" style={{color:"var(--amber)"}}>
            {actors}
          </div>
          <div className="counter-label">Tracked actors</div>
          <div className="counter-delta delta-up">↑ 3 new this week</div>
        </div>
      </div>
    </div>
  );
}

// ─── Geo threat map ───────────────────────────────────────────────────────────
function GeoMap() {
  const [hovered, setHovered] = useState(null);
  const [dots, setDots] = useState(GEO_DOTS);

  // pulse dot sizes randomly
  useEffect(() => {
    const t = setInterval(() => {
      setDots(prev => prev.map(d => ({
        ...d,
        r: 4 + Math.random() * 4
      })));
    }, 1500);
    return () => clearInterval(t);
  }, []);

  const sevColor = { critical:"#FF3B5C", high:"#F5A623", medium:"#3B9EFF", low:"#00D4B4" };

  return (
    <div className="geo-panel">
      <div className="panel-header">
        <span className="panel-title">Global threat origin map</span>
        <span style={{fontSize:".65rem",color:"var(--dim)",fontFamily:"'JetBrains Mono',monospace"}}>
          last 24h
        </span>
      </div>
      <div className="geo-map">
        <svg className="geo-svg" viewBox="0 0 100 50" preserveAspectRatio="xMidYMid meet">
          {/* simplified world grid */}
          {[10,20,30,40,50,60,70,80,90].map(x => (
            <line key={x} x1={x} y1={0} x2={x} y2={50}
              stroke="rgba(30,45,64,.5)" strokeWidth=".2"/>
          ))}
          {[10,20,30,40].map(y => (
            <line key={y} x1={0} y1={y} x2={100} y2={y}
              stroke="rgba(30,45,64,.5)" strokeWidth=".2"/>
          ))}
          {/* continent blobs */}
          <ellipse cx="22" cy="28" rx="10" ry="7" fill="rgba(0,212,180,.04)" stroke="rgba(0,212,180,.08)" strokeWidth=".3"/>
          <ellipse cx="51" cy="26" rx="13" ry="9" fill="rgba(0,212,180,.04)" stroke="rgba(0,212,180,.08)" strokeWidth=".3"/>
          <ellipse cx="73" cy="32" rx="14" ry="10" fill="rgba(0,212,180,.04)" stroke="rgba(0,212,180,.08)" strokeWidth=".3"/>
          <ellipse cx="55" cy="42" rx="6"  ry="4"  fill="rgba(0,212,180,.04)" stroke="rgba(0,212,180,.08)" strokeWidth=".3"/>
          <ellipse cx="84" cy="38" rx="5"  ry="3"  fill="rgba(0,212,180,.04)" stroke="rgba(0,212,180,.08)" strokeWidth=".3"/>
          {/* attack lines from hotspots to center */}
          {dots.filter(d=>d.sev==="critical"||d.sev==="high").map((d,i)=>(
            <line key={i}
              x1={d.x} y1={d.y} x2={51} y2={26}
              stroke={sevColor[d.sev]}
              strokeWidth=".15"
              strokeDasharray=".8 .6"
              opacity=".3"
            />
          ))}
          {/* threat dots */}
          {dots.map((d, i) => (
            <g key={i} className="geo-dot"
              onMouseEnter={() => setHovered(d)}
              onMouseLeave={() => setHovered(null)}>
              <circle cx={d.x} cy={d.y}
                r={hovered===d ? 6 : (d.r||5)}
                fill={sevColor[d.sev]}
                opacity=".8"
                style={{transition:"r .3s"}}
              />
              <circle cx={d.x} cy={d.y}
                r={(d.r||5)+3}
                fill="none"
                stroke={sevColor[d.sev]}
                strokeWidth=".3"
                opacity=".3"
              />
            </g>
          ))}
          {/* tooltip */}
          {hovered && (
            <g>
              <rect x={hovered.x - 18} y={hovered.y - 12} width={36} height={8}
                fill="rgba(15,25,35,.95)" rx="1" stroke="rgba(30,45,64,.8)" strokeWidth=".3"/>
              <text x={hovered.x} y={hovered.y - 6.5}
                textAnchor="middle" fill="#E8F0FA"
                fontSize="2.2" fontFamily="JetBrains Mono">
                {hovered.label}
              </text>
            </g>
          )}
        </svg>
      </div>
      <div className="geo-legend">
        {Object.entries({critical:"#FF3B5C",high:"#F5A623",medium:"#3B9EFF",low:"#00D4B4"}).map(([k,v])=>(
          <div className="geo-legend-item" key={k}>
            <div className="geo-legend-dot" style={{background:v}}/>
            {k}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Threat actors ────────────────────────────────────────────────────────────
function ThreatActors() {
  const colors = ["rgba(255,59,92,.15)","rgba(245,166,35,.15)","rgba(59,158,255,.15)","rgba(0,212,180,.1)"];
  const borders = ["var(--red)","var(--amber)","#3B9EFF","var(--teal)"];

  return (
    <div className="actors-panel">
      <div className="panel-header">
        <span className="panel-title">Tracked threat actors</span>
        <span style={{
          fontSize:".65rem",color:"var(--teal)",
          fontFamily:"'JetBrains Mono',monospace",
          background:"rgba(0,212,180,.08)",
          border:"1px solid rgba(0,212,180,.2)",
          borderRadius:4, padding:".1rem .45rem"
        }}>
          {THREAT_ACTORS.filter(a=>a.active).length} active
        </span>
      </div>
      {THREAT_ACTORS.map((a, i) => (
        <div className="actor-row" key={a.name}>
          <div className="actor-avatar"
            style={{background:colors[i], borderColor:borders[i], color:borders[i]}}>
            {a.name.slice(0,3)}
          </div>
          <div className="actor-info">
            <div className="actor-name">{a.name}
              <span style={{fontSize:".68rem",color:"var(--dim)",fontWeight:400,marginLeft:6}}>
                · {a.region}
              </span>
            </div>
            <div className="actor-aka">{a.aka}</div>
          </div>
          <div className="actor-stats">
            <div>
              <div className="actor-stat-val">{a.iocs}</div>
              <div className="actor-stat-lbl">IOCs</div>
            </div>
            <div>
              <div className="actor-stat-val">{a.campaigns}</div>
              <div className="actor-stat-lbl">campaigns</div>
            </div>
          </div>
          <div className="active-badge"
            style={{background: a.active ? "var(--teal)" : "var(--dim)"}}
            title={a.active ? "Active" : "Dormant"}
          />
        </div>
      ))}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function Login() {
  const scrollToFeatures = (e) => {
    e.preventDefault();
    document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="landing-page">
      {/* Nav */}
      <nav className="landing-nav">
        <div className="logo">
          <div className="logo-icon">TI</div>
          ThreatIntel
        </div>
        <div className="nav-links">
          <a href="#features" onClick={scrollToFeatures}>Features</a>
          <a href="#feed" onClick={(e) => { e.preventDefault(); document.getElementById('feed')?.scrollIntoView({ behavior: 'smooth' }); }}>Live feed</a>
          <a href="#docs" onClick={(e) => e.preventDefault()}>Docs</a>
          <button className="nav-cta" onClick={() => document.querySelector('.auth-card')?.scrollIntoView({ behavior: 'smooth' })}>Request access</button>
        </div>
      </nav>

      {/* Hero */}
      <section className="hero">
        <div>
          <div className="hero-eyebrow">
            <span className="eyebrow-dot"/>
            Threat intelligence platform · v2.0
          </div>
          <h1>
            Detect threats<br/>
            before they<br/>
            <em>hit your network</em>
          </h1>
          <p className="hero-sub">
            Unified IOC management, live threat feeds, MITRE ATT&CK mapping,
            and real-time alerting — built for security analysts who need
            intelligence, not noise.
          </p>
          <div className="hero-stats">
            <div className="stat-item">
              <div className="stat-num">2.4M+</div>
              <div className="stat-label">IOCs tracked</div>
            </div>
            <div className="stat-item">
              <div className="stat-num">12</div>
              <div className="stat-label">Live feeds</div>
            </div>
            <div className="stat-item">
              <div className="stat-num">&lt;5 min</div>
              <div className="stat-label">Feed refresh</div>
            </div>
          </div>
          <TerminalTicker />
        </div>

        <AuthCard />
      </section>

      {/* Features */}
      <section className="features" id="features">
        <p className="section-eyebrow">// capabilities</p>
        <h2 className="section-title">Everything a threat analyst needs in one place</h2>
        <div className="features-grid">
          {FEATURES.map(f => (
            <div className="feat-card" key={f.name}>
              <div className="feat-icon">{f.icon}</div>
              <p className="feat-name">{f.name}</p>
              <p className="feat-desc-text">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Dynamic activity section */}
      <section className="activity-section" id="feed">
        <p className="section-eyebrow">// live activity</p>
        <h2 className="section-title">Threat intelligence, in real time</h2>
        <div className="activity-grid">
          <LiveStream />
          <StatCounters />
        </div>
        <div className="activity-grid-bottom">
          <GeoMap />
          <ThreatActors />
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="logo" style={{fontSize:".85rem"}}>
          <div className="logo-icon" style={{width:24,height:24,fontSize:".6rem"}}>TI</div>
          ThreatIntel Platform
        </div>
        <p>Built for security analysts · OTP access only · No passwords stored</p>
      </footer>
    </div>
  );
}