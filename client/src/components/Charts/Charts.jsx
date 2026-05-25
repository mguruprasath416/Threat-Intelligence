// ============================================================
// components/Charts/Charts.jsx — ALL DASHBOARD CHARTS
// ============================================================
// Four chart components built with Recharts:
//
//   SeverityDonut     → Donut chart: IOC breakdown by severity
//   IOCTypePie        → Pie chart: IOCs by type (IP/domain/URL/hash)
//   TrendLineChart    → Line chart: IOC count over last 30 days
//   CountryBarChart   → Horizontal bar: top countries by threat count
//
// All charts share the same dark theme using CSS variables
// and custom Recharts tooltips styled to match the UI.
// ============================================================

import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Area, AreaChart,
  BarChart, Bar,
} from 'recharts';
import './Charts.css';

// ── Shared Custom Tooltip ──────────────────────────────────
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      {label && <div className="tooltip-label">{label}</div>}
      {payload.map((entry, i) => (
        <div key={i} className="tooltip-row">
          <span className="tooltip-dot" style={{ background: entry.color }} />
          <span className="tooltip-name">{entry.name}:</span>
          <span className="tooltip-value">{entry.value}</span>
        </div>
      ))}
    </div>
  );
};

// ── Severity Donut ─────────────────────────────────────────
// Shows how IOCs are distributed across severity levels
export const SeverityDonut = ({ data }) => {
  if (!data || data.length === 0) return <ChartEmpty />;

  const COLORS = {
    Critical: '#ff3355',
    High:     '#ff8800',
    Medium:   '#ffcc00',
    Low:      '#00ff88',
  };

  const chartData = data.map(d => ({
    name:  d._id,
    value: d.count,
    color: COLORS[d._id] || '#7a9bb5',
  }));

  const total = chartData.reduce((s, d) => s + d.value, 0);

  return (
    <div className="chart-container">
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%" cy="50%"
            innerRadius={65}
            outerRadius={95}
            paddingAngle={3}
            dataKey="value"
            stroke="none"
          >
            {chartData.map((entry, index) => (
              <Cell
                key={index}
                fill={entry.color}
                style={{ filter: `drop-shadow(0 0 6px ${entry.color}60)` }}
              />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            formatter={(value) => (
              <span style={{ fontFamily: 'Share Tech Mono', fontSize: '11px',
                color: COLORS[value] || '#7a9bb5' }}>{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
      {/* Center label */}
      <div className="donut-center">
        <div className="donut-total">{total}</div>
        <div className="donut-label">TOTAL</div>
      </div>
    </div>
  );
};

// ── IOC Type Distribution ─────────────────────────────────
export const IOCTypePie = ({ data }) => {
  if (!data || data.length === 0) return <ChartEmpty />;

  const COLORS = {
    ip:     '#00d4ff',
    domain: '#7c6af7',
    url:    '#ff8800',
    hash:   '#00ff88',
    email:  '#ff3355',
  };

  const chartData = data.map(d => ({
    name:  d._id?.toUpperCase(),
    value: d.count,
    color: COLORS[d._id] || '#7a9bb5',
  }));

  return (
    <div className="chart-container">
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%" cy="50%"
            outerRadius={95}
            paddingAngle={2}
            dataKey="value"
            stroke="none"
            label={({ name, percent }) =>
              percent > 0.05 ? `${name} ${(percent * 100).toFixed(0)}%` : ''
            }
            labelLine={false}
          >
            {chartData.map((entry, i) => (
              <Cell key={i} fill={entry.color}
                style={{ filter: `drop-shadow(0 0 4px ${entry.color}60)` }} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

// ── IOC Trend Line ─────────────────────────────────────────
// Shows daily IOC count over last 30 days
export const TrendLineChart = ({ data }) => {
  if (!data || data.length === 0) return <ChartEmpty />;

  const chartData = data.map(d => ({
    date:  d._id?.slice(5),   // Strip year: "2024-01-15" → "01-15"
    count: d.count,
  }));

  return (
    <div className="chart-container">
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.03)" vertical={false} />
          <XAxis
            dataKey="date"
            tick={{ fontFamily: 'Share Tech Mono', fontSize: 10, fill: '#3d5a6e' }}
            tickLine={false} axisLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fontFamily: 'Share Tech Mono', fontSize: 10, fill: '#3d5a6e' }}
            tickLine={false} axisLine={false}
            allowDecimals={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone"
            dataKey="count"
            name="IOCs"
            stroke="#00d4ff"
            strokeWidth={2}
            fill="url(#trendGradient)"
            dot={false}
            activeDot={{ r: 4, fill: '#00d4ff', stroke: 'none' }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

// ── Top Countries Bar Chart ────────────────────────────────
export const CountryBarChart = ({ data }) => {
  if (!data || data.length === 0) return <ChartEmpty />;

  const chartData = data.slice(0, 8).map(d => ({
    country: d._id,
    count:   d.count,
  }));

  return (
    <div className="chart-container">
      <ResponsiveContainer width="100%" height={220}>
        <BarChart
          data={chartData}
          layout="vertical"
          margin={{ top: 0, right: 30, left: 10, bottom: 0 }}
        >
          <CartesianGrid stroke="rgba(255,255,255,0.03)" horizontal={false} />
          <XAxis
            type="number"
            tick={{ fontFamily: 'Share Tech Mono', fontSize: 10, fill: '#3d5a6e' }}
            tickLine={false} axisLine={false}
          />
          <YAxis
            dataKey="country" type="category"
            tick={{ fontFamily: 'Share Tech Mono', fontSize: 10, fill: '#7a9bb5' }}
            tickLine={false} axisLine={false} width={35}
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="count" name="IOCs" radius={[0, 2, 2, 0]}>
            {chartData.map((_, i) => (
              <Cell
                key={i}
                fill={`hsl(${200 - i * 12}, 90%, ${55 - i * 3}%)`}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

// ── Empty State ────────────────────────────────────────────
const ChartEmpty = () => (
  <div className="chart-empty">
    <span>NO DATA AVAILABLE</span>
  </div>
);
