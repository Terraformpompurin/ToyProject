import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { groupByService } from '../data/checkMetadata.js'

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#10b981', '#06b6d4']

const SERVICE_ICONS = {
  'Security Group': '🔒',
  'S3':             '🪣',
  'IAM':            '👤',
  'RDS':            '🗄️',
  'CloudTrail':     '📜',
  'AWS':            '☁️',
}

export default function ServicePieChart({ violations }) {
  const data = groupByService(violations)

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-400 text-sm">
        위반 항목 없음
      </div>
    )
  }

  return (
    <div>
      <h3 className="text-sm font-semibold text-gray-600 uppercase tracking-wide mb-3">
        서비스별 위반 분포
      </h3>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={75}
            innerRadius={35}
            paddingAngle={3}
          >
            {data.map((_, idx) => (
              <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value, name) => [`${value}건`, `${SERVICE_ICONS[name] ?? '☁️'} ${name}`]}
          />
          <Legend
            formatter={(value) => `${SERVICE_ICONS[value] ?? '☁️'} ${value}`}
            iconType="circle"
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
