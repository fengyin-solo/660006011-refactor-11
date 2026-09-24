// 漏洞模式的唯一事实源：仓库根目录 shared/vulnerability-patterns.json
// 后端扫描、/api/patterns 与前端模式库、前端审计入口全部从这一份生成。
import sharedJson from '@shared/vulnerability-patterns.json'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface VulnerabilityPattern {
  id: string
  /** 扫描结论里记录的类型名（与后端历史输出一致） */
  type: string
  /** 模式库页面展示的短名称 */
  name: string
  severity: Severity
  /** 统一的匹配写法，前后端共用同一份正则 */
  regex: string
  /** 模式库页面展示的说明（保持原有文字） */
  description: string
  /** 扫描结论里展示的说明（保持后端原有文字） */
  findingDescription: string
  suggestion: string
  /** 历史结论里出现过的旧名称，用于把旧结论解析回当前定义 */
  aliases: string[]
}

interface SharedDefinitions {
  version: number
  patterns: VulnerabilityPattern[]
}

const shared = sharedJson as SharedDefinitions

export const VULNERABILITY_PATTERNS: VulnerabilityPattern[] = shared.patterns

/** 模式库视图：字段沿用页面原本使用的 name/severity/description/regex */
export const PATTERN_LIBRARY = VULNERABILITY_PATTERNS.map((p) => ({
  name: p.name,
  severity: p.severity,
  description: p.description,
  regex: p.regex,
}))

export interface DetectedVulnerability {
  type: string
  severity: Severity
  line: number
  description: string
  suggestion: string
}

/**
 * 按共用定义扫描合约代码。
 * 遍历顺序、正则写法、行号计算与结论字段均与后端 detect_vulnerabilities 对齐，
 * 保证整数溢出、未授权访问等模式在两个入口口径完全一致。
 */
export function detectVulnerabilities(code: string): DetectedVulnerability[] {
  const vulnerabilities: DetectedVulnerability[] = []

  for (const vp of VULNERABILITY_PATTERNS) {
    const re = new RegExp(vp.regex, 'gm')
    let m: RegExpExecArray | null
    while ((m = re.exec(code)) !== null) {
      const lineNum = code.slice(0, m.index).split('\n').length
      vulnerabilities.push({
        type: vp.type,
        severity: vp.severity,
        line: lineNum,
        description: vp.findingDescription,
        suggestion: vp.suggestion,
      })
      // 防止零宽匹配导致死循环
      if (m.index === re.lastIndex) re.lastIndex++
    }
  }

  return vulnerabilities
}

/**
 * 把结论中记录的类型名（包含历史上出现过的旧名称）解析回当前定义，
 * 保证历史里已生成的结论在定义收拢后仍能照常打开与展示。
 */
export function resolvePattern(typeName: string | null | undefined): VulnerabilityPattern | undefined {
  if (!typeName) return undefined
  return VULNERABILITY_PATTERNS.find(
    (p) => p.type === typeName || p.aliases.includes(typeName),
  )
}
