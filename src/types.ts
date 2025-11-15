export interface SecurityIssue {
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  file: string;
  line?: number;
  column?: number;
  code?: string;
  fix?: string;
}

export interface ScanResult {
  files: number;
  issues: SecurityIssue[];
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: boolean;
}

export interface SecurityRule {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  check: (content: string, file: string) => SecurityIssue[];
}
