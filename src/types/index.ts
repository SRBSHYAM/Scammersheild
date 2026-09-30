export type InputType = 'message' | 'email' | 'url' | 'phone' | 'mixed';
export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';

export interface Evidence { label: string; detail: string; weight: number; source: 'deterministic' | 'reputation' | 'ai'; severity: 'positive' | 'neutral' | 'caution'; }
export interface AnalysisResult { id: string; inputType: InputType; riskScore: number; riskLevel: RiskLevel; confidence: Confidence; category: string; summary: string; uncertainty: string; indicators: Evidence[]; extractedUrls: string[]; recommendations: string[]; domain?: string; protocol?: string; hostname?: string; formatStatus?: string; region?: string; reputationStatus: string; aiStatus: string; createdAt: string; originalInput?: string; }
export interface ThreatEntry { id: string; title: string; category: string; risk: RiskLevel; description: string; indicators: string[]; scenario: string; advice: string; sample: string; }
export interface HistoryRecord { id: string; timestamp: string; inputType: InputType; riskLevel: RiskLevel; riskScore: number; category: string; explanation: string; }
