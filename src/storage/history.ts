import type { AnalysisResult, HistoryRecord, InputType, RiskLevel } from '../types';
const KEY='scamshield-history-v1';
const inputTypes:InputType[]=['message','email','url','phone','mixed'];
const riskLevels:RiskLevel[]=['safe','low','medium','high','critical'];
function isRecord(value:unknown):value is HistoryRecord { if(!value||typeof value!=='object') return false; const item=value as Partial<HistoryRecord>; return typeof item.id==='string'&&typeof item.timestamp==='string'&&inputTypes.includes(item.inputType as InputType)&&riskLevels.includes(item.riskLevel as RiskLevel)&&typeof item.riskScore==='number'&&Number.isFinite(item.riskScore)&&typeof item.category==='string'&&typeof item.explanation==='string'; }
export function loadHistory():HistoryRecord[]{ try { const parsed=JSON.parse(localStorage.getItem(KEY)||'[]'); return Array.isArray(parsed)?parsed.filter(isRecord).slice(0,50):[]; } catch { return []; } }
export function saveResult(result:AnalysisResult){ const record:HistoryRecord={id:result.id,timestamp:result.createdAt,inputType:result.inputType,riskLevel:result.riskLevel,riskScore:result.riskScore,category:result.category,explanation:result.summary}; localStorage.setItem(KEY,JSON.stringify([record,...loadHistory()].slice(0,50))); }
export function deleteHistory(id:string){ localStorage.setItem(KEY,JSON.stringify(loadHistory().filter(item=>item.id!==id))); }
export function clearHistory(){ localStorage.removeItem(KEY); }
