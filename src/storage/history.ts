import type { AnalysisResult, HistoryRecord } from '../types';
const KEY='scamshield-history-v1';
export function loadHistory():HistoryRecord[]{ try { const parsed=JSON.parse(localStorage.getItem(KEY)||'[]'); return Array.isArray(parsed)?parsed:[]; } catch { return []; } }
export function saveResult(result:AnalysisResult){ const record:HistoryRecord={id:result.id,timestamp:result.createdAt,inputType:result.inputType,riskLevel:result.riskLevel,riskScore:result.riskScore,category:result.category,explanation:result.summary}; localStorage.setItem(KEY,JSON.stringify([record,...loadHistory()].slice(0,50))); }
export function deleteHistory(id:string){ localStorage.setItem(KEY,JSON.stringify(loadHistory().filter(item=>item.id!==id))); }
export function clearHistory(){ localStorage.removeItem(KEY); }
