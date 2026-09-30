import type { AnalysisResult } from '../types';
export interface ReputationProvider { name:string; checkUrl(url:string):Promise<{status:string; evidence:string[]}>; }
export interface AiProvider { name:string; analyze(input:string):Promise<Partial<AnalysisResult>>; }
export const unavailableReputation:ReputationProvider={name:'No provider configured',async checkUrl(){return {status:'External reputation data unavailable.',evidence:[]};}};
export const unavailableAi:AiProvider={name:'No AI provider configured',async analyze(){return {};}};
