import { AlertTriangle, ArrowUpRight, Loader2, ScanLine } from 'lucide-react';
export function LoadingState(){return <div className="state-card loading-state"><Loader2 className="spin" size={24}/><div><strong>SCANNING...</strong><p>Analyzing content and checking available indicators...</p></div></div>}
export function EmptyState({title,detail}:{title:string;detail:string}){return <div className="state-card"><ScanLine size={25}/><div><strong>{title}</strong><p>{detail}</p></div></div>}
export function ErrorState({detail}:{detail:string}){return <div className="state-card error-state"><AlertTriangle size={25}/><div><strong>Assessment needs review</strong><p>{detail}</p></div></div>}
export function SectionHeader({kicker,title,detail,action}:{kicker:string;title:string;detail?:string;action?:React.ReactNode}){return <div className="section-header"><div><div className="eyebrow">{kicker}</div><h1>{title}</h1>{detail&&<p className="muted">{detail}</p>}</div>{action&&<div>{action}</div>}</div>}
export function LinkButton({children,onClick}:{children:React.ReactNode;onClick:()=>void}){return <button className="text-link" onClick={onClick}>{children}<ArrowUpRight size={14}/></button>}
