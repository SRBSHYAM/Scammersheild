import type { AnalysisResult, Confidence, Evidence, InputType, RiskLevel } from '../types';

const urlRegex = /(?:https?:\/\/|www\.)[^\s<>()]+/gi;
const phoneRegex = /(?:\+?\d[\d\s().-]{7,}\d)/;
const emailRegex = /\b[^\s@]+@[^\s@]+\.[^\s@]+\b/;
const rules: Array<{pattern:RegExp; label:string; detail:string; weight:number; category:string}> = [
 {pattern:/urgent|immediately|within \d+ (?:minutes?|hours?)|act now|last warning|आज|तुरंत/i,label:'Urgency language detected',detail:'Pressure to act quickly can reduce careful verification.',weight:14,category:'Social Engineering'},
 {pattern:/suspend|blocked|freeze|legal action|police|penalty|arrest|बंद|जुर्माना/i,label:'Threat or account fear detected',detail:'Fear-based consequences are commonly used in impersonation attempts.',weight:13,category:'Impersonation'},
 {pattern:/otp|one[- ]time password|verification code/i,label:'OTP request detected',detail:'Never share OTPs; legitimate support should not ask for them.',weight:25,category:'OTP Scam'},
 {pattern:/password|passcode|pin|cvv|card number|banking credentials|पासवर्ड|पिन/i,label:'Sensitive credential request detected',detail:'Requests for passwords, PINs, CVV, or card details are high-risk signals.',weight:27,category:'Phishing'},
 {pattern:/pay|payment|deposit|transfer|upi|qr|refund|₹|rs\.?\s?\d+|money/i,label:'Financial request detected',detail:'Unsolicited money or QR requests warrant independent verification.',weight:19,category:'Payment Fraud'},
 {pattern:/kyc|pan card|aadhar|aadhaar|reactivat/i,label:'KYC or identity request detected',detail:'Unexpected identity-document requests can indicate fake KYC flows.',weight:18,category:'Fake KYC'},
 {pattern:/parcel|delivery|courier|shipment|customs/i,label:'Delivery theme detected',detail:'Delivery themes are frequently used in smishing lures.',weight:8,category:'Delivery Scam'},
 {pattern:/job|work from home|task|commission|salary|earn \S+ daily/i,label:'Job or task offer detected',detail:'Unsolicited easy-income offers deserve verification.',weight:12,category:'Job Scam'},
 {pattern:/guaranteed|double|profit|return|investment|crypto|trading/i,label:'Investment promise detected',detail:'Guaranteed or unusually high returns are caution signals.',weight:16,category:'Investment Scam'},
 {pattern:/support|customer care|bank|government|income tax|police|whatsapp/i,label:'Impersonation theme detected',detail:'Brand or authority themes should be verified through official channels.',weight:8,category:'Impersonation'}
];
const shorteners = /(^|\.)((bit\.ly)|(tinyurl\.com)|(t\.co)|(goo\.gl)|(ow\.ly))$/i;
const suspiciousTlds = /\.(top|click|zip|xyz|work|gq|tk|ml|cf|ga)$/i;
const suspiciousWords = /(verify|login|secure|account|update|wallet|bonus|claim|support|refund|kyc)/i;

export function classifyInput(raw:string): InputType {
 const value=raw.trim(); const hasUrl=urlRegex.test(value); urlRegex.lastIndex=0; const hasPhone=phoneRegex.test(value); const hasEmail=emailRegex.test(value);
 if(hasUrl && (value.length>120 || /[a-z]{3,}\s/i.test(value.replace(urlRegex,'')))) return 'mixed';
 if(hasUrl) return 'url'; if(hasPhone && value.replace(phoneRegex,'').trim().length<12) return 'phone'; if(hasEmail || /subject:|dear |unsubscribe/i.test(value)) return 'email'; return 'message';
}
export function extractUrls(raw:string){ return (raw.match(urlRegex) ?? []).map(x=>x.replace(/[),.;!?]+$/,'')); }
function urlEvidence(raw:string): {evidence:Evidence[]; meta:Partial<AnalysisResult>} {
 const evidence:Evidence[]=[]; const value=raw.trim(); let parsed:URL;
 try { parsed=new URL(/^https?:\/\//i.test(value)?value:`https://${value}`); } catch { return {evidence:[{label:'Invalid URL structure',detail:'The value could not be parsed as a standard URL.',weight:12,source:'deterministic',severity:'caution'}],meta:{reputationStatus:'External reputation data unavailable',aiStatus:'AI analysis not configured'}}; }
 const host=parsed.hostname; const protocol=parsed.protocol.replace(':',''); const parts=host.split('.');
 if(protocol!=='https') evidence.push({label:'Connection is not HTTPS',detail:'Transport encryption is absent; this is an indicator, not proof of fraud.',weight:8,source:'deterministic',severity:'caution'});
 if(/@/.test(value)) evidence.push({label:'@ symbol in URL',detail:'An @ symbol can obscure the actual destination host.',weight:18,source:'deterministic',severity:'positive'});
 if(/\d{1,3}(?:\.\d{1,3}){3}/.test(host)) evidence.push({label:'IP-address hostname detected',detail:'Direct IP links deserve extra verification.',weight:16,source:'deterministic',severity:'caution'});
 if(value.length>100) evidence.push({label:'Long URL detected',detail:'Length alone does not prove maliciousness, but it may hide complex parameters.',weight:5,source:'deterministic',severity:'caution'});
 if(parts.length>4) evidence.push({label:'Excessive subdomains detected',detail:'Multiple subdomains can be used in lookalike URLs.',weight:12,source:'deterministic',severity:'caution'});
 if(/%[0-9a-f]{2}/i.test(value)) evidence.push({label:'Encoded URL characters detected',detail:'Encoding can make a destination harder to inspect.',weight:8,source:'deterministic',severity:'caution'});
 if(parsed.port && !['80','443'].includes(parsed.port)) evidence.push({label:'Unusual port detected',detail:`Port ${parsed.port} is uncommon for a public web link.`,weight:12,source:'deterministic',severity:'caution'});
 if(host.startsWith('xn--') || host.includes('.xn--')) evidence.push({label:'Punycode / IDN indicator detected',detail:'Internationalized domains can be legitimate but may resemble other brands.',weight:12,source:'deterministic',severity:'caution'});
 if(shorteners.test(host)) evidence.push({label:'URL shortener detected',detail:'The final destination is hidden until the link is expanded.',weight:13,source:'deterministic',severity:'caution'});
 if(suspiciousTlds.test(host)) evidence.push({label:'Uncommon TLD detected',detail:'A TLD alone does not prove a site is unsafe; verify the domain independently.',weight:7,source:'deterministic',severity:'caution'});
 if(suspiciousWords.test(value)) evidence.push({label:'Sensitive action keyword in URL',detail:'Login, verify, wallet, or refund language can signal a lure.',weight:8,source:'deterministic',severity:'caution'});
 if(/(paytm|sbi|hdfc|icici|amazon|flipkart|google|microsoft|whatsapp)/i.test(host) && !/(paytm\.com|sbi\.co\.in|hdfcbank\.com|icicibank\.com|amazon\.in|flipkart\.com|google\.com|microsoft\.com|whatsapp\.com)$/i.test(host)) evidence.push({label:'Potential brand lookalike',detail:'A familiar brand term appears outside an obvious official domain.',weight:20,source:'deterministic',severity:'positive'});
 return {evidence,meta:{domain:host,hostname:host,protocol,reputationStatus:'External reputation data unavailable',aiStatus:'AI analysis not configured'}};
}
function phoneAssessment(raw:string){ const normalized=raw.replace(/[^\d+]/g,''); const digits=normalized.replace(/\D/g,''); const evidence:Evidence[]=[]; let region='Unknown region';
 if(normalized.startsWith('+91') || (digits.length===10 && /^[6-9]/.test(digits))) region='India'; else if(normalized.startsWith('+1')) region='North America'; else if(normalized.startsWith('+44')) region='United Kingdom'; else if(normalized.startsWith('+61')) region='Australia';
 const valid=(digits.length>=10 && digits.length<=15);
 if(!valid) evidence.push({label:'Phone format needs review',detail:'The number does not match a broad international format.',weight:18,source:'deterministic',severity:'caution'});
 if(/(.)\1{5,}/.test(digits)) evidence.push({label:'Repeated digit pattern detected',detail:'Highly repetitive formatting can indicate a placeholder or invalid number.',weight:12,source:'deterministic',severity:'caution'});
 return {evidence,region,formatStatus:valid?'Broad format valid':'Format needs review'};
}
export function analyzeInput(raw:string):AnalysisResult {
 const input=raw.trim(); const inputType=classifyInput(input); const urls=extractUrls(input); const evidence:Evidence[]=[]; let category='General scam indicators'; let meta:Partial<AnalysisResult>={reputationStatus:'External reputation data unavailable',aiStatus:'AI analysis not configured'};
 if(inputType==='url' || urls.length){ const urlResult=urlEvidence(urls[0] ?? input); evidence.push(...urlResult.evidence); meta={...meta,...urlResult.meta}; }
 if(inputType==='phone'){ const p=phoneAssessment(input); evidence.push(...p.evidence); meta={...meta,region:p.region,formatStatus:p.formatStatus,reputationStatus:'Unknown reputation — no verified reports available.'}; }
 for(const rule of rules){ if(rule.pattern.test(input)){ evidence.push({label:rule.label,detail:rule.detail,weight:rule.weight,source:'deterministic',severity:rule.weight>=20?'positive':'caution'}); if(category==='General scam indicators') category=rule.category; } }
 if(!evidence.length) evidence.push({label:'No significant scam indicators detected',detail:'The submitted content is not showing the tested local heuristics.',weight:-4,source:'deterministic',severity:'neutral'});
 const score=Math.max(0,Math.min(100,evidence.reduce((sum,item)=>sum+item.weight,0))); const riskLevel:RiskLevel=score>=80?'critical':score>=60?'high':score>=35?'medium':score>=12?'low':'safe'; const confidence:Confidence=evidence.length>=4?'high':evidence.length>=2?'medium':'low';
 const summary=riskLevel==='safe'?'No significant scam indicators were detected in the submitted content. Automated analysis cannot guarantee that content is legitimate.':riskLevel==='low'?'A small number of caution signals were detected. Verify the context through a trusted channel.':`${riskLevel==='critical'?'High-risk':'Potentially unsafe'} indicators detected. Review the evidence before taking action.`;
 const recommendations=riskLevel==='safe'?['Continue to verify the sender and use official apps or websites.','Never share passwords, OTPs, PINs, CVV, or banking credentials.']:['Do not click unexpected links or provide credentials.','Verify the request using the organization’s official website, app, or a trusted phone number.','If money was sent in India, contact your bank and report quickly via 1930.'];
 return {id:crypto.randomUUID(),inputType,riskScore:score,riskLevel,confidence,category,summary,indicators:evidence,extractedUrls:urls,recommendations,...meta,reputationStatus:meta.reputationStatus ?? 'External reputation data unavailable',aiStatus:meta.aiStatus ?? 'AI analysis not configured',createdAt:new Date().toISOString()};
}
