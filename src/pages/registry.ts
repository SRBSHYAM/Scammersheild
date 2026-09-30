import type { PageKey } from '../components/Navigation';
export const PAGE_ROUTES:Record<PageKey,string>={quick:'/',message:'/message-scanner',url:'/url-checker',phone:'/phone-radar',screen:'/screen-scan',library:'/threat-library',intel:'/threat-intel',history:'/scan-history',privacy:'/privacy'};
export const PAGE_TITLES:Record<PageKey,string>={quick:'Quick Scan',message:'Message Scanner',url:'URL Checker',phone:'Phone Radar',screen:'Screen Scan',library:'Threat Library',intel:'Threat Intelligence',history:'Scan History',privacy:'Privacy & Resources'};
export const pageFromPath=(path:string):PageKey=>(Object.entries(PAGE_ROUTES).find(([,route])=>route===path)?.[0] as PageKey|undefined)??'quick';
