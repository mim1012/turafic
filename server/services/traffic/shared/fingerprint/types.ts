export interface FingerprintProfile {
  version: string;
  deviceName: string;
  userAgent: string;
  viewport: {
    width: number;
    height: number;
    deviceScaleFactor: number;
  };
  platform: string;
  webgl: {
    vendor: string;
    renderer: string;
  };
  deviceMemory: number;
  hardwareConcurrency: number;
  maxTouchPoints: number;
  headers: {
    "accept-language": string;
    "sec-ch-ua": string;
    "sec-ch-ua-mobile": string;
    "sec-ch-ua-platform": string;
  };
  timezone: string;
  languages: string[];
  colorDepth: number;
}
