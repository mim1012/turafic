export class Logger {
  constructor(private engineVersion: string) {}

  info(message: string, data?: any): void {
    console.log(`[${this.engineVersion}] ${message}`, data || "");
  }

  warn(message: string, data?: any): void {
    console.warn(`[${this.engineVersion}] ${message}`, data || "");
  }

  error(message: string, error?: any): void {
    console.error(`[${this.engineVersion}] ${message}`, error || "");
  }

  success(message: string, data?: any): void {
    console.log(`[${this.engineVersion}] ✅ ${message}`, data || "");
  }
}
