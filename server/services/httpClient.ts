/**
 * Advanced HTTP Client
 *
 * 실제 Chrome Mobile 브라우저와 동일한 HTTP 동작을 모방합니다.
 * - Cookie 세션 관리
 * - gzip/br 압축 자동 해제
 * - 적절한 timeout 설정
 */

import axios, { AxiosInstance, AxiosRequestConfig } from "axios";

/**
 * Advanced HTTP Client
 */
export class AdvancedHttpClient {
  private client: AxiosInstance;
  private cookieJar: Map<string, string> = new Map();

  constructor() {
    this.client = axios.create({
      timeout: 30000, // 30초
      maxRedirects: 5,
      validateStatus: (status) => status < 500, // 4xx 응답도 성공으로 처리
      decompress: true, // gzip/br 자동 해제
      httpAgent: undefined, // HTTP/1.1 agent 비활성화
      httpsAgent: undefined, // HTTP/1.1 agent 비활성화
    });

    // 응답 인터셉터: Set-Cookie 처리
    this.client.interceptors.response.use((response) => {
      const setCookies = response.headers["set-cookie"];
      if (setCookies) {
        this.saveCookies(setCookies);
      }
      return response;
    });
  }

  /**
   * Set-Cookie 헤더에서 쿠키 추출 및 저장
   */
  private saveCookies(setCookies: string | string[]): void {
    const cookieArray = Array.isArray(setCookies) ? setCookies : [setCookies];

    cookieArray.forEach((cookieStr) => {
      // "name=value; Path=/; ..." 형식에서 name=value만 추출
      const match = cookieStr.match(/^([^=]+)=([^;]+)/);
      if (match) {
        const [, name, value] = match;
        this.cookieJar.set(name, value);
      }
    });
  }

  /**
   * 저장된 쿠키를 Cookie 헤더 형식으로 반환
   */
  private getCookieHeader(): string {
    const cookies: string[] = [];
    this.cookieJar.forEach((value, name) => {
      cookies.push(`${name}=${value}`);
    });
    return cookies.join("; ");
  }

  /**
   * HTTP GET 요청
   *
   * @param url 요청 URL
   * @param headers 추가 헤더
   * @returns HTML 응답
   */
  async get(
    url: string,
    headers: Record<string, string>
  ): Promise<{ status: number; data: string }> {
    // 저장된 쿠키와 전달받은 헤더 병합
    const finalHeaders = { ...headers };

    // 저장된 쿠키가 있으면 추가 (전달받은 Cookie 헤더와 병합)
    const savedCookies = this.getCookieHeader();
    if (savedCookies) {
      if (finalHeaders["cookie"]) {
        // 기존 Cookie 헤더와 병합
        finalHeaders["cookie"] = `${finalHeaders["cookie"]}; ${savedCookies}`;
      } else {
        finalHeaders["cookie"] = savedCookies;
      }
    }

    const config: AxiosRequestConfig = {
      headers: finalHeaders,
      responseType: "text",
    };

    try {
      const response = await this.client.get(url, config);

      return {
        status: response.status,
        data: response.data,
      };
    } catch (error: any) {
      // 네트워크 에러 또는 timeout
      if (error.response) {
        return {
          status: error.response.status,
          data: error.response.data || "",
        };
      }

      throw error;
    }
  }

  /**
   * 쿠키 초기화
   */
  clearCookies(): void {
    this.cookieJar.clear();
  }

  /**
   * 특정 쿠키 설정
   */
  setCookie(name: string, value: string): void {
    this.cookieJar.set(name, value);
  }

  /**
   * 특정 쿠키 가져오기
   */
  getCookie(name: string): string | undefined {
    return this.cookieJar.get(name);
  }
}
