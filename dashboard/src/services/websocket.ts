import { WebSocketMessage } from '../types';

type MessageHandler = (message: WebSocketMessage) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectInterval: number = 5000;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private messageHandlers: Set<MessageHandler> = new Set();
  private isConnecting: boolean = false;

  constructor(url: string) {
    this.url = url;
  }

  connect() {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return;
    }

    this.isConnecting = true;
    console.log('[WebSocket] 연결 시도:', this.url);

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        console.log('[WebSocket] 연결 성공');
        this.isConnecting = false;
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
          this.reconnectTimer = null;
        }
      };

      this.ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          console.log('[WebSocket] 메시지 수신:', message.type);
          this.messageHandlers.forEach((handler) => handler(message));
        } catch (error) {
          console.error('[WebSocket] 메시지 파싱 에러:', error);
        }
      };

      this.ws.onerror = (error) => {
        console.error('[WebSocket] 에러:', error);
        this.isConnecting = false;
      };

      this.ws.onclose = () => {
        console.log('[WebSocket] 연결 종료');
        this.isConnecting = false;
        this.scheduleReconnect();
      };
    } catch (error) {
      console.error('[WebSocket] 연결 실패:', error);
      this.isConnecting = false;
      this.scheduleReconnect();
    }
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) {
      return;
    }

    console.log(`[WebSocket] ${this.reconnectInterval / 1000}초 후 재연결 시도`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.reconnectInterval);
  }

  onMessage(handler: MessageHandler) {
    this.messageHandlers.add(handler);
    return () => {
      this.messageHandlers.delete(handler);
    };
  }

  send(message: any) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('[WebSocket] 연결되지 않음, 메시지 전송 실패');
    }
  }

  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }
}

// Singleton 인스턴스
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/dashboard';
export const websocketService = new WebSocketService(WS_URL);
