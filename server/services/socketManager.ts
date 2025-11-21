import { Server as HTTPServer } from "http";
import { Server as SocketIOServer, Socket } from "socket.io";

// 실시간 이벤트 타입 정의
export interface BotStatusEvent {
  botId: string;
  botName: string;
  status: "online" | "offline" | "error";
  ip?: string;
  lastSeen: string;
  errorMessage?: string;
}

export interface RankUpdateEvent {
  campaignId: number;
  keyword: string;
  productName: string;
  rank: number;
  previousRank?: number;
  timestamp: string;
}

export interface TaskEvent {
  taskId: number;
  campaignId: number;
  botId: string;
  type: "assigned" | "started" | "completed" | "failed";
  timestamp: string;
  details?: string;
}

export interface ErrorEvent {
  source: string; // "bot", "campaign", "rank_check"
  severity: "warning" | "error" | "critical";
  message: string;
  details?: any;
  timestamp: string;
}

/**
 * Socket.io 서버 관리자
 * 실시간 이벤트를 웹 클라이언트에게 브로드캐스트
 */
class SocketManager {
  private io: SocketIOServer | null = null;
  private connectedClients: Map<string, Socket> = new Map();

  /**
   * Socket.io 서버 초기화
   */
  public initialize(server: HTTPServer): void {
    this.io = new SocketIOServer(server, {
      cors: {
        origin: process.env.CLIENT_URL || "http://localhost:5173",
        credentials: true,
        methods: ["GET", "POST"],
      },
      pingTimeout: 60000,
      pingInterval: 25000,
    });

    this.io.on("connection", (socket: Socket) => {
      console.log(`[SocketManager] 클라이언트 연결: ${socket.id}`);
      this.connectedClients.set(socket.id, socket);

      // 연결 시 현재 상태 전송
      this.sendInitialState(socket);

      socket.on("disconnect", () => {
        console.log(`[SocketManager] 클라이언트 연결 해제: ${socket.id}`);
        this.connectedClients.delete(socket.id);
      });

      // 핑 이벤트 처리
      socket.on("ping", () => {
        socket.emit("pong", { timestamp: new Date().toISOString() });
      });
    });

    console.log("[SocketManager] Socket.io 서버 초기화 완료");
  }

  /**
   * 초기 상태 전송 (연결 시)
   */
  private async sendInitialState(socket: Socket): Promise<void> {
    // TODO: DB에서 현재 봇 상태, 진행 중인 작업 등 조회하여 전송
    socket.emit("initial:state", {
      timestamp: new Date().toISOString(),
      message: "연결 완료",
    });
  }

  /**
   * 봇 상태 변경 이벤트 브로드캐스트
   */
  public broadcastBotStatus(data: BotStatusEvent): void {
    if (!this.io) {
      console.warn("[SocketManager] Socket.io 서버가 초기화되지 않았습니다.");
      return;
    }

    this.io.emit("bot:status", data);
    console.log(`[SocketManager] 봇 상태 브로드캐스트: ${data.botId} → ${data.status}`);
  }

  /**
   * 순위 변동 이벤트 브로드캐스트
   */
  public broadcastRankUpdate(data: RankUpdateEvent): void {
    if (!this.io) return;

    this.io.emit("rank:updated", data);
    console.log(
      `[SocketManager] 순위 업데이트 브로드캐스트: ${data.productName} → ${data.rank}위`
    );
  }

  /**
   * 작업 이벤트 브로드캐스트
   */
  public broadcastTaskEvent(data: TaskEvent): void {
    if (!this.io) return;

    this.io.emit(`task:${data.type}`, data);
    console.log(
      `[SocketManager] 작업 이벤트 브로드캐스트: Task #${data.taskId} → ${data.type}`
    );
  }

  /**
   * 에러 이벤트 브로드캐스트
   */
  public broadcastError(data: ErrorEvent): void {
    if (!this.io) return;

    this.io.emit("error:occurred", data);
    console.log(`[SocketManager] 에러 브로드캐스트: [${data.severity}] ${data.message}`);
  }

  /**
   * 특정 이벤트 브로드캐스트 (범용)
   */
  public broadcast(eventName: string, data: any): void {
    if (!this.io) return;

    this.io.emit(eventName, data);
  }

  /**
   * 연결된 클라이언트 수 조회
   */
  public getConnectedClientsCount(): number {
    return this.connectedClients.size;
  }

  /**
   * Socket.io 서버 종료
   */
  public close(): void {
    if (this.io) {
      this.io.close();
      this.io = null;
      console.log("[SocketManager] Socket.io 서버 종료");
    }
  }
}

// 싱글톤 인스턴스
export const socketManager = new SocketManager();
