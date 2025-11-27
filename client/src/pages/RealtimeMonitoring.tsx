import { useEffect, useState } from "react";
import { io, Socket } from "socket.io-client";
import { RealtimeBotStatus } from "../components/RealtimeBotStatus";
import { RealtimeRankChart } from "../components/RealtimeRankChart";
import { RealtimeTaskProgress } from "../components/RealtimeTaskProgress";
import { RealtimeErrorLog } from "../components/RealtimeErrorLog";

// 실시간 이벤트 타입
interface BotStatusEvent {
  botId: string;
  botName: string;
  status: "online" | "offline" | "error";
  ip?: string;
  lastSeen: string;
  errorMessage?: string;
}

interface RankUpdateEvent {
  campaignId: number;
  keyword: string;
  productName: string;
  rank: number;
  previousRank?: number;
  timestamp: string;
}

interface TaskEvent {
  taskId: number;
  campaignId: number;
  botId: string;
  type: "assigned" | "started" | "completed" | "failed";
  timestamp: string;
  details?: string;
}

interface ErrorEvent {
  source: string;
  severity: "warning" | "error" | "critical";
  message: string;
  details?: any;
  timestamp: string;
}

export function RealtimeMonitoring() {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<string>("");

  // 이벤트 상태
  const [botStatuses, setBotStatuses] = useState<Map<string, BotStatusEvent>>(new Map());
  const [rankHistory, setRankHistory] = useState<RankUpdateEvent[]>([]);
  const [tasks, setTasks] = useState<TaskEvent[]>([]);
  const [errors, setErrors] = useState<ErrorEvent[]>([]);

  useEffect(() => {
    // Socket.io 연결
    const SOCKET_URL = import.meta.env.VITE_API_URL || "http://localhost:3000";
    const newSocket = io(SOCKET_URL, {
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
    });

    newSocket.on("connect", () => {
      console.log("[RealtimeMonitoring] Socket.io 연결됨:", newSocket.id);
      setIsConnected(true);
    });

    newSocket.on("disconnect", () => {
      console.log("[RealtimeMonitoring] Socket.io 연결 해제");
      setIsConnected(false);
    });

    // 봇 상태 이벤트
    newSocket.on("bot:status", (data: BotStatusEvent) => {
      console.log("[RealtimeMonitoring] 봇 상태 업데이트:", data);
      setBotStatuses((prev) => {
        const updated = new Map(prev);
        updated.set(data.botId, data);
        return updated;
      });
      setLastUpdate(new Date().toLocaleTimeString());
    });

    // 순위 변동 이벤트
    newSocket.on("rank:updated", (data: RankUpdateEvent) => {
      console.log("[RealtimeMonitoring] 순위 업데이트:", data);
      setRankHistory((prev) => [data, ...prev].slice(0, 50)); // 최근 50개만
      setLastUpdate(new Date().toLocaleTimeString());
    });

    // 작업 이벤트
    newSocket.on("task:assigned", (data: TaskEvent) => {
      console.log("[RealtimeMonitoring] 작업 할당:", data);
      setTasks((prev) => [data, ...prev].slice(0, 100));
      setLastUpdate(new Date().toLocaleTimeString());
    });

    newSocket.on("task:completed", (data: TaskEvent) => {
      console.log("[RealtimeMonitoring] 작업 완료:", data);
      setTasks((prev) => [data, ...prev].slice(0, 100));
      setLastUpdate(new Date().toLocaleTimeString());
    });

    // 에러 이벤트
    newSocket.on("error:occurred", (data: ErrorEvent) => {
      console.log("[RealtimeMonitoring] 에러 발생:", data);
      setErrors((prev) => [data, ...prev].slice(0, 100));
      setLastUpdate(new Date().toLocaleTimeString());
    });

    // 초기 상태
    newSocket.on("initial:state", (data: any) => {
      console.log("[RealtimeMonitoring] 초기 상태 수신:", data);
      setLastUpdate(new Date().toLocaleTimeString());
    });

    setSocket(newSocket);

    // 정리
    return () => {
      console.log("[RealtimeMonitoring] 컴포넌트 언마운트, Socket.io 종료");
      newSocket.close();
    };
  }, []);

  return (
    <div className="p-6 space-y-6">
      {/* 헤더 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${isConnected ? "bg-red-500 animate-pulse" : "bg-gray-400"}`} />
          <h1 className="text-3xl font-bold">
            {isConnected ? "🔴 LIVE" : "⚫ OFFLINE"} Turafic 실시간 모니터링
          </h1>
        </div>
        <div className="text-sm text-gray-500">
          마지막 업데이트: {lastUpdate || "대기 중"}
        </div>
      </div>

      {/* 연결 상태 경고 */}
      {!isConnected && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <p className="text-yellow-800">
            ⚠️ Socket.io 서버에 연결되지 않았습니다. 재연결 시도 중...
          </p>
        </div>
      )}

      {/* 4가지 핵심 지표 */}
      <div className="grid grid-cols-1 gap-6">
        {/* 1. 봇 상태 */}
        <RealtimeBotStatus botStatuses={botStatuses} />

        {/* 2. 순위 변동 차트 */}
        <RealtimeRankChart rankHistory={rankHistory} />

        {/* 3. 작업 진행률 */}
        <RealtimeTaskProgress tasks={tasks} />

        {/* 4. 에러 로그 */}
        <RealtimeErrorLog errors={errors} />
      </div>

      {/* 디버그 정보 (개발 모드에서만) */}
      {import.meta.env.DEV && (
        <div className="mt-6 p-4 bg-gray-100 rounded-lg text-xs">
          <p>
            <strong>Socket ID:</strong> {socket?.id || "연결 안 됨"}
          </p>
          <p>
            <strong>봇 수:</strong> {botStatuses.size}
          </p>
          <p>
            <strong>순위 기록:</strong> {rankHistory.length}
          </p>
          <p>
            <strong>작업:</strong> {tasks.length}
          </p>
          <p>
            <strong>에러:</strong> {errors.length}
          </p>
        </div>
      )}
    </div>
  );
}
