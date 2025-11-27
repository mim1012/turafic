interface BotStatusEvent {
  botId: string;
  botName: string;
  status: "online" | "offline" | "error";
  ip?: string;
  lastSeen: string;
  errorMessage?: string;
}

interface Props {
  botStatuses: Map<string, BotStatusEvent>;
}

export function RealtimeBotStatus({ botStatuses }: Props) {
  // 봇 통계 계산
  const bots = Array.from(botStatuses.values());
  const onlineBots = bots.filter((b) => b.status === "online");
  const offlineBots = bots.filter((b) => b.status === "offline");
  const errorBots = bots.filter((b) => b.status === "error");

  // 봇 역할별 분류 (임시 - 실제로는 봇 데이터에 role 필드 필요)
  const leaderBots = bots.filter((b) => b.botName.includes("leader") || parseInt(b.botId) <= 6);
  const workerBots = bots.filter(
    (b) => (b.botName.includes("worker") || parseInt(b.botId) > 6) && parseInt(b.botId) <= 18
  );
  const rankCheckerBots = bots.filter((b) => b.botName.includes("rank") || parseInt(b.botId) > 18);

  const getStatusIcon = (status: "online" | "offline" | "error") => {
    switch (status) {
      case "online":
        return "🟢";
      case "offline":
        return "🔴";
      case "error":
        return "🟡";
    }
  };

  const getStatusColor = (status: "online" | "offline" | "error") => {
    switch (status) {
      case "online":
        return "bg-green-100 text-green-800 border-green-200";
      case "offline":
        return "bg-red-100 text-red-800 border-red-200";
      case "error":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
    }
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
        <span>📱</span> 봇 상태 ({bots.length}대)
      </h2>

      {/* 전체 통계 */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-center">
          <div className="text-3xl font-bold text-green-700">{onlineBots.length}</div>
          <div className="text-sm text-green-600">🟢 온라인</div>
        </div>
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-center">
          <div className="text-3xl font-bold text-red-700">{offlineBots.length}</div>
          <div className="text-sm text-red-600">🔴 오프라인</div>
        </div>
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 text-center">
          <div className="text-3xl font-bold text-yellow-700">{errorBots.length}</div>
          <div className="text-sm text-yellow-600">🟡 에러</div>
        </div>
      </div>

      {/* 역할별 봇 상태 */}
      <div className="space-y-4">
        {/* 대장봇 (Leader Bots) */}
        <div>
          <div className="font-semibold mb-2 text-gray-700">
            대장봇: {getStatusIcons(leaderBots)} ({leaderBots.filter((b) => b.status === "online").length}/
            {leaderBots.length} 온라인)
          </div>
        </div>

        {/* 쫄병봇 (Worker Bots) */}
        <div>
          <div className="font-semibold mb-2 text-gray-700">
            쫄병봇: {getStatusIcons(workerBots)} ({workerBots.filter((b) => b.status === "online").length}/
            {workerBots.length} 온라인)
          </div>
        </div>

        {/* 순위체크봇 (Rank Checker Bots) */}
        <div>
          <div className="font-semibold mb-2 text-gray-700">
            순위체크봇: {getStatusIcons(rankCheckerBots)} (
            {rankCheckerBots.filter((b) => b.status === "online").length}/{rankCheckerBots.length} 온라인)
          </div>
        </div>
      </div>

      {/* 봇 상세 목록 (에러가 있는 봇만 표시) */}
      {errorBots.length > 0 && (
        <div className="mt-6">
          <h3 className="font-semibold text-red-700 mb-2">🚨 에러 발생 봇</h3>
          <div className="space-y-2">
            {errorBots.map((bot) => (
              <div
                key={bot.botId}
                className="bg-red-50 border border-red-200 rounded p-3 text-sm"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-semibold">{bot.botName}</span>
                    <span className="text-gray-500 ml-2">(ID: {bot.botId})</span>
                  </div>
                  <div className="text-xs text-gray-500">
                    {new Date(bot.lastSeen).toLocaleTimeString()}
                  </div>
                </div>
                {bot.errorMessage && (
                  <div className="text-red-600 mt-1">{bot.errorMessage}</div>
                )}
                {bot.ip && <div className="text-gray-500 text-xs mt-1">IP: {bot.ip}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 봇이 없을 때 */}
      {bots.length === 0 && (
        <div className="text-center text-gray-500 py-8">
          <p>아직 연결된 봇이 없습니다.</p>
          <p className="text-sm mt-2">봇이 연결되면 자동으로 표시됩니다.</p>
        </div>
      )}
    </div>
  );
}

// 헬퍼 함수: 봇 목록을 아이콘으로 표시
function getStatusIcons(bots: BotStatusEvent[]): string {
  if (bots.length === 0) return "없음";

  return bots
    .map((bot) => {
      switch (bot.status) {
        case "online":
          return "🟢";
        case "offline":
          return "🔴";
        case "error":
          return "🟡";
      }
    })
    .join("");
}
