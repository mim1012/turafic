interface TaskEvent {
  taskId: number;
  campaignId: number;
  botId: string;
  type: "assigned" | "started" | "completed" | "failed";
  timestamp: string;
  details?: string;
}

interface Props {
  tasks: TaskEvent[];
}

export function RealtimeTaskProgress({ tasks }: Props) {
  // 작업 통계 계산
  const assignedTasks = tasks.filter((t) => t.type === "assigned");
  const completedTasks = tasks.filter((t) => t.type === "completed");
  const failedTasks = tasks.filter((t) => t.type === "failed");

  // 진행 중인 작업 (assigned - completed - failed)
  const inProgressCount = Math.max(
    0,
    assignedTasks.length - completedTasks.length - failedTasks.length
  );

  // 완료율 계산
  const totalTasks = tasks.length;
  const completionRate =
    totalTasks > 0 ? ((completedTasks.length / totalTasks) * 100).toFixed(1) : 0;

  // 최근 작업 10개
  const recentTasks = tasks.slice(0, 10);

  const getTaskTypeIcon = (type: TaskEvent["type"]) => {
    switch (type) {
      case "assigned":
        return "📝";
      case "started":
        return "▶️";
      case "completed":
        return "✅";
      case "failed":
        return "❌";
    }
  };

  const getTaskTypeColor = (type: TaskEvent["type"]) => {
    switch (type) {
      case "assigned":
        return "text-blue-600";
      case "started":
        return "text-purple-600";
      case "completed":
        return "text-green-600";
      case "failed":
        return "text-red-600";
    }
  };

  const getTaskTypeName = (type: TaskEvent["type"]) => {
    switch (type) {
      case "assigned":
        return "할당됨";
      case "started":
        return "시작됨";
      case "completed":
        return "완료됨";
      case "failed":
        return "실패";
    }
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
        <span>⚙️</span> 작업 진행 현황
      </h2>

      {/* 작업 통계 */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-blue-700">{assignedTasks.length}</div>
          <div className="text-xs text-blue-600">할당됨</div>
        </div>
        <div className="bg-purple-50 border border-purple-200 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-purple-700">{inProgressCount}</div>
          <div className="text-xs text-purple-600">진행 중</div>
        </div>
        <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-green-700">{completedTasks.length}</div>
          <div className="text-xs text-green-600">완료</div>
        </div>
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-red-700">{failedTasks.length}</div>
          <div className="text-xs text-red-600">실패</div>
        </div>
      </div>

      {/* 진행률 바 */}
      {totalTasks > 0 && (
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-semibold text-gray-700">전체 완료율</span>
            <span className="text-sm font-bold text-green-700">{completionRate}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
            <div
              className="bg-green-500 h-3 rounded-full transition-all duration-300"
              style={{ width: `${completionRate}%` }}
            />
          </div>
          <div className="text-xs text-gray-500 mt-1">
            {completedTasks.length} / {totalTasks} 작업 완료
          </div>
        </div>
      )}

      {/* 최근 작업 목록 */}
      {recentTasks.length > 0 ? (
        <div>
          <h3 className="font-semibold mb-2 text-gray-700">최근 작업 (최대 10개)</h3>
          <div className="space-y-1 max-h-64 overflow-y-auto">
            {recentTasks.map((task, index) => (
              <div
                key={`${task.taskId}-${task.timestamp}-${index}`}
                className="flex items-center justify-between text-sm p-2 bg-gray-50 rounded hover:bg-gray-100 transition-colors"
              >
                <div className="flex items-center gap-2 flex-1">
                  <span className="text-lg">{getTaskTypeIcon(task.type)}</span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">작업 #{task.taskId}</span>
                      <span className={`text-xs font-semibold ${getTaskTypeColor(task.type)}`}>
                        {getTaskTypeName(task.type)}
                      </span>
                    </div>
                    {task.details && (
                      <div className="text-xs text-gray-600">{task.details}</div>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-gray-500">
                    봇 #{task.botId}
                  </div>
                  <div className="text-xs text-gray-400">
                    {new Date(task.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="text-center text-gray-500 py-8">
          <p>아직 작업 기록이 없습니다.</p>
          <p className="text-sm mt-2">작업이 시작되면 자동으로 표시됩니다.</p>
        </div>
      )}
    </div>
  );
}
