import { useEffect } from "react";
import { useToast } from "@/hooks/use-toast";

interface ErrorEvent {
  source: string;
  severity: "warning" | "error" | "critical";
  message: string;
  details?: any;
  timestamp: string;
}

interface Props {
  errors: ErrorEvent[];
}

export function RealtimeErrorLog({ errors }: Props) {
  const { toast } = useToast();

  // 새 에러 발생 시 Toast 알림
  useEffect(() => {
    if (errors.length > 0) {
      const latestError = errors[0];

      // Toast 알림 표시
      toast({
        variant: latestError.severity === "critical" ? "destructive" : "default",
        title: `🚨 ${getSeverityName(latestError.severity)}`,
        description: `[${latestError.source}] ${latestError.message}`,
        duration: latestError.severity === "critical" ? 10000 : 5000,
      });
    }
  }, [errors.length]); // errors.length 변경 시에만 실행

  const getSeverityIcon = (severity: ErrorEvent["severity"]) => {
    switch (severity) {
      case "warning":
        return "⚠️";
      case "error":
        return "❌";
      case "critical":
        return "🔴";
    }
  };

  const getSeverityColor = (severity: ErrorEvent["severity"]) => {
    switch (severity) {
      case "warning":
        return "bg-yellow-50 border-yellow-200 text-yellow-800";
      case "error":
        return "bg-red-50 border-red-200 text-red-800";
      case "critical":
        return "bg-red-100 border-red-300 text-red-900";
    }
  };

  const getSeverityName = (severity: ErrorEvent["severity"]) => {
    switch (severity) {
      case "warning":
        return "경고";
      case "error":
        return "에러";
      case "critical":
        return "치명적 에러";
    }
  };

  // 심각도별 통계
  const warningCount = errors.filter((e) => e.severity === "warning").length;
  const errorCount = errors.filter((e) => e.severity === "error").length;
  const criticalCount = errors.filter((e) => e.severity === "critical").length;

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
        <span>🚨</span> 에러 로그 (최근 100개)
      </h2>

      {/* 에러 통계 */}
      {errors.length > 0 && (
        <div className="grid grid-cols-3 gap-3 mb-6">
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-yellow-700">{warningCount}</div>
            <div className="text-xs text-yellow-600">⚠️ 경고</div>
          </div>
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-red-700">{errorCount}</div>
            <div className="text-xs text-red-600">❌ 에러</div>
          </div>
          <div className="bg-red-100 border border-red-300 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-red-900">{criticalCount}</div>
            <div className="text-xs text-red-800">🔴 치명적</div>
          </div>
        </div>
      )}

      {/* 에러 목록 */}
      {errors.length > 0 ? (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {errors.slice(0, 10).map((error, index) => (
            <div
              key={`${error.timestamp}-${index}`}
              className={`border rounded-lg p-3 ${getSeverityColor(error.severity)}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-2 flex-1">
                  <span className="text-lg">{getSeverityIcon(error.severity)}</span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-semibold text-sm">
                        [{getSeverityName(error.severity)}]
                      </span>
                      <span className="text-xs bg-white bg-opacity-50 px-2 py-1 rounded">
                        {error.source}
                      </span>
                    </div>
                    <div className="text-sm">{error.message}</div>
                    {error.details && (
                      <div className="mt-2 text-xs font-mono bg-white bg-opacity-30 p-2 rounded">
                        {typeof error.details === "string"
                          ? error.details
                          : JSON.stringify(error.details, null, 2)}
                      </div>
                    )}
                  </div>
                </div>
                <div className="text-xs text-right whitespace-nowrap ml-4">
                  {new Date(error.timestamp).toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center text-gray-500 py-8">
          <p className="text-green-600 font-semibold">✨ 에러가 없습니다!</p>
          <p className="text-sm mt-2 text-gray-500">모든 시스템이 정상적으로 작동 중입니다.</p>
        </div>
      )}

      {/* 모든 에러 보기 링크 (나중에 구현) */}
      {errors.length > 10 && (
        <div className="mt-4 text-center">
          <button
            className="text-sm text-blue-600 hover:text-blue-800 font-semibold"
            onClick={() => {
              // TODO: 전체 에러 로그 모달 열기
              alert(`총 ${errors.length}개의 에러가 있습니다.`);
            }}
          >
            모든 에러 보기 ({errors.length}개) →
          </button>
        </div>
      )}
    </div>
  );
}
