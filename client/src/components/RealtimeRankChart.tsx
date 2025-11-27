import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";

interface RankUpdateEvent {
  campaignId: number;
  keyword: string;
  productName: string;
  rank: number;
  previousRank?: number;
  timestamp: string;
}

interface Props {
  rankHistory: RankUpdateEvent[];
}

export function RealtimeRankChart({ rankHistory }: Props) {
  // 차트 데이터 준비 (최근 20개)
  const chartData = rankHistory
    .slice(0, 20)
    .reverse() // 시간 순서대로
    .map((event, index) => ({
      index,
      time: new Date(event.timestamp).toLocaleTimeString(),
      rank: event.rank,
      productName: event.productName,
      keyword: event.keyword,
    }));

  // 최신 순위 정보
  const latestRank = rankHistory.length > 0 ? rankHistory[0] : null;

  // 순위 변화 계산
  const rankChange =
    latestRank && latestRank.previousRank
      ? latestRank.previousRank - latestRank.rank
      : null;

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
        <span>📈</span> 순위 변동 (실시간)
      </h2>

      {/* 최신 순위 정보 */}
      {latestRank && (
        <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-semibold text-lg">{latestRank.productName}</div>
              <div className="text-sm text-gray-600">키워드: {latestRank.keyword}</div>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-blue-700">{latestRank.rank}위</div>
              {rankChange !== null && (
                <div
                  className={`text-sm font-semibold ${
                    rankChange > 0
                      ? "text-green-600"
                      : rankChange < 0
                      ? "text-red-600"
                      : "text-gray-600"
                  }`}
                >
                  {rankChange > 0 && "↑ "}
                  {rankChange < 0 && "↓ "}
                  {rankChange === 0 && "→ "}
                  {Math.abs(rankChange)}위
                  {rankChange > 0 && " 상승"}
                  {rankChange < 0 && " 하락"}
                  {rankChange === 0 && " 변동 없음"}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Recharts 라인 차트 */}
      {chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" tick={{ fontSize: 12 }} />
            <YAxis
              reversed
              domain={[1, "auto"]}
              label={{ value: "순위", angle: -90, position: "insideLeft" }}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                    <div className="bg-white p-3 border border-gray-300 rounded shadow-lg">
                      <p className="font-semibold">{data.productName}</p>
                      <p className="text-sm text-gray-600">키워드: {data.keyword}</p>
                      <p className="text-lg font-bold text-blue-700">{data.rank}위</p>
                      <p className="text-xs text-gray-500">{data.time}</p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Legend />
            <Line
              type="monotone"
              dataKey="rank"
              stroke="#2563eb"
              strokeWidth={2}
              dot={{ r: 4 }}
              activeDot={{ r: 6 }}
              name="순위"
            />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <div className="text-center text-gray-500 py-12">
          <p>아직 순위 데이터가 없습니다.</p>
          <p className="text-sm mt-2">순위 체크가 시작되면 자동으로 표시됩니다.</p>
        </div>
      )}

      {/* 순위 기록 목록 */}
      {rankHistory.length > 0 && (
        <div className="mt-6">
          <h3 className="font-semibold mb-2 text-gray-700">최근 순위 기록 (최대 10개)</h3>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {rankHistory.slice(0, 10).map((event, index) => {
              const change =
                event.previousRank !== undefined
                  ? event.previousRank - event.rank
                  : null;

              return (
                <div
                  key={`${event.campaignId}-${event.timestamp}-${index}`}
                  className="flex items-center justify-between text-sm p-2 bg-gray-50 rounded"
                >
                  <div className="flex-1">
                    <span className="font-semibold">{event.productName}</span>
                    <span className="text-gray-500 ml-2 text-xs">
                      ({event.keyword})
                    </span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="font-bold text-blue-700">{event.rank}위</span>
                    {change !== null && (
                      <span
                        className={`text-xs font-semibold ${
                          change > 0
                            ? "text-green-600"
                            : change < 0
                            ? "text-red-600"
                            : "text-gray-600"
                        }`}
                      >
                        {change > 0 && "↑"}
                        {change < 0 && "↓"}
                        {change === 0 && "→"}
                        {Math.abs(change)}
                      </span>
                    )}
                    <span className="text-xs text-gray-500">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
