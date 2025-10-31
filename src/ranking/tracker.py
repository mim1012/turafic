"""
순위 추적 데이터 관리 모듈
"""
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from config.settings import config
from src.utils.logger import log
from src.utils.helpers import calculate_rank_change, get_timestamp


class RankTracker:
    """순위 추적 데이터 관리 클래스"""

    def __init__(self, product_id: str):
        self.product_id = product_id
        self.data_file = config.RANKINGS_DIR / f"rank_history_{product_id}.json"
        self.history: List[Dict[str, Any]] = []
        self._ensure_data_dir()
        self._load_history()

    def _ensure_data_dir(self):
        """데이터 디렉토리 생성"""
        config.RANKINGS_DIR.mkdir(parents=True, exist_ok=True)

    def _load_history(self):
        """기존 히스토리 로드"""
        if self.data_file.exists():
            try:
                with open(self.data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.history = data.get("history", [])
                log.info(f"순위 히스토리 로드 완료: {len(self.history)}개 기록")
            except Exception as e:
                log.error(f"히스토리 로드 실패: {e}")
                self.history = []
        else:
            log.info(f"새 순위 추적 파일 생성: {self.product_id}")

    def _save_history(self):
        """히스토리 저장"""
        try:
            data = {
                "product_id": self.product_id,
                "total_records": len(self.history),
                "last_updated": get_timestamp(),
                "history": self.history,
            }

            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            log.debug(f"순위 히스토리 저장 완료: {self.data_file}")

        except Exception as e:
            log.error(f"히스토리 저장 실패: {e}")

    def add_record(
        self,
        rank_info: Optional[Dict[str, Any]],
        iteration: int,
        test_case_id: int,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        순위 기록 추가

        Args:
            rank_info: 순위 정보 (check_product_rank 결과)
            iteration: 반복 횟수 (1-100)
            test_case_id: 테스트 케이스 ID
            notes: 메모

        Returns:
            저장된 레코드
        """
        record = {
            "iteration": iteration,
            "test_case_id": test_case_id,
            "rank_info": rank_info,
            "timestamp": get_timestamp(),
            "notes": notes,
        }

        # 이전 순위와 비교
        if rank_info and len(self.history) > 0:
            prev_record = self.history[-1]
            prev_rank_info = prev_record.get("rank_info")

            if prev_rank_info:
                prev_rank = prev_rank_info.get("absolute_rank", 0)
                curr_rank = rank_info.get("absolute_rank", 0)
                rank_change = calculate_rank_change(prev_rank, curr_rank)

                record["rank_change"] = rank_change
                record["rank_improved"] = rank_change < 0

                if rank_change < 0:
                    log.success(f"순위 상승: {prev_rank}위 → {curr_rank}위 ({abs(rank_change)}위 상승)")
                elif rank_change > 0:
                    log.warning(f"순위 하락: {prev_rank}위 → {curr_rank}위 ({rank_change}위 하락)")
                else:
                    log.info(f"순위 유지: {curr_rank}위")

        self.history.append(record)
        self._save_history()

        log.info(f"순위 기록 추가: iteration={iteration}, 총 {len(self.history)}개 기록")
        return record

    def get_latest_rank(self) -> Optional[Dict[str, Any]]:
        """최신 순위 정보 반환"""
        if not self.history:
            return None

        return self.history[-1].get("rank_info")

    def get_rank_at_iteration(self, iteration: int) -> Optional[Dict[str, Any]]:
        """특정 반복 차수의 순위 정보 반환"""
        for record in reversed(self.history):
            if record.get("iteration") == iteration:
                return record.get("rank_info")
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """순위 통계 계산"""
        if not self.history:
            return {
                "total_records": 0,
                "error": "데이터 없음",
            }

        # 유효한 순위 데이터만 추출
        valid_ranks = [
            record["rank_info"]["absolute_rank"]
            for record in self.history
            if record.get("rank_info") is not None
        ]

        if not valid_ranks:
            return {
                "total_records": len(self.history),
                "valid_records": 0,
                "error": "유효한 순위 데이터 없음",
            }

        # 통계 계산
        import statistics

        stats = {
            "total_records": len(self.history),
            "valid_records": len(valid_ranks),
            "best_rank": min(valid_ranks),
            "worst_rank": max(valid_ranks),
            "average_rank": round(statistics.mean(valid_ranks), 2),
            "median_rank": statistics.median(valid_ranks),
            "rank_range": max(valid_ranks) - min(valid_ranks),
        }

        # 순위 변동 계산
        rank_changes = []
        for i in range(1, len(self.history)):
            prev_info = self.history[i - 1].get("rank_info")
            curr_info = self.history[i].get("rank_info")

            if prev_info and curr_info:
                prev_rank = prev_info.get("absolute_rank", 0)
                curr_rank = curr_info.get("absolute_rank", 0)
                rank_changes.append(calculate_rank_change(prev_rank, curr_rank))

        if rank_changes:
            stats["total_improvements"] = sum(1 for c in rank_changes if c < 0)
            stats["total_declines"] = sum(1 for c in rank_changes if c > 0)
            stats["total_unchanged"] = sum(1 for c in rank_changes if c == 0)
            stats["average_change"] = round(statistics.mean(rank_changes), 2)

        # 첫 번째와 마지막 순위 비교
        first_rank = self.history[0].get("rank_info", {}).get("absolute_rank")
        last_rank = self.history[-1].get("rank_info", {}).get("absolute_rank")

        if first_rank and last_rank:
            total_change = calculate_rank_change(first_rank, last_rank)
            stats["first_rank"] = first_rank
            stats["last_rank"] = last_rank
            stats["total_change"] = total_change
            stats["overall_improved"] = total_change < 0

        return stats

    def export_to_csv(self, output_path: Optional[Path] = None) -> Path:
        """CSV 파일로 내보내기"""
        import csv

        if output_path is None:
            output_path = config.RESULTS_DIR / f"rank_history_{self.product_id}.csv"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)

                # 헤더
                writer.writerow([
                    "반복",
                    "테스트케이스ID",
                    "키워드",
                    "페이지",
                    "위치",
                    "절대순위",
                    "순위변동",
                    "개선여부",
                    "상품명",
                    "확인일시",
                    "메모",
                ])

                # 데이터
                for record in self.history:
                    rank_info = record.get("rank_info")
                    if rank_info:
                        writer.writerow([
                            record.get("iteration", ""),
                            record.get("test_case_id", ""),
                            rank_info.get("keyword", ""),
                            rank_info.get("page", ""),
                            rank_info.get("position", ""),
                            rank_info.get("absolute_rank", ""),
                            record.get("rank_change", ""),
                            "O" if record.get("rank_improved") else "X",
                            rank_info.get("product_name", ""),
                            rank_info.get("checked_at", ""),
                            record.get("notes", ""),
                        ])
                    else:
                        writer.writerow([
                            record.get("iteration", ""),
                            record.get("test_case_id", ""),
                            "",
                            "",
                            "",
                            "순위권밖",
                            "",
                            "",
                            "",
                            record.get("timestamp", ""),
                            record.get("notes", ""),
                        ])

            log.success(f"CSV 내보내기 완료: {output_path}")
            return output_path

        except Exception as e:
            log.error(f"CSV 내보내기 실패: {e}")
            raise


# 편의 함수
def get_tracker(product_id: str) -> RankTracker:
    """RankTracker 인스턴스 생성 편의 함수"""
    return RankTracker(product_id)


if __name__ == "__main__":
    # 테스트
    tracker = RankTracker("12345678")

    # 가짜 순위 데이터 추가
    for i in range(1, 6):
        fake_rank_info = {
            "product_id": "12345678",
            "keyword": "무선 이어폰",
            "page": 3,
            "position": 15 - i,  # 점진적 상승
            "absolute_rank": 55 - i,
            "product_name": "테스트 상품",
            "product_url": "https://shopping.naver.com/products/12345678",
            "checked_at": get_timestamp(),
        }

        tracker.add_record(fake_rank_info, i, test_case_id=1)

    # 통계 출력
    stats = tracker.get_statistics()
    print("\n=== 순위 통계 ===")
    for key, value in stats.items():
        print(f"{key}: {value}")

    # CSV 내보내기 테스트
    # tracker.export_to_csv()
