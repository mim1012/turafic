"""
Ranking Scheduler (12시간 주기)
롤링 윈도우 방식으로 243개 케이스 순위 체크
"""

import time
import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from .task_engine import load_test_matrix
from src.ranking.checker import RankChecker
from src.utils.helpers import calculate_rank_change


class RankingScheduler:
    """12시간 주기 순위 체크 스케줄러"""

    def __init__(
        self,
        product_keyword: str,
        campaign_id: Optional[str] = None,
        product_id: Optional[str] = None,
        batch_size: int = 27,
        delay_hours: int = 12,
        db_session=None  # AsyncSession for DB operations
    ):
        self.product_keyword = product_keyword
        self.campaign_id = campaign_id or str(uuid.uuid4())
        self.product_id = product_id
        self.batch_size = batch_size
        self.delay_seconds = delay_hours * 3600
        self.db_session = db_session
        self.rank_checker = RankChecker()
        self.batches = self._create_batches()
        
    def _create_batches(self) -> List[List[Dict]]:
        """243개 케이스를 27개씩 9개 배치로 분할"""
        all_cases = load_test_matrix()
        batches = []
        for i in range(0, len(all_cases), self.batch_size):
            batches.append(all_cases[i:i + self.batch_size])
        return batches
    
    def run(self):
        """메인 실행 루프 - 5일간 실행"""
        print(f"[Ranking Scheduler] 시작: {datetime.now()}")
        print(f"총 배치 수: {len(self.batches)}")
        print(f"배치당 케이스 수: {self.batch_size}")
        print(f"측정 주기: {self.delay_seconds // 3600}시간")
        
        # 초기 순위 측정
        baseline_rank = self._check_product_rank()
        self._log_rank("baseline", baseline_rank)
        print(f"초기 순위: {baseline_rank}위")
        
        for batch_num, batch_cases in enumerate(self.batches, 1):
            print(f"
[Batch {batch_num}/{len(self.batches)}] 트래픽 발생 중...")
            
            # 배치 내 모든 케이스 트래픽 발생
            for test_case in batch_cases:
                self._execute_traffic(test_case)
            
            print(f"[Batch {batch_num}] 완료. 12시간 대기 중...")
            time.sleep(self.delay_seconds)
            
            # 순위 측정
            current_rank = self._check_product_rank()
            self._log_rank(f"batch_{batch_num}", current_rank)
            print(f"[Batch {batch_num}] 순위: {current_rank}위 (변동: {baseline_rank - current_rank:+d})")
            
            # 결과 저장
            self._save_batch_results(batch_num, batch_cases, baseline_rank, current_rank)
        
        print(f"
[Ranking Scheduler] 완료: {datetime.now()}")
    
    def _execute_traffic(self, test_case: Dict):
        """단일 케이스 트래픽 100회 발생"""
        print(f"  - {test_case['test_case_id']}: ", end="", flush=True)
        
        for i in range(100):
            # TODO: 실제 트래픽 발생 로직 연동
            # perform_traffic_action(test_case)
            # toggle_airplane_mode()
            time.sleep(random.randint(60, 180))  # 1-3분 간격
            
            if (i + 1) % 20 == 0:
                print(f"{i+1}", end="", flush=True)
            elif (i + 1) % 10 == 0:
                print(".", end="", flush=True)
        
        print(" OK")
    
    def _check_product_rank(self) -> Optional[int]:
        """상품 순위 체크 (실제 네이버 쇼핑 크롤링)"""
        try:
            rank_info = self.rank_checker.check_product_rank(
                keyword=self.product_keyword,
                product_id=self.product_id,
                max_pages=10  # 최대 10페이지 (200위) 검색
            )

            if rank_info and rank_info.get("product_id"):
                rank = rank_info["absolute_rank"]
                print(f"✅ 순위 측정 성공: {rank}위 (페이지 {rank_info['page']}, 위치 {rank_info['position']})")

                # DB에 저장 (선택적)
                if self.db_session:
                    self._save_rank_to_db(rank_info)

                return rank
            else:
                print(f"⚠️  상품을 찾지 못함 (키워드: {self.product_keyword})")
                return None

        except Exception as e:
            print(f"❌ 순위 체크 실패: {e}")
            return None
    
    def _log_rank(self, label: str, rank: int):
        """순위 로그 기록"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {label}: {rank}위
"
        
        with open("ranking_log.txt", "a", encoding="utf-8") as f:
            f.write(log_entry)
    
    def _save_rank_to_db(self, rank_info: Dict):
        """순위를 DB에 저장 (비동기 세션 필요)"""
        # TODO: 실제 구현 시 AsyncSession 사용
        # 현재는 스케줄러가 동기 실행이므로 DB 저장은 별도 처리 필요
        pass

    def _save_batch_results(self, batch_num: int, batch_cases: List[Dict], baseline: int, current: int):
        """배치 결과 저장 (JSON 파일 + DB)"""
        result = {
            "batch_num": batch_num,
            "timestamp": datetime.now().isoformat(),
            "baseline_rank": baseline,
            "current_rank": current,
            "rank_change": calculate_rank_change(baseline, current),
            "test_cases": [tc["test_case_id"] for tc in batch_cases]
        }

        # JSON 파일 백업
        import json
        with open(f"batch_{batch_num}_results.json", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        print(f"  결과 저장: batch_{batch_num}_results.json")

        # DB 저장 (선택적)
        if self.db_session:
            # TODO: BatchExecution 테이블에 저장
            pass


def run_ranking_test(product_keyword: str):
    """랭킹 테스트 실행 진입점"""
    scheduler = RankingScheduler(product_keyword=product_keyword)
    scheduler.run()


if __name__ == "__main__":
    run_ranking_test("프로틴 쉐이크")
