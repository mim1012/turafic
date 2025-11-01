"""
Product Management API
상품 등록, 조회, 수정, 삭제 및 순위 관리 API
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from datetime import datetime
from typing import List, Optional
import uuid

from server.core.database import get_session

router = APIRouter()

# ==================== 요청/응답 모델 ====================

class ProductCreateRequest(BaseModel):
    """상품 등록 요청"""
    keyword: str  # 검색 키워드
    naver_product_id: str  # 네이버 상품 ID
    product_name: str  # 상품명
    product_url: str  # 상품 URL

    # 선택적 메타데이터
    category: Optional[str] = None
    brand: Optional[str] = None
    price: Optional[int] = None
    original_price: Optional[int] = None
    discount_rate: Optional[int] = None
    notes: Optional[str] = None


class ProductUpdateRequest(BaseModel):
    """상품 정보 수정 요청"""
    keyword: Optional[str] = None
    product_name: Optional[str] = None
    product_url: Optional[str] = None
    category: Optional[str] = None
    brand: Optional[str] = None
    price: Optional[int] = None
    status: Optional[str] = None
    is_target: Optional[bool] = None
    notes: Optional[str] = None


class RankUpdateRequest(BaseModel):
    """순위 업데이트 요청"""
    rank: int  # 전체 순위 (1부터 시작)
    page: int  # 페이지 번호 (1부터 시작)
    position: int  # 페이지 내 위치 (1-20)
    checked_by: Optional[str] = None  # 체크한 봇 ID
    campaign_id: Optional[str] = None  # 연관 캠페인 ID


class ProductResponse(BaseModel):
    """상품 정보 응답"""
    product_id: str
    keyword: str
    naver_product_id: str
    product_name: str
    product_url: str

    category: Optional[str]
    brand: Optional[str]
    price: Optional[int]

    current_rank: Optional[int]
    initial_rank: Optional[int]
    rank_improvement: Optional[int]

    status: str
    is_target: bool

    total_traffic_count: int
    total_rank_checks: int

    created_at: str
    updated_at: str


class RankHistoryResponse(BaseModel):
    """순위 히스토리 응답"""
    id: int
    product_id: str
    rank: int
    page: int
    position: int
    keyword: str
    checked_by: Optional[str]
    campaign_id: Optional[str]
    checked_at: str


# ==================== API 엔드포인트 ====================

@router.post("/products", status_code=201)
async def create_product(
    request: ProductCreateRequest,
    session: AsyncSession = Depends(get_session)
):
    """
    새 상품 등록

    핵심 5가지 파라미터:
    1. keyword: 검색 키워드
    2. naver_product_id: 네이버 상품 ID
    3. product_name: 상품명
    4. product_url: 상품 URL
    5. (campaign_id는 별도 캠페인 생성 시 연결)
    """
    # 중복 체크 (naver_product_id 기준)
    result = await session.execute(
        text("SELECT product_id FROM products WHERE naver_product_id = :nid"),
        {"nid": request.naver_product_id}
    )
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Product with naver_product_id '{request.naver_product_id}' already exists"
        )

    # 상품 등록
    product_id = str(uuid.uuid4())

    await session.execute(
        text("""
            INSERT INTO products (
                product_id, keyword, naver_product_id, product_name, product_url,
                category, brand, price, original_price, discount_rate, notes,
                status, created_by, created_at, updated_at
            )
            VALUES (
                :pid, :keyword, :nid, :pname, :purl,
                :category, :brand, :price, :oprice, :discount, :notes,
                'active', 'api', NOW(), NOW()
            )
        """),
        {
            "pid": product_id,
            "keyword": request.keyword,
            "nid": request.naver_product_id,
            "pname": request.product_name,
            "purl": request.product_url,
            "category": request.category,
            "brand": request.brand,
            "price": request.price,
            "oprice": request.original_price,
            "discount": request.discount_rate,
            "notes": request.notes
        }
    )

    await session.commit()

    return {
        "product_id": product_id,
        "message": "Product created successfully",
        "next_steps": [
            f"Create campaign: POST /api/v1/campaigns (with product_id={product_id})",
            f"Check rank: POST /api/v1/products/{product_id}/rank",
            f"View product: GET /api/v1/products/{product_id}"
        ]
    }


@router.get("/products/{product_id}")
async def get_product(
    product_id: str,
    session: AsyncSession = Depends(get_session)
):
    """상품 상세 정보 조회"""
    result = await session.execute(
        text("""
            SELECT
                product_id, keyword, naver_product_id, product_name, product_url,
                category, brand, price, original_price, discount_rate,
                current_rank, initial_rank, best_rank, worst_rank, rank_improvement,
                status, is_target,
                total_traffic_count, total_rank_checks,
                created_at, updated_at, last_rank_check_at, notes
            FROM products
            WHERE product_id = :pid
        """),
        {"pid": product_id}
    )
    product = result.mappings().one_or_none()

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    return {
        **dict(product),
        "created_at": product["created_at"].isoformat() if product["created_at"] else None,
        "updated_at": product["updated_at"].isoformat() if product["updated_at"] else None,
        "last_rank_check_at": product["last_rank_check_at"].isoformat() if product["last_rank_check_at"] else None
    }


@router.get("/products")
async def list_products(
    status: Optional[str] = Query(None, description="Filter by status: active, inactive, testing, completed"),
    keyword: Optional[str] = Query(None, description="Filter by keyword (partial match)"),
    is_target: Optional[bool] = Query(None, description="Filter by target status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session)
):
    """상품 목록 조회 (필터링 및 페이지네이션)"""

    # Build query
    where_clauses = []
    params = {"limit": limit, "offset": offset}

    if status:
        where_clauses.append("status = :status")
        params["status"] = status

    if keyword:
        where_clauses.append("keyword ILIKE :keyword")
        params["keyword"] = f"%{keyword}%"

    if is_target is not None:
        where_clauses.append("is_target = :is_target")
        params["is_target"] = is_target

    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

    # Count total
    count_result = await session.execute(
        text(f"SELECT COUNT(*) FROM products WHERE {where_sql}"),
        params
    )
    total = count_result.scalar()

    # Fetch products
    result = await session.execute(
        text(f"""
            SELECT
                product_id, keyword, naver_product_id, product_name, product_url,
                category, brand, price,
                current_rank, initial_rank, rank_improvement,
                status, is_target,
                total_traffic_count, total_rank_checks,
                created_at
            FROM products
            WHERE {where_sql}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        params
    )
    products = result.mappings().all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "products": [
            {
                **dict(p),
                "created_at": p["created_at"].isoformat() if p["created_at"] else None
            }
            for p in products
        ]
    }


@router.patch("/products/{product_id}")
async def update_product(
    product_id: str,
    request: ProductUpdateRequest,
    session: AsyncSession = Depends(get_session)
):
    """상품 정보 수정"""

    # Check product exists
    result = await session.execute(
        text("SELECT product_id FROM products WHERE product_id = :pid"),
        {"pid": product_id}
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Product not found")

    # Build update query
    updates = []
    params = {"pid": product_id}

    if request.keyword is not None:
        updates.append("keyword = :keyword")
        params["keyword"] = request.keyword

    if request.product_name is not None:
        updates.append("product_name = :pname")
        params["pname"] = request.product_name

    if request.product_url is not None:
        updates.append("product_url = :purl")
        params["purl"] = request.product_url

    if request.category is not None:
        updates.append("category = :category")
        params["category"] = request.category

    if request.brand is not None:
        updates.append("brand = :brand")
        params["brand"] = request.brand

    if request.price is not None:
        updates.append("price = :price")
        params["price"] = request.price

    if request.status is not None:
        updates.append("status = :status")
        params["status"] = request.status

    if request.is_target is not None:
        updates.append("is_target = :is_target")
        params["is_target"] = request.is_target

    if request.notes is not None:
        updates.append("notes = :notes")
        params["notes"] = request.notes

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates.append("updated_at = NOW()")

    await session.execute(
        text(f"UPDATE products SET {', '.join(updates)} WHERE product_id = :pid"),
        params
    )
    await session.commit()

    return {"message": "Product updated successfully"}


@router.delete("/products/{product_id}")
async def delete_product(
    product_id: str,
    session: AsyncSession = Depends(get_session)
):
    """상품 삭제 (소프트 삭제 - status를 'inactive'로 변경)"""

    result = await session.execute(
        text("UPDATE products SET status = 'inactive', updated_at = NOW() WHERE product_id = :pid RETURNING product_id"),
        {"pid": product_id}
    )
    deleted = result.scalar_one_or_none()

    if not deleted:
        raise HTTPException(status_code=404, detail="Product not found")

    await session.commit()

    return {"message": "Product deactivated successfully"}


@router.post("/products/{product_id}/rank")
async def update_product_rank(
    product_id: str,
    request: RankUpdateRequest,
    session: AsyncSession = Depends(get_session)
):
    """
    상품 순위 업데이트

    순위 계산 공식:
    rank = (page - 1) × 20 + position
    예: 3페이지 5번째 → (3-1)×20+5 = 45위
    """

    # Check product exists
    result = await session.execute(
        text("SELECT product_id FROM products WHERE product_id = :pid"),
        {"pid": product_id}
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Product not found")

    # Call stored function
    await session.execute(
        text("""
            SELECT update_product_rank(
                :pid, :rank, :page, :position, :checked_by, :campaign_id
            )
        """),
        {
            "pid": product_id,
            "rank": request.rank,
            "page": request.page,
            "position": request.position,
            "checked_by": request.checked_by,
            "campaign_id": request.campaign_id
        }
    )
    await session.commit()

    # Get updated product
    result = await session.execute(
        text("""
            SELECT current_rank, initial_rank, rank_improvement, best_rank, worst_rank
            FROM products WHERE product_id = :pid
        """),
        {"pid": product_id}
    )
    product = result.mappings().one()

    return {
        "message": "Rank updated successfully",
        "current_rank": product["current_rank"],
        "initial_rank": product["initial_rank"],
        "rank_improvement": product["rank_improvement"],
        "best_rank": product["best_rank"],
        "worst_rank": product["worst_rank"]
    }


@router.get("/products/{product_id}/rank/history")
async def get_rank_history(
    product_id: str,
    days: int = Query(7, ge=1, le=90, description="Number of days to retrieve"),
    session: AsyncSession = Depends(get_session)
):
    """상품 순위 히스토리 조회"""

    # Check product exists
    result = await session.execute(
        text("SELECT product_id FROM products WHERE product_id = :pid"),
        {"pid": product_id}
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Product not found")

    # Get rank trend
    result = await session.execute(
        text("SELECT * FROM get_rank_trend(:pid, :days)"),
        {"pid": product_id, "days": days}
    )
    trend = result.mappings().all()

    # Get detailed history
    result = await session.execute(
        text("""
            SELECT
                id, product_id, rank, page, position, keyword,
                checked_by, campaign_id, checked_at
            FROM product_rank_history
            WHERE product_id = :pid
            ORDER BY checked_at DESC
            LIMIT 100
        """),
        {"pid": product_id}
    )
    history = result.mappings().all()

    return {
        "product_id": product_id,
        "trend": [
            {
                **dict(t),
                "check_date": t["check_date"].isoformat() if t["check_date"] else None
            }
            for t in trend
        ],
        "history": [
            {
                **dict(h),
                "checked_at": h["checked_at"].isoformat() if h["checked_at"] else None
            }
            for h in history
        ]
    }


@router.get("/products/{product_id}/stats")
async def get_product_stats(
    product_id: str,
    session: AsyncSession = Depends(get_session)
):
    """상품 통계 조회 (캠페인, 트래픽, 순위 등)"""

    result = await session.execute(
        text("SELECT * FROM product_stats WHERE product_id = :pid"),
        {"pid": product_id}
    )
    stats = result.mappings().one_or_none()

    if not stats:
        raise HTTPException(status_code=404, detail="Product not found")

    return {
        **dict(stats),
        "last_rank_check_at": stats["last_rank_check_at"].isoformat() if stats["last_rank_check_at"] else None
    }


@router.get("/products/stats/summary")
async def get_products_summary(
    session: AsyncSession = Depends(get_session)
):
    """전체 상품 요약 통계"""

    result = await session.execute(text("""
        SELECT
            COUNT(*) AS total_products,
            COUNT(CASE WHEN status = 'active' THEN 1 END) AS active_products,
            COUNT(CASE WHEN is_target = TRUE THEN 1 END) AS target_products,
            SUM(total_traffic_count) AS total_traffic,
            SUM(total_rank_checks) AS total_rank_checks,
            AVG(CASE WHEN current_rank IS NOT NULL THEN current_rank END) AS avg_current_rank,
            COUNT(CASE WHEN rank_improvement < 0 THEN 1 END) AS products_improved
        FROM products
    """))
    summary = result.mappings().one()

    return dict(summary)
