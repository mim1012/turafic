# Turafic 실시간 모니터링 대시보드

네이버 쇼핑 순위 조작 프로젝트 **Turafic**의 실시간 모니터링 대시보드입니다.

## 🚀 기능

### 실시간 모니터링
- ✅ **WebSocket 기반** 실시간 업데이트
- ✅ **봇 상태** 모니터링 (22개 봇)
- ✅ **캠페인 진행률** 추적 (18개 테스트 케이스)
- ✅ **순위 변동** 차트
- ✅ **이벤트 로그** 스트리밍

### 주요 화면
1. **메인 대시보드**: 캠페인 개요, 봇 상태, 순위 변동, 최근 이벤트
2. **봇 상태 모니터링**: 22개 봇의 실시간 상태 및 진행률
3. **캠페인 진행률**: 18개 테스트 케이스별 진행률 및 순위 개선도
4. **실시간 로그**: 모든 에이전트의 로그 스트리밍

## 🛠️ 기술 스택

- **Framework**: React 18 + TypeScript
- **상태 관리**: Zustand
- **UI 라이브러리**: Material-UI (MUI)
- **차트**: Chart.js + react-chartjs-2
- **WebSocket**: native WebSocket API
- **HTTP 클라이언트**: Axios
- **빌드 도구**: Vite

## 📦 설치

```bash
# 패키지 설치
pnpm install
```

## 🔧 환경 변수 설정

`.env` 파일을 생성하고 다음 내용을 입력합니다:

```env
# API 서버 URL
VITE_API_URL=http://localhost:8000/api/v1

# WebSocket URL
VITE_WS_URL=ws://localhost:8000/ws/dashboard
```

## 🚀 실행

### 개발 모드
```bash
pnpm dev
```

브라우저에서 `http://localhost:3000`으로 접속합니다.

### 프로덕션 빌드
```bash
pnpm build
```

## 📁 프로젝트 구조

```
dashboard/
├── src/
│   ├── components/        # React 컴포넌트
│   ├── hooks/             # Custom Hooks
│   ├── stores/            # Zustand 스토어
│   ├── services/          # API 서비스
│   ├── types/             # TypeScript 타입
│   ├── App.tsx
│   └── main.tsx
├── .env                   # 환경 변수
└── package.json
```

## 📚 관련 문서

- [ARCHITECTURE_OVERVIEW.md](../docs/ARCHITECTURE_OVERVIEW.md) - 전체 아키텍처
- [DASHBOARD_DESIGN.md](../docs/DASHBOARD_DESIGN.md) - 대시보드 설계
- [CLAUDE.md](../CLAUDE.md) - 프로젝트 전체 개요

---

**Turafic** - 네이버 쇼핑 순위 조작 프로젝트
