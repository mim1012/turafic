/**
 * ProfileManager - PBR 멀티 프로필 관리
 *
 * 기능:
 * - 프로필 생성/저장/로드
 * - MID 쿼터 관리 (프로필당 동일 MID 2회 제한)
 * - 프로필 로테이션 (사용 가능한 프로필 선택)
 */

import * as fs from 'fs';
import * as path from 'path';
import { FingerprintProfile } from '../fingerprint/types';

export interface ProfileData {
  id: string;
  userDataDir: string;
  fingerprint: FingerprintProfile;
  warmedUp: boolean;
  lastUsed: string;  // ISO date string
  midQuota: Record<string, number>;  // MID별 사용 횟수
}

const MID_QUOTA_PER_PROFILE = 2;
const PROFILES_DIR = path.join(process.cwd(), 'profiles');
const FINGERPRINT_DIR = path.join(process.cwd(), 'server', 'services', 'traffic', 'profiles');

// version → 파일 매핑
const VERSION_FILE_MAP: Record<string, string> = {
  'v7': 'v7-samsung-s23.json',
  'v8': 'v8-iphone-15-pro.json',
  'v9': 'v9-samsung-s24-ultra.json',
  'v10': 'v10-xiaomi-13-pro.json',
  'v11': 'v11-iphone-14-pro-max.json',
  'v12': 'v12-oppo-find-x5-pro.json',
  'v13': 'v13-google-pixel-8-pro.json',
  'v14': 'v14-oneplus-11.json',
  'v15': 'v15-vivo-x90-pro.json',
  'v16': 'v16-samsung-z-fold5.json',
  'v17': 'v17-iphone-13-pro.json',
  'v18': 'v18-asus-rog-phone-7.json',
  'v19': 'v19-samsung-a54.json',
  'v20': 'v20-motorola-edge-40-pro.json',
};

export class ProfileManager {
  private profiles: ProfileData[] = [];
  private currentIndex: number = 0;

  constructor() {
    // 프로필 디렉토리 생성
    if (!fs.existsSync(PROFILES_DIR)) {
      fs.mkdirSync(PROFILES_DIR, { recursive: true });
    }
  }

  /**
   * 저장된 프로필 로드
   */
  async loadProfiles(): Promise<void> {
    const dirs = fs.readdirSync(PROFILES_DIR).filter(dir =>
      dir.startsWith('profile-') &&
      fs.statSync(path.join(PROFILES_DIR, dir)).isDirectory()
    );

    this.profiles = [];

    for (const dir of dirs) {
      const metadataPath = path.join(PROFILES_DIR, dir, 'metadata.json');
      if (fs.existsSync(metadataPath)) {
        try {
          const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf-8'));
          this.profiles.push(metadata);
        } catch (e) {
          console.warn(`Failed to load profile ${dir}:`, e);
        }
      }
    }

    console.log(`[ProfileManager] Loaded ${this.profiles.length} profiles`);
  }

  /**
   * Fingerprint JSON 파일 로드
   */
  private loadFingerprint(version: string): FingerprintProfile {
    const fileName = VERSION_FILE_MAP[version];
    if (!fileName) {
      throw new Error(`Unknown version: ${version}`);
    }

    const filePath = path.join(FINGERPRINT_DIR, fileName);
    if (!fs.existsSync(filePath)) {
      throw new Error(`Fingerprint file not found: ${filePath}`);
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(content) as FingerprintProfile;
  }

  /**
   * 새 프로필 생성
   */
  async createProfile(version: string = 'v7'): Promise<ProfileData> {
    const profileId = `profile-${String(this.profiles.length + 1).padStart(3, '0')}`;
    const profileDir = path.join(PROFILES_DIR, profileId);
    const userDataDir = path.join(profileDir, 'data');

    // 디렉토리 생성
    fs.mkdirSync(userDataDir, { recursive: true });

    // fingerprint 로드 (기존 v7-v20 프로필 중 선택)
    const fingerprint = this.loadFingerprint(version);

    const profileData: ProfileData = {
      id: profileId,
      userDataDir,
      fingerprint,
      warmedUp: false,
      lastUsed: new Date().toISOString(),
      midQuota: {}
    };

    // 메타데이터 저장
    this.saveProfileMetadata(profileData);

    this.profiles.push(profileData);
    console.log(`[ProfileManager] Created profile: ${profileId} (${version})`);

    return profileData;
  }

  /**
   * N개 프로필 일괄 생성
   */
  async createProfiles(count: number): Promise<ProfileData[]> {
    const created: ProfileData[] = [];
    const versions = ['v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15', 'v16'];

    for (let i = 0; i < count; i++) {
      const version = versions[i % versions.length];
      const profile = await this.createProfile(version);
      created.push(profile);
    }

    return created;
  }

  /**
   * 사용 가능한 프로필 선택 (MID 쿼터 체크)
   */
  getAvailableProfile(targetMid: string): ProfileData | null {
    // 워밍업된 프로필만 선택
    const warmedProfiles = this.profiles.filter(p => p.warmedUp);

    if (warmedProfiles.length === 0) {
      // 워밍업된 프로필이 없으면 전체에서 선택
      return this.getAvailableFromAll(targetMid);
    }

    // MID 쿼터가 남은 프로필 찾기
    for (const profile of warmedProfiles) {
      if (this.canUseMid(profile, targetMid)) {
        return profile;
      }
    }

    // 쿼터가 남은 프로필 없음
    console.warn(`[ProfileManager] No available profile for MID ${targetMid}`);
    return null;
  }

  private getAvailableFromAll(targetMid: string): ProfileData | null {
    for (const profile of this.profiles) {
      if (this.canUseMid(profile, targetMid)) {
        return profile;
      }
    }
    return null;
  }

  /**
   * MID 사용 가능 여부 확인
   */
  canUseMid(profile: ProfileData, mid: string): boolean {
    const usage = profile.midQuota[mid] || 0;
    return usage < MID_QUOTA_PER_PROFILE;
  }

  /**
   * MID 사용 기록
   */
  recordMidUsage(profileId: string, mid: string): void {
    const profile = this.profiles.find(p => p.id === profileId);
    if (!profile) {
      console.warn(`[ProfileManager] Profile not found: ${profileId}`);
      return;
    }

    const currentUsage = profile.midQuota[mid] || 0;
    profile.midQuota[mid] = currentUsage + 1;
    profile.lastUsed = new Date().toISOString();

    // 메타데이터 저장
    this.saveProfileMetadata(profile);

    console.log(`[ProfileManager] MID ${mid} usage: ${profile.midQuota[mid]}/${MID_QUOTA_PER_PROFILE} (${profileId})`);
  }

  /**
   * 프로필 워밍업 완료 표시
   */
  markAsWarmedUp(profileId: string): void {
    const profile = this.profiles.find(p => p.id === profileId);
    if (profile) {
      profile.warmedUp = true;
      this.saveProfileMetadata(profile);
      console.log(`[ProfileManager] Profile warmed up: ${profileId}`);
    }
  }

  /**
   * 다음 프로필 선택 (라운드 로빈)
   */
  getNextProfile(): ProfileData | null {
    if (this.profiles.length === 0) return null;

    const profile = this.profiles[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.profiles.length;
    return profile;
  }

  /**
   * 프로필 메타데이터 저장
   */
  private saveProfileMetadata(profile: ProfileData): void {
    const profileDir = path.join(PROFILES_DIR, profile.id);
    const metadataPath = path.join(profileDir, 'metadata.json');

    if (!fs.existsSync(profileDir)) {
      fs.mkdirSync(profileDir, { recursive: true });
    }

    fs.writeFileSync(metadataPath, JSON.stringify(profile, null, 2));
  }

  /**
   * 모든 프로필 반환
   */
  getProfiles(): ProfileData[] {
    return [...this.profiles];
  }

  /**
   * 프로필 수 반환
   */
  getProfileCount(): number {
    return this.profiles.length;
  }

  /**
   * 워밍업된 프로필 수 반환
   */
  getWarmedUpCount(): number {
    return this.profiles.filter(p => p.warmedUp).length;
  }

  /**
   * MID별 사용 현황 조회
   */
  getMidUsageStats(mid: string): { profileId: string; usage: number }[] {
    return this.profiles.map(p => ({
      profileId: p.id,
      usage: p.midQuota[mid] || 0
    }));
  }

  /**
   * 프로필 쿼터 리셋 (일일 리셋용)
   */
  resetAllQuotas(): void {
    for (const profile of this.profiles) {
      profile.midQuota = {};
      this.saveProfileMetadata(profile);
    }
    console.log(`[ProfileManager] All quotas reset (${this.profiles.length} profiles)`);
  }

  /**
   * 특정 프로필 조회
   */
  getProfile(profileId: string): ProfileData | null {
    return this.profiles.find(p => p.id === profileId) || null;
  }
}

// 싱글톤 인스턴스
let instance: ProfileManager | null = null;

export function getProfileManager(): ProfileManager {
  if (!instance) {
    instance = new ProfileManager();
  }
  return instance;
}
