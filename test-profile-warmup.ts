/**
 * 프로필 생성 및 워밍업 테스트
 *
 * 1. 프로필 2개 생성
 * 2. 각 프로필 히스토리 워밍업 (약 3분)
 * 3. 워밍업 완료 상태 확인
 */

import { ProfileManager, getProfileManager } from './server/services/traffic/shared/profile/ProfileManager';
import { HistoryWarmer } from './server/services/traffic/shared/profile/HistoryWarmer';

const TEST_PROFILE_COUNT = 10;  // 10개 프로필 생성 + 워밍업

async function main() {
  console.log('');
  console.log('============================================================');
  console.log('  프로필 생성 및 워밍업 테스트');
  console.log('============================================================');
  console.log(`생성할 프로필 수: ${TEST_PROFILE_COUNT}개`);
  console.log('');

  const profileManager = getProfileManager();

  // 1. 기존 프로필 로드
  console.log('[Step 1] 기존 프로필 로드...');
  await profileManager.loadProfiles();
  console.log(`  기존 프로필: ${profileManager.getProfileCount()}개`);
  console.log(`  워밍업 완료: ${profileManager.getWarmedUpCount()}개`);
  console.log('');

  // 2. 프로필 생성 (필요시)
  const needCreate = TEST_PROFILE_COUNT - profileManager.getProfileCount();
  if (needCreate > 0) {
    console.log(`[Step 2] 새 프로필 ${needCreate}개 생성...`);
    await profileManager.createProfiles(needCreate);
    console.log(`  생성 완료: ${profileManager.getProfileCount()}개`);
  } else {
    console.log(`[Step 2] 이미 ${profileManager.getProfileCount()}개 프로필 존재 - 생성 스킵`);
  }
  console.log('');

  // 3. 워밍업 안 된 프로필 워밍업
  const profiles = profileManager.getProfiles();
  const unwarmedProfiles = profiles.filter(p => !p.warmedUp);

  if (unwarmedProfiles.length > 0) {
    console.log(`[Step 3] ${unwarmedProfiles.length}개 프로필 워밍업 시작...`);
    console.log('  (프로필당 약 3분 소요)');
    console.log('');

    const warmer = new HistoryWarmer();

    for (let i = 0; i < unwarmedProfiles.length; i++) {
      const profile = unwarmedProfiles[i];
      console.log(`\n[${'='.repeat(50)}]`);
      console.log(`[Profile ${i + 1}/${unwarmedProfiles.length}] ${profile.id}`);
      console.log(`  Fingerprint: ${profile.fingerprint.version}`);
      console.log(`  UserDataDir: ${profile.userDataDir.substring(0, 50)}...`);
      console.log(`[${'='.repeat(50)}]`);

      const startTime = Date.now();
      const success = await warmer.warmUp(profile);
      const duration = Math.round((Date.now() - startTime) / 1000);

      if (success) {
        profileManager.markAsWarmedUp(profile.id);
        console.log(`\n[${profile.id}] 워밍업 완료 (${duration}초)`);
      } else {
        console.log(`\n[${profile.id}] 워밍업 실패 (${duration}초)`);
      }

      // 프로필 간 휴식
      if (i < unwarmedProfiles.length - 1) {
        console.log('\n[휴식] 5초 대기...');
        await new Promise(r => setTimeout(r, 5000));
      }
    }
  } else {
    console.log(`[Step 3] 모든 프로필 워밍업 완료 상태 - 스킵`);
  }

  // 4. 결과 요약
  console.log('\n');
  console.log('============================================================');
  console.log('  결과 요약');
  console.log('============================================================');
  console.log(`총 프로필: ${profileManager.getProfileCount()}개`);
  console.log(`워밍업 완료: ${profileManager.getWarmedUpCount()}개`);
  console.log('');

  const finalProfiles = profileManager.getProfiles();
  console.log('프로필 목록:');
  finalProfiles.forEach((p, i) => {
    const status = p.warmedUp ? 'WARMED' : 'PENDING';
    console.log(`  [${i + 1}] ${p.id} - ${p.fingerprint.version} - ${status}`);
  });

  console.log('\n============================================================');
  console.log('  테스트 완료');
  console.log('============================================================');
}

main().catch(console.error);
