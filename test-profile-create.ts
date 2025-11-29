/**
 * 프로필 생성 테스트 (빠른 검증용)
 */

import { getProfileManager } from './server/services/traffic/shared/profile/ProfileManager';

async function main() {
  console.log('프로필 생성 테스트 시작...\n');

  const profileManager = getProfileManager();

  // 기존 프로필 로드
  await profileManager.loadProfiles();
  console.log(`기존 프로필: ${profileManager.getProfileCount()}개`);

  // 프로필 1개 생성
  if (profileManager.getProfileCount() === 0) {
    console.log('\n새 프로필 생성 중...');
    const profile = await profileManager.createProfile('v7');
    console.log(`생성됨: ${profile.id}`);
    console.log(`  userDataDir: ${profile.userDataDir}`);
    console.log(`  fingerprint: ${profile.fingerprint.version}`);
    console.log(`  warmedUp: ${profile.warmedUp}`);
  } else {
    console.log('\n기존 프로필 목록:');
    profileManager.getProfiles().forEach((p, i) => {
      console.log(`  [${i + 1}] ${p.id} - ${p.fingerprint.version} - ${p.warmedUp ? 'WARMED' : 'PENDING'}`);
    });
  }

  console.log('\n테스트 완료');
}

main().catch(console.error);
