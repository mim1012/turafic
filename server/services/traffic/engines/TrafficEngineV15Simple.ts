/**
 * v15 Simple Engine - Vivo X90 Pro 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v15Profile from '../profiles/v15-vivo-x90-pro.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v15Profile as FingerprintProfile;

export class TrafficEngineV15Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v15-simple";
  }
}
