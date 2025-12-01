/**
 * v11 Simple Engine - iPhone 14 Pro Max 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v11Profile from '../profiles/v11-iphone-14-pro-max.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v11Profile as FingerprintProfile;

export class TrafficEngineV11Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v11-simple";
  }
}
