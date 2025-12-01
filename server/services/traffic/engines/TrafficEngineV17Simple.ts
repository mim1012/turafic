/**
 * v17 Simple Engine - iPhone 13 Pro 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v17Profile from '../profiles/v17-iphone-13-pro.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v17Profile as FingerprintProfile;

export class TrafficEngineV17Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v17-simple";
  }
}
