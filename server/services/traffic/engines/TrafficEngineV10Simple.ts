/**
 * v10 Simple Engine - Xiaomi 13 Pro 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v10Profile from '../profiles/v10-xiaomi-13-pro.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v10Profile as FingerprintProfile;

export class TrafficEngineV10Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v10-simple";
  }
}
