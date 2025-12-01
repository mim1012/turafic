/**
 * v16 Simple Engine - Samsung Galaxy Z Fold5 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v16Profile from '../profiles/v16-samsung-z-fold5.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v16Profile as FingerprintProfile;

export class TrafficEngineV16Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v16-simple";
  }
}
