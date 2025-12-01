/**
 * v12 Simple Engine - OPPO Find X5 Pro 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v12Profile from '../profiles/v12-oppo-find-x5-pro.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v12Profile as FingerprintProfile;

export class TrafficEngineV12Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v12-simple";
  }
}
