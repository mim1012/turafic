/**
 * v20 Simple Engine - Motorola Edge 40 Pro 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v20Profile from '../profiles/v20-motorola-edge-40-pro.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v20Profile as FingerprintProfile;

export class TrafficEngineV20Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v20-simple";
  }
}
