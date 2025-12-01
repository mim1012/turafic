/**
 * v18 Simple Engine - ASUS ROG Phone 7 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v18Profile from '../profiles/v18-asus-rog-phone-7.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v18Profile as FingerprintProfile;

export class TrafficEngineV18Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v18-simple";
  }
}
