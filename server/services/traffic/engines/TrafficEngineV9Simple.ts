/**
 * v9 Simple Engine - Samsung Galaxy S24 Ultra 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v9Profile from '../profiles/v9-samsung-s24-ultra.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v9Profile as FingerprintProfile;

export class TrafficEngineV9Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v9-simple";
  }
}
