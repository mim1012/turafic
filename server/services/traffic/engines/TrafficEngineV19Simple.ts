/**
 * v19 Simple Engine - Samsung Galaxy A54 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v19Profile from '../profiles/v19-samsung-a54.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v19Profile as FingerprintProfile;

export class TrafficEngineV19Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v19-simple";
  }
}
