/**
 * v14 Simple Engine - OnePlus 11 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v14Profile from '../profiles/v14-oneplus-11.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v14Profile as FingerprintProfile;

export class TrafficEngineV14Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v14-simple";
  }
}
