/**
 * v13 Simple Engine - Google Pixel 8 Pro 프로필
 */
import { TrafficEngineBaseSimple } from "./TrafficEngineBaseSimple";
import v13Profile from '../profiles/v13-google-pixel-8-pro.json';
import type { FingerprintProfile } from '../shared/fingerprint/types';

const profile = v13Profile as FingerprintProfile;

export class TrafficEngineV13Simple extends TrafficEngineBaseSimple {
  protected get profile(): FingerprintProfile {
    return profile;
  }

  protected get versionString(): string {
    return "v13-simple";
  }
}
