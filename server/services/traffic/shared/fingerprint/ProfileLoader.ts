import { FingerprintProfile } from "./types";

export class ProfileLoader {
  static load(profile: any): FingerprintProfile {
    return profile as FingerprintProfile;
  }
}
