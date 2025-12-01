import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v18Profile from "../profiles/v18-asus-rog-phone-7.json";

/**
 * V18 Fullname Engine
 * Profile: v18-asus-rog-phone-7
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV18Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v18Profile));
  }
}
