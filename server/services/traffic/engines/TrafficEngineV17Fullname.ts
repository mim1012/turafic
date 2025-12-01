import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v17Profile from "../profiles/v17-iphone-13-pro.json";

/**
 * V17 Fullname Engine
 * Profile: v17-iphone-13-pro
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV17Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v17Profile));
  }
}
