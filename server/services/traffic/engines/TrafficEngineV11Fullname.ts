import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v11Profile from "../profiles/v11-iphone-14-pro-max.json";

/**
 * V11 Fullname Engine
 * Profile: v11-iphone-14-pro-max
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV11Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v11Profile));
  }
}
