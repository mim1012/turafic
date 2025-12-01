import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v12Profile from "../profiles/v12-oppo-find-x5-pro.json";

/**
 * V12 Fullname Engine
 * Profile: v12-oppo-find-x5-pro
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV12Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v12Profile));
  }
}
