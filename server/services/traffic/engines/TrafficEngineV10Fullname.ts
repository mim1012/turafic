import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v10Profile from "../profiles/v10-xiaomi-13-pro.json";

/**
 * V10 Fullname Engine
 * Profile: v10-xiaomi-13-pro
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV10Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v10Profile));
  }
}
