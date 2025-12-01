import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v20Profile from "../profiles/v20-motorola-edge-40-pro.json";

/**
 * V20 Fullname Engine
 * Profile: v20-motorola-edge-40-pro
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV20Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v20Profile));
  }
}
