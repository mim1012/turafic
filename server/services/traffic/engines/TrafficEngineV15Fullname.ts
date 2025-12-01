import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v15Profile from "../profiles/v15-vivo-x90-pro.json";

/**
 * V15 Fullname Engine
 * Profile: v15-vivo-x90-pro
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV15Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v15Profile));
  }
}
