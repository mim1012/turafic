import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v16Profile from "../profiles/v16-samsung-z-fold5.json";

/**
 * V16 Fullname Engine
 * Profile: v16-samsung-z-fold5
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV16Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v16Profile));
  }
}
