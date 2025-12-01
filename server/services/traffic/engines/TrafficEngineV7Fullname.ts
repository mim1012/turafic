import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v7Profile from "../profiles/v7-samsung-s23.json";

/**
 * V7 Fullname Engine
 * Profile: v7-samsung-s23
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV7Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v7Profile));
  }
}
