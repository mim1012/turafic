import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v9Profile from "../profiles/v9-samsung-s24-ultra.json";

/**
 * V9 Fullname Engine
 * Profile: v9-samsung-s24-ultra
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV9Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v9Profile));
  }
}
