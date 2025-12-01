import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v8Profile from "../profiles/v8-iphone-15-pro.json";

/**
 * V8 Fullname Engine
 * Profile: v8-iphone-15-pro
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV8Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v8Profile));
  }
}
