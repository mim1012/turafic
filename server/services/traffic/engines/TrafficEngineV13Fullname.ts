import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v13Profile from "../profiles/v13-google-pixel-8-pro.json";

/**
 * V13 Fullname Engine
 * Profile: v13-google-pixel-8-pro
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV13Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v13Profile));
  }
}
