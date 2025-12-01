import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v14Profile from "../profiles/v14-oneplus-11.json";

/**
 * V14 Fullname Engine
 * Profile: v14-oneplus-11
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV14Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v14Profile));
  }
}
