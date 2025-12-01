import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v19Profile from "../profiles/v19-samsung-a54.json";

/**
 * V19 Fullname Engine
 * Profile: v19-samsung-a54
 * Mode: Fullname traffic (통합검색)
 */
export class TrafficEngineV19Fullname extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v19Profile));
  }
}
