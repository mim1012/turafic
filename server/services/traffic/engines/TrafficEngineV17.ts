import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v17Profile from "../profiles/v17-iphone-13-pro.json";

export class TrafficEngineV17 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v17Profile));
  }
}
