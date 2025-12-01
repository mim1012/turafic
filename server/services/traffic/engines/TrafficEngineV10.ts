import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v10Profile from "../profiles/v10-xiaomi-13-pro.json";

export class TrafficEngineV10 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v10Profile));
  }
}
