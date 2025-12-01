import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v12Profile from "../profiles/v12-oppo-find-x5-pro.json";

export class TrafficEngineV12 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v12Profile));
  }
}
