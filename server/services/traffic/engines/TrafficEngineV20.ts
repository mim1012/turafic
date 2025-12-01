import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v20Profile from "../profiles/v20-motorola-edge-40-pro.json";

export class TrafficEngineV20 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v20Profile));
  }
}
