import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v15Profile from "../profiles/v15-vivo-x90-pro.json";

export class TrafficEngineV15 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v15Profile));
  }
}
