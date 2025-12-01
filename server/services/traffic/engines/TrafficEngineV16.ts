import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v16Profile from "../profiles/v16-samsung-z-fold5.json";

export class TrafficEngineV16 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v16Profile));
  }
}
