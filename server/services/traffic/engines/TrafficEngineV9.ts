import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v9Profile from "../profiles/v9-samsung-s24-ultra.json";

export class TrafficEngineV9 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v9Profile));
  }
}
