import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v7Profile from "../profiles/v7-samsung-s23.json";

export class TrafficEngineV7 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v7Profile));
  }
}
