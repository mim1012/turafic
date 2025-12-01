import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v13Profile from "../profiles/v13-google-pixel-8-pro.json";

export class TrafficEngineV13 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v13Profile));
  }
}
