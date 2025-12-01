import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v8Profile from "../profiles/v8-iphone-15-pro.json";

export class TrafficEngineV8 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v8Profile));
  }
}
