import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v11Profile from "../profiles/v11-iphone-14-pro-max.json";

export class TrafficEngineV11 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v11Profile));
  }
}
