import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v14Profile from "../profiles/v14-oneplus-11.json";

export class TrafficEngineV14 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v14Profile));
  }
}
