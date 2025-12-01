import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v18Profile from "../profiles/v18-asus-rog-phone-7.json";

export class TrafficEngineV18 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v18Profile));
  }
}
