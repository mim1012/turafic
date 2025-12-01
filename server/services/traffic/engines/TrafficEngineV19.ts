import { TrafficEngineBase } from "./TrafficEngineBase";
import { ProfileLoader } from "../shared/fingerprint/ProfileLoader";
import v19Profile from "../profiles/v19-samsung-a54.json";

export class TrafficEngineV19 extends TrafficEngineBase {
  constructor() {
    super(ProfileLoader.load(v19Profile));
  }
}
