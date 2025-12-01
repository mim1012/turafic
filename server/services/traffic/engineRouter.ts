// Simple engines (통합검색 모드 - v7-v20 모두 프로필 기반)
import { TrafficEngineV7Simple } from "./engines/TrafficEngineV7Simple";
import { TrafficEngineV8Simple } from "./engines/TrafficEngineV8Simple";
import { TrafficEngineV9Simple } from "./engines/TrafficEngineV9Simple";
import { TrafficEngineV10Simple } from "./engines/TrafficEngineV10Simple";
import { TrafficEngineV11Simple } from "./engines/TrafficEngineV11Simple";
import { TrafficEngineV12Simple } from "./engines/TrafficEngineV12Simple";
import { TrafficEngineV13Simple } from "./engines/TrafficEngineV13Simple";
import { TrafficEngineV14Simple } from "./engines/TrafficEngineV14Simple";
import { TrafficEngineV15Simple } from "./engines/TrafficEngineV15Simple";
import { TrafficEngineV16Simple } from "./engines/TrafficEngineV16Simple";
import { TrafficEngineV17Simple } from "./engines/TrafficEngineV17Simple";
import { TrafficEngineV18Simple } from "./engines/TrafficEngineV18Simple";
import { TrafficEngineV19Simple } from "./engines/TrafficEngineV19Simple";
import { TrafficEngineV20Simple } from "./engines/TrafficEngineV20Simple";

// Fullname engines (통합검색 mode)
import { TrafficEngineV7Fullname } from "./engines/TrafficEngineV7Fullname";
import { TrafficEngineV8Fullname } from "./engines/TrafficEngineV8Fullname";
import { TrafficEngineV9Fullname } from "./engines/TrafficEngineV9Fullname";
import { TrafficEngineV10Fullname } from "./engines/TrafficEngineV10Fullname";
import { TrafficEngineV11Fullname } from "./engines/TrafficEngineV11Fullname";
import { TrafficEngineV12Fullname } from "./engines/TrafficEngineV12Fullname";
import { TrafficEngineV13Fullname } from "./engines/TrafficEngineV13Fullname";
import { TrafficEngineV14Fullname } from "./engines/TrafficEngineV14Fullname";
import { TrafficEngineV15Fullname } from "./engines/TrafficEngineV15Fullname";
import { TrafficEngineV16Fullname } from "./engines/TrafficEngineV16Fullname";
import { TrafficEngineV17Fullname } from "./engines/TrafficEngineV17Fullname";
import { TrafficEngineV18Fullname } from "./engines/TrafficEngineV18Fullname";
import { TrafficEngineV19Fullname } from "./engines/TrafficEngineV19Fullname";
import { TrafficEngineV20Fullname } from "./engines/TrafficEngineV20Fullname";

export type EngineVersion =
  | "v7"
  | "v8"
  | "v9"
  | "v10"
  | "v11"
  | "v12"
  | "v13"
  | "v14"
  | "v15"
  | "v16"
  | "v17"
  | "v18"
  | "v19"
  | "v20";

export class EngineRouter {
  static getEngine(version: EngineVersion): any {
    switch (version) {
      case "v7":
        return new TrafficEngineV7Simple();
      case "v8":
        return new TrafficEngineV8Simple();
      case "v9":
        return new TrafficEngineV9Simple();
      case "v10":
        return new TrafficEngineV10Simple();
      case "v11":
        return new TrafficEngineV11Simple();
      case "v12":
        return new TrafficEngineV12Simple();
      case "v13":
        return new TrafficEngineV13Simple();
      case "v14":
        return new TrafficEngineV14Simple();
      case "v15":
        return new TrafficEngineV15Simple();
      case "v16":
        return new TrafficEngineV16Simple();
      case "v17":
        return new TrafficEngineV17Simple();
      case "v18":
        return new TrafficEngineV18Simple();
      case "v19":
        return new TrafficEngineV19Simple();
      case "v20":
        return new TrafficEngineV20Simple();
      default:
        throw new Error(`Unknown engine version: ${version}`);
    }
  }

  static getAllVersions(): EngineVersion[] {
    return [
      "v7",
      "v8",
      "v9",
      "v10",
      "v11",
      "v12",
      "v13",
      "v14",
      "v15",
      "v16",
      "v17",
      "v18",
      "v19",
      "v20",
    ];
  }

  static getRandomVersion(): EngineVersion {
    const versions = this.getAllVersions();
    return versions[Math.floor(Math.random() * versions.length)];
  }

  /**
   * Fullname 엔진 가져오기 (통합검색 모드)
   */
  static getFullnameEngine(version: EngineVersion): any {
    switch (version) {
      case "v7":
        return new TrafficEngineV7Fullname();
      case "v8":
        return new TrafficEngineV8Fullname();
      case "v9":
        return new TrafficEngineV9Fullname();
      case "v10":
        return new TrafficEngineV10Fullname();
      case "v11":
        return new TrafficEngineV11Fullname();
      case "v12":
        return new TrafficEngineV12Fullname();
      case "v13":
        return new TrafficEngineV13Fullname();
      case "v14":
        return new TrafficEngineV14Fullname();
      case "v15":
        return new TrafficEngineV15Fullname();
      case "v16":
        return new TrafficEngineV16Fullname();
      case "v17":
        return new TrafficEngineV17Fullname();
      case "v18":
        return new TrafficEngineV18Fullname();
      case "v19":
        return new TrafficEngineV19Fullname();
      case "v20":
        return new TrafficEngineV20Fullname();
      default:
        throw new Error(`Unknown fullname engine version: ${version}`);
    }
  }

  /**
   * 랜덤 Fullname 엔진 가져오기 (프로필 로테이션)
   */
  static getRandomFullnameEngine(): any {
    const version = this.getRandomVersion();
    return this.getFullnameEngine(version);
  }
}
