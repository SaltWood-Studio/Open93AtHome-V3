import { Utilities } from "../Utilities.js";
import { ApiFactory } from "./ApiFactory.js";

export class ApiOther {
    public static register(inst: ApiFactory) {
        inst.app.get("/api/other/random_file", (req, res) => {
            res.redirect(encodeURI(Utilities.getRandomElement(inst.files)?.path || ''));
        });
    }
}