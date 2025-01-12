import { Utilities } from "../Utilities.js";
import { ApiFactory } from "./ApiFactory.js";

export class ApiOther {
    public static register(inst: ApiFactory) {
        inst.app.get("/api/other/random_file", (req, res) => {
            const type = req.query.type ?? "redirect";
            switch (type) {
                case "302":
                case "redirect":
                    res.redirect(encodeURI(Utilities.getRandomElement(inst.files)?.path || ''));
                    break;
                case "json":
                    const url = Utilities.getRandomElement(inst.files)?.path || '';
                    res.json({
                        url: url,
                        encodedUrl: encodeURI(url)
                    });
                default:
                    res.status(400).json({
                        error: "Bad request"
                    });
            }
        });
    }
}